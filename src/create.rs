//! PAR2 recovery set creation.
//!
//! Produces an index file (`<base>.par2`) holding the critical packets (Main, FileDesc, IFSC,
//! Creator) and recovery volumes (`<base>.volXX+YY.par2`) whose recovery slices are computed
//! by the streaming [`Engine`]. Recovery packets are written first in every volume followed by
//! repeated copies of the critical packets, as `par2cmdline` does, so a volume alone still
//! describes the set.
//!
//! The creator exists primarily so that verification and repair can be tested end-to-end
//! without external tools, and so that the engine can be cross-checked against `par2cmdline`
//! (its output must verify with `par2 verify`, and sets made by `par2 create` must repair with
//! this crate).

use crate::gf16::input_constant_logs;
use crate::gf16::simd::Kernel;
use crate::hasher::md5;
use crate::packet::{
    compute_file_id, compute_set_id, encode_creator_body, encode_file_desc_body, encode_ifsc_body, encode_main_body, encode_packet,
    read_exact_at, FileId, PacketHeader, SetId, SliceChecksum, HEADER_LEN, TYPE_CREATOR, TYPE_FILEDESC, TYPE_IFSC, TYPE_MAIN, TYPE_RECVSLIC,
};
use crate::parhash::{file_hashes_parallel, hash_ranges_parallel, slice_ranges, HashRange};
use crate::reed_solomon::{Engine, EngineConfig, InputKind, InputReader, InputSpec, OutputSink, RsError};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

/// How recovery slices are distributed over volume files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeScheme {
    /// All recovery slices in one volume file.
    Single,
    /// Fixed number of slices per volume (the last one may be smaller).
    Uniform(u32),
    /// `par2cmdline`'s default: 1, 2, 4, 8, ... slices per volume, remainder in the last.
    Exponential,
}

/// Creation parameters.
#[derive(Clone, Debug)]
pub struct CreateOptions {
    /// Slice size (multiple of 4, `> 0`).
    pub slice_size: u64,
    /// Number of recovery slices to generate.
    pub recovery_blocks: u32,
    /// Exponent of the first recovery slice.
    pub first_exponent: u32,
    /// Volume layout.
    pub volumes: VolumeScheme,
    /// Creator packet text.
    pub creator: String,
    /// Engine tuning.
    pub engine: EngineConfig,
    /// SIMD kernel.
    pub kernel: Kernel,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            slice_size: 1 << 20,
            recovery_blocks: 10,
            first_exponent: 0,
            volumes: VolumeScheme::Exponential,
            creator: format!("par-rs {}", env!("CARGO_PKG_VERSION")),
            engine: EngineConfig::default(),
            kernel: Kernel::detect(),
        }
    }
}

/// A file to protect.
#[derive(Clone, Debug)]
pub struct SourceFile {
    /// Location on disk.
    pub path: PathBuf,
    /// Name stored in the PAR2 set (relative, `/` separated, raw bytes).
    pub par2_name: Vec<u8>,
}

impl SourceFile {
    /// Source whose PAR2 name is its file name.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let name = path.file_name().map(crate::filenames::os_str_bytes).unwrap_or_default();
        Self { path, par2_name: name }
    }
}

/// Creation errors.
#[derive(Debug)]
pub enum CreateError {
    /// Invalid slice size.
    BadSliceSize(u64),
    /// No source files.
    NoSources,
    /// More than 32768 input slices.
    TooManyInputSlices(u64),
    /// Recovery exponents would exceed 65535.
    TooManyRecoveryBlocks,
    /// Empty or invalid PAR2 name for a source.
    BadSourceName(PathBuf),
    /// Two sources resolve to the same file id.
    DuplicateSource(PathBuf),
    /// I/O.
    Io(io::Error),
    /// Reed-Solomon failure.
    Rs(RsError),
    /// Cancelled.
    Cancelled,
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateError::BadSliceSize(s) => write!(f, "invalid slice size {s} (must be a positive multiple of 4)"),
            CreateError::NoSources => f.write_str("no source files"),
            CreateError::TooManyInputSlices(n) => write!(f, "{n} input slices exceed the PAR2 limit of 32768; use a larger slice size"),
            CreateError::TooManyRecoveryBlocks => f.write_str("recovery exponents exceed 65535"),
            CreateError::BadSourceName(p) => write!(f, "invalid PAR2 name for {}", p.display()),
            CreateError::DuplicateSource(p) => write!(f, "duplicate source {}", p.display()),
            CreateError::Io(e) => write!(f, "I/O error: {e}"),
            CreateError::Rs(e) => write!(f, "{e}"),
            CreateError::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for CreateError {}

impl From<io::Error> for CreateError {
    fn from(e: io::Error) -> Self {
        CreateError::Io(e)
    }
}

impl From<RsError> for CreateError {
    fn from(e: RsError) -> Self {
        match e {
            RsError::Cancelled => CreateError::Cancelled,
            RsError::Io(e) => CreateError::Io(e),
            other => CreateError::Rs(other),
        }
    }
}

/// Result of a creation run.
#[derive(Clone, Debug)]
pub struct CreateReport {
    /// Set id.
    pub set_id: SetId,
    /// Files written (index first, then volumes).
    pub files: Vec<PathBuf>,
    /// Total input slices.
    pub input_slices: u64,
    /// Recovery slices written.
    pub recovery_slices: u32,
}

/// Progress stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateStage {
    /// Hashing source files (`done`/`total` in bytes).
    Hashing,
    /// Computing recovery data (`done`/`total` in input-slice reads).
    Computing,
    /// Writing packets.
    Writing,
}

/// Progress callback `(stage, done, total)`.
pub type CreateProgress<'a> = dyn FnMut(CreateStage, u64, u64) + 'a;

struct HashedSource {
    path: PathBuf,
    name: Vec<u8>,
    file_id: FileId,
    length: u64,
    hash_full: [u8; 16],
    hash_16k: [u8; 16],
    slices: Vec<SliceChecksum>,
}

/// Map a parallel-hashing error (cancellation is reported as `Interrupted`).
fn hash_err(e: io::Error) -> CreateError {
    if e.kind() == io::ErrorKind::Interrupted {
        CreateError::Cancelled
    } else {
        CreateError::Io(e)
    }
}

/// Reads input slices directly from the source files.
struct SourceReader {
    files: Vec<File>,
    /// `(file index, offset, available bytes)` per global input slice.
    slices: Vec<(usize, u64, u64)>,
}

impl InputReader for SourceReader {
    fn read_input(&self, source: usize, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let (fi, base, avail) = self.slices[source];
        if offset >= avail {
            buf.fill(0);
            return Ok(());
        }
        let n = ((avail - offset) as usize).min(buf.len());
        read_exact_at(&self.files[fi], base + offset, &mut buf[..n])?;
        buf[n..].fill(0);
        Ok(())
    }
}

/// Volume layout: `(first exponent offset, count)` per volume.
pub fn volume_layout(scheme: VolumeScheme, total: u32) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    if total == 0 {
        return out;
    }
    match scheme {
        VolumeScheme::Single => out.push((0, total)),
        VolumeScheme::Uniform(n) => {
            let n = n.max(1);
            let mut s = 0;
            while s < total {
                let c = n.min(total - s);
                out.push((s, c));
                s += c;
            }
        }
        VolumeScheme::Exponential => {
            let mut s = 0;
            let mut c = 1u32;
            while s < total {
                let take = c.min(total - s);
                out.push((s, take));
                s += take;
                c = c.saturating_mul(2);
            }
        }
    }
    out
}

/// Where each recovery slice lives inside its volume file.
struct VolumePlan {
    path: PathBuf,
    /// Number of recovery slices in the volume (global indices are contiguous from the first).
    count: u32,
    /// Number of critical-packet copies appended after the recovery packets.
    copies: u32,
}

/// Sink writing recovery payloads into pre-sized volume files. Packet MD5s are computed
/// afterwards from the files on all cores (see [`create`]).
struct VolumeSink {
    files: Vec<File>,
    /// Per recovery index: `(volume index, byte offset of packet header)`.
    locations: Vec<(usize, u64)>,
}

impl OutputSink for VolumeSink {
    fn write_output(&mut self, output: usize, offset: u64, data: &[u8]) -> io::Result<()> {
        let (vi, pkt_off) = self.locations[output];
        write_all_at(&self.files[vi], pkt_off + HEADER_LEN as u64 + 4 + offset, data)
    }
}

fn write_all_at(file: &File, offset: u64, data: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(data, offset)
    }
    #[cfg(not(unix))]
    {
        use std::io::Seek;
        let mut f = file;
        f.seek(io::SeekFrom::Start(offset))?;
        f.write_all(data)
    }
}

/// Create a recovery set for `sources`, writing `<out_dir>/<base>.par2` and volumes.
pub fn create(sources: &[SourceFile], out_dir: &Path, base: &str, opts: &CreateOptions, cancel: Option<&AtomicBool>, progress: &mut CreateProgress<'_>) -> Result<CreateReport, CreateError> {
    if opts.slice_size == 0 || !opts.slice_size.is_multiple_of(4) || opts.slice_size > crate::packet::MAX_SLICE_SIZE {
        return Err(CreateError::BadSliceSize(opts.slice_size));
    }
    if sources.is_empty() {
        return Err(CreateError::NoSources);
    }
    if (opts.first_exponent as u64 + opts.recovery_blocks as u64) > 65535 {
        return Err(CreateError::TooManyRecoveryBlocks);
    }

    // ---- identify sources ----
    // The file order (and so the Main packet and set id) only needs each file's length and its
    // 16k hash, so the expensive digests run concurrently with the recovery computation.
    for s in sources {
        if s.par2_name.is_empty() || s.par2_name.len() > crate::packet::MAX_FILENAME_LEN {
            return Err(CreateError::BadSourceName(s.path.clone()));
        }
    }
    let paths: Vec<&Path> = sources.iter().map(|s| s.path.as_path()).collect();
    let sizes: Vec<u64> = sources.iter().map(|s| std::fs::metadata(&s.path).map(|m| m.len())).collect::<io::Result<_>>()?;
    let total_bytes: u64 = sizes.iter().sum();
    let threads = opts.engine.num_threads;
    let hash_16k: Vec<[u8; 16]> = paths.iter().map(|p| crate::hasher::file_md5_16k(p)).collect::<io::Result<_>>()?;
    let mut hashed: Vec<HashedSource> = Vec::with_capacity(sources.len());
    for (k, s) in sources.iter().enumerate() {
        let file_id = compute_file_id(&hash_16k[k], sizes[k], &s.par2_name);
        if hashed.iter().any(|o| o.file_id == file_id) {
            return Err(CreateError::DuplicateSource(s.path.clone()));
        }
        let slice_count = sizes[k].div_ceil(opts.slice_size) as usize;
        hashed.push(HashedSource { path: s.path.clone(), name: s.par2_name.clone(), file_id, length: sizes[k], hash_full: [0u8; 16], hash_16k: hash_16k[k], slices: vec![SliceChecksum { md5: [0u8; 16], crc32: 0 }; slice_count] });
    }
    // PAR2 order: ascending file id. `source_of[i]` is the source index of `hashed[i]`.
    let mut source_of: Vec<usize> = (0..hashed.len()).collect();
    source_of.sort_by_key(|&k| hashed[k].file_id);
    hashed.sort_by_key(|a| a.file_id);
    let input_slices: u64 = hashed.iter().map(|h| h.slices.len() as u64).sum();
    if input_slices > 32768 {
        return Err(CreateError::TooManyInputSlices(input_slices));
    }
    let ids: Vec<FileId> = hashed.iter().map(|h| h.file_id).collect();
    let main_body = encode_main_body(opts.slice_size, &ids, &[]);
    let set_id = compute_set_id(&main_body);
    let critical_packets = |hashed: &[HashedSource]| -> Vec<u8> {
        let mut critical: Vec<u8> = Vec::new();
        critical.extend(encode_packet(&set_id, &TYPE_MAIN, &main_body));
        for h in hashed {
            critical.extend(encode_packet(&set_id, &TYPE_FILEDESC, &encode_file_desc_body(&h.file_id, &h.hash_full, &h.hash_16k, h.length, &h.name)));
            if !h.slices.is_empty() {
                critical.extend(encode_packet(&set_id, &TYPE_IFSC, &encode_ifsc_body(&h.file_id, &h.slices)));
            }
        }
        critical.extend(encode_packet(&set_id, &TYPE_CREATOR, &encode_creator_body(opts.creator.as_bytes())));
        critical
    };
    // Same length as the final packets (digests are fixed width); sizes the volume files.
    let critical_len = critical_packets(&hashed).len() as u64;

    std::fs::create_dir_all(out_dir)?;
    let index_path = out_dir.join(format!("{base}.par2"));
    let mut files_written = vec![index_path.clone()];

    // ---- recovery volumes (prepared before the digests so the engine can start) ----
    let total = opts.recovery_blocks;
    let exponents: Vec<u32> = (0..total).map(|i| opts.first_exponent + i).collect();
    let with_recovery = total > 0 && input_slices > 0;
    let packet_len = HEADER_LEN as u64 + 4 + opts.slice_size;
    let mut plans: Vec<VolumePlan> = Vec::new();
    let mut sink = VolumeSink { files: Vec::new(), locations: vec![(0, 0); if with_recovery { total as usize } else { 0 }] };
    if with_recovery {
        let layout = volume_layout(opts.volumes, total);
        let width = crate::filenames::volume_number_width(opts.first_exponent + total);
        for (vi, &(first, count)) in layout.iter().enumerate() {
            let name = crate::filenames::volume_filename(base, opts.first_exponent + first, count, width);
            let path = out_dir.join(&name);
            let copies = 1 + (31 - count.max(1).leading_zeros()); // 1 + floor(log2(count))
            for i in 0..count {
                sink.locations[(first + i) as usize] = (vi, i as u64 * packet_len);
            }
            let size = count as u64 * packet_len + copies as u64 * critical_len;
            let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path)?;
            f.set_len(size)?;
            // Header + exponent of every recovery packet, MD5 still zero: the digest covers
            // bytes 32.. of the packet, which are complete on disk once the data lands.
            for i in 0..count {
                let header = PacketHeader { length: packet_len, packet_md5: [0u8; 16], set_id, packet_type: TYPE_RECVSLIC };
                let mut prefix = [0u8; HEADER_LEN + 4];
                prefix[..HEADER_LEN].copy_from_slice(&header.to_bytes());
                prefix[HEADER_LEN..].copy_from_slice(&exponents[(first + i) as usize].to_le_bytes());
                write_all_at(&f, i as u64 * packet_len, &prefix)?;
            }
            sink.files.push(f);
            files_written.push(path.clone());
            plans.push(VolumePlan { path, count, copies });
        }
    }

    // ---- digests (all cores) concurrently with the recovery computation ----
    // Whole-file MD5 chains run one file per thread (they cannot be split); the per-slice
    // CRC-32 + MD5 are independent messages hashed in multi-lane jobs on every core.
    progress(CreateStage::Hashing, 0, total_bytes);
    let mut ranges: Vec<HashRange> = Vec::new();
    for (k, &len) in sizes.iter().enumerate() {
        ranges.extend(slice_ranges(k, len, opts.slice_size, len.div_ceil(opts.slice_size)));
    }
    type Digests = (Vec<crate::hasher::FileHashes>, Vec<(u32, [u8; 16])>);
    let digests: Result<Digests, CreateError> = std::thread::scope(|sc| {
        let hasher = sc.spawn(|| -> Result<Digests, CreateError> {
            let fh = file_hashes_parallel(&paths, threads, cancel).map_err(hash_err)?;
            let sh = hash_ranges_parallel(&paths, &ranges, threads, cancel, &mut |_| {}).map_err(hash_err)?;
            Ok((fh, sh))
        });
        let computed: Result<(), CreateError> = if with_recovery {
            let logs = input_constant_logs(input_slices as usize).map_err(|_| CreateError::TooManyInputSlices(input_slices))?;
            let mut reader = SourceReader { files: Vec::with_capacity(hashed.len()), slices: Vec::with_capacity(input_slices as usize) };
            let mut specs: Vec<InputSpec> = Vec::with_capacity(input_slices as usize);
            for (fi, h) in hashed.iter().enumerate() {
                reader.files.push(File::open(&h.path)?);
                for si in 0..h.slices.len() as u64 {
                    let off = si * opts.slice_size;
                    let avail = (h.length - off).min(opts.slice_size);
                    let g = reader.slices.len();
                    reader.slices.push((fi, off, avail));
                    specs.push(InputSpec { kind: InputKind::Data { logbase: logs[g] }, source: g });
                }
            }
            let engine = Engine { slice_size: opts.slice_size, inputs: &specs, output_exponents: &exponents, post_transform: None, config: opts.engine, kernel: opts.kernel };
            let inputs_total = specs.len() as u64;
            engine
                .run(&reader, &mut sink, cancel, &mut |c, ct, i, it| {
                    let total = (ct as u64) * inputs_total.max(1);
                    let done = ((c as u64) * it as u64 + i as u64).min(total);
                    progress(CreateStage::Computing, done, total);
                })
                .map_err(CreateError::from)
        } else {
            Ok(())
        };
        let digests = hasher.join().unwrap_or_else(|_| Err(io::Error::other("hashing thread panicked").into()));
        computed.and(digests)
    });
    let (file_hashes, slice_hashes) = digests?;
    progress(CreateStage::Hashing, total_bytes, total_bytes);
    let mut cursor = vec![0usize; sources.len()];
    {
        let mut c = 0usize;
        for (k, &len) in sizes.iter().enumerate() {
            cursor[k] = c;
            c += len.div_ceil(opts.slice_size) as usize;
        }
    }
    for (i, h) in hashed.iter_mut().enumerate() {
        let k = source_of[i];
        let fh = &file_hashes[k];
        if fh.len != sizes[k] {
            return Err(io::Error::other(format!("{} changed while being hashed", h.path.display())).into());
        }
        h.hash_full = fh.md5_full;
        for (j, sl) in h.slices.iter_mut().enumerate() {
            let (crc32, md5) = slice_hashes[cursor[k] + j];
            *sl = SliceChecksum { md5, crc32 };
        }
    }

    // ---- critical packets: index file + copies in every volume, then packet MD5s ----
    let critical = critical_packets(&hashed);
    debug_assert_eq!(critical.len() as u64, critical_len);
    {
        let mut f = File::create(&index_path)?;
        f.write_all(&critical)?;
    }
    if with_recovery {
        progress(CreateStage::Writing, 0, plans.len() as u64);
        let vol_paths: Vec<&Path> = plans.iter().map(|p| p.path.as_path()).collect();
        let pkt_ranges: Vec<HashRange> = sink
            .locations
            .iter()
            .map(|&(vi, off)| HashRange { file: vi, offset: off + 32, len: packet_len - 32, pad_to: packet_len - 32 })
            .collect();
        let pkt_md5 = hash_ranges_parallel(&vol_paths, &pkt_ranges, threads, cancel, &mut |_| {}).map_err(hash_err)?;
        for (r, &(vi, off)) in sink.locations.iter().enumerate() {
            write_all_at(&sink.files[vi], off + 16, &pkt_md5[r].1)?;
        }
        for (vi, plan) in plans.iter().enumerate() {
            let f = &sink.files[vi];
            let mut off = plan.count as u64 * packet_len;
            for _ in 0..plan.copies {
                write_all_at(f, off, &critical)?;
                off += critical.len() as u64;
            }
            progress(CreateStage::Writing, vi as u64 + 1, plans.len() as u64);
        }
    }

    Ok(CreateReport { set_id, files: files_written, input_slices, recovery_slices: if input_slices > 0 { total } else { 0 } })
}

/// Build a complete single-buffer PAR2 set in memory (critical packets followed by recovery
/// packets with real recovery data). `files` are `(par2 name, contents)`.
pub fn create_in_memory(files: &[(&[u8], &[u8])], slice_size: usize, exponents: &[u32], kernel: Kernel) -> Result<(Vec<u8>, SetId), CreateError> {
    if slice_size == 0 || !slice_size.is_multiple_of(4) {
        return Err(CreateError::BadSliceSize(slice_size as u64));
    }
    struct Mem {
        name: Vec<u8>,
        data: Vec<u8>,
        id: FileId,
        slices: Vec<SliceChecksum>,
    }
    let mut mems: Vec<Mem> = files
        .iter()
        .map(|(name, data)| {
            let h16 = crate::hasher::md5_16k(data);
            let id = compute_file_id(&h16, data.len() as u64, name);
            let slices = data
                .chunks(slice_size)
                .map(|c| {
                    let mut p = c.to_vec();
                    p.resize(slice_size, 0);
                    let (crc32, md5) = crate::hasher::slice_checksums(&p);
                    SliceChecksum { md5, crc32 }
                })
                .collect();
            Mem { name: name.to_vec(), data: data.to_vec(), id, slices }
        })
        .collect();
    mems.sort_by_key(|a| a.id);
    let ids: Vec<FileId> = mems.iter().map(|m| m.id).collect();
    let main_body = encode_main_body(slice_size as u64, &ids, &[]);
    let set_id = compute_set_id(&main_body);
    let mut out = encode_packet(&set_id, &TYPE_MAIN, &main_body);
    for m in &mems {
        let h = md5(&m.data);
        let h16 = crate::hasher::md5_16k(&m.data);
        out.extend(encode_packet(&set_id, &TYPE_FILEDESC, &encode_file_desc_body(&m.id, &h, &h16, m.data.len() as u64, &m.name)));
        if !m.slices.is_empty() {
            out.extend(encode_packet(&set_id, &TYPE_IFSC, &encode_ifsc_body(&m.id, &m.slices)));
        }
    }
    out.extend(encode_packet(&set_id, &TYPE_CREATOR, &encode_creator_body(b"par-rs (in-memory)")));
    let mut inputs: Vec<&[u8]> = Vec::new();
    for m in &mems {
        for c in m.data.chunks(slice_size) {
            inputs.push(c);
        }
    }
    if !inputs.is_empty() && !exponents.is_empty() {
        let rec = crate::reed_solomon::encode_in_memory(slice_size, &inputs, exponents, EngineConfig::default(), kernel)?;
        for (e, data) in exponents.iter().zip(&rec) {
            out.extend_from_slice(&crate::packet::encode_recovery_packet_prefix(&set_id, *e, data));
            out.extend_from_slice(data);
        }
    }
    Ok((out, set_id))
}

// ---------------------------------------------------------------------------------------------
// Complete set builder (index + volumes in memory)
// ---------------------------------------------------------------------------------------------

/// Options for [`build_set`].
#[derive(Clone, Debug)]
pub struct SetOptions {
    /// Slice size (multiple of 4, non-zero).
    pub slice_size: usize,
    /// Recovery slices to generate.
    pub recovery_blocks: u32,
    /// Exponent of the first recovery slice.
    pub first_exponent: u32,
    /// Volume layout.
    pub volumes: VolumeScheme,
    /// Creator string.
    pub creator: String,
    /// Emit `UniFileN` packets for names that are not pure ASCII (the `FileDesc` keeps the UTF-8 bytes).
    pub unicode_names: bool,
    /// Kernel.
    pub kernel: Kernel,
}

impl Default for SetOptions {
    fn default() -> Self {
        Self { slice_size: 1 << 20, recovery_blocks: 10, first_exponent: 0, volumes: VolumeScheme::Exponential, creator: "par-rs".into(), unicode_names: true, kernel: Kernel::detect() }
    }
}

/// A complete recovery set in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Par2Set {
    /// Set id.
    pub set_id: SetId,
    /// Contents of `<base>.par2`.
    pub index: Vec<u8>,
    /// `(file name, contents)` of every `<base>.volNNN+MM.par2` volume.
    pub volumes: Vec<(String, Vec<u8>)>,
    /// Number of input slices.
    pub input_slices: usize,
}

impl Par2Set {
    /// Write the index and volumes into `dir`.
    pub fn write_to(&self, dir: &Path, base: &str) -> io::Result<Vec<PathBuf>> {
        std::fs::create_dir_all(dir)?;
        let mut out = Vec::with_capacity(self.volumes.len() + 1);
        let idx = dir.join(format!("{base}.par2"));
        std::fs::write(&idx, &self.index)?;
        out.push(idx);
        for (name, data) in &self.volumes {
            let p = dir.join(name);
            std::fs::write(&p, data)?;
            out.push(p);
        }
        Ok(out)
    }
}

/// `UniFileN` packet type.
pub const TYPE_UNIFILEN: [u8; 16] = *b"PAR 2.0\0UniFileN";

/// Body of a `UniFileN` packet: file id + UTF-16LE name, NUL padded to a multiple of 4.
pub fn encode_unicode_name_body(file_id: &FileId, name: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(16 + name.len() * 2 + 4);
    body.extend_from_slice(&file_id.0);
    for u in name.encode_utf16() {
        body.extend_from_slice(&u.to_le_bytes());
    }
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    body
}

/// Build a complete PAR2 set (Main, FileDesc, IFSC, Creator, optional UniFileN, RecvSlic)
/// for in-memory `(name, contents)` sources, laid out like `par2cmdline` (`base` is used for
/// the volume file names). Replaces the single-buffer [`create_in_memory`] where an index and
/// separate volumes are wanted.
pub fn build_set(base: &str, sources: &[(&str, &[u8])], opts: &SetOptions) -> Result<Par2Set, CreateError> {
    let ss = opts.slice_size;
    if ss == 0 || !ss.is_multiple_of(4) {
        return Err(CreateError::BadSliceSize(ss as u64));
    }
    if sources.is_empty() {
        return Err(CreateError::NoSources);
    }
    if (opts.first_exponent as u64 + opts.recovery_blocks as u64) > 65535 {
        return Err(CreateError::TooManyRecoveryBlocks);
    }
    struct Mem<'a> {
        name: &'a str,
        data: &'a [u8],
        id: FileId,
        slices: Vec<SliceChecksum>,
    }
    let mut mems: Vec<Mem<'_>> = Vec::with_capacity(sources.len());
    for (name, data) in sources {
        if name.is_empty() || name.len() > crate::packet::MAX_FILENAME_LEN {
            return Err(CreateError::BadSourceName(PathBuf::from(name)));
        }
        let h16 = crate::hasher::md5_16k(data);
        let id = compute_file_id(&h16, data.len() as u64, name.as_bytes());
        if mems.iter().any(|m| m.id == id) {
            return Err(CreateError::DuplicateSource(PathBuf::from(name)));
        }
        let padded: Vec<Vec<u8>> = data
            .chunks(ss)
            .map(|c| {
                let mut p = c.to_vec();
                p.resize(ss, 0);
                p
            })
            .collect();
        let refs: Vec<&[u8]> = padded.iter().map(Vec::as_slice).collect();
        let slices = crate::md5simd::md5_many(&refs).into_iter().zip(&padded).map(|(md5, p)| SliceChecksum { md5, crc32: crate::crc::crc32(p) }).collect();
        mems.push(Mem { name, data, id, slices });
    }
    mems.sort_by_key(|m| m.id);
    let input_slices: usize = mems.iter().map(|m| m.slices.len()).sum();
    if input_slices > 32768 {
        return Err(CreateError::TooManyInputSlices(input_slices as u64));
    }
    let ids: Vec<FileId> = mems.iter().map(|m| m.id).collect();
    let main_body = encode_main_body(ss as u64, &ids, &[]);
    let set_id = compute_set_id(&main_body);
    let mut critical = encode_packet(&set_id, &TYPE_MAIN, &main_body);
    for m in &mems {
        critical.extend(encode_packet(&set_id, &TYPE_FILEDESC, &encode_file_desc_body(&m.id, &md5(m.data), &crate::hasher::md5_16k(m.data), m.data.len() as u64, m.name.as_bytes())));
        if !m.slices.is_empty() {
            critical.extend(encode_packet(&set_id, &TYPE_IFSC, &encode_ifsc_body(&m.id, &m.slices)));
        }
        if opts.unicode_names && !m.name.is_ascii() {
            critical.extend(encode_packet(&set_id, &TYPE_UNIFILEN, &encode_unicode_name_body(&m.id, m.name)));
        }
    }
    critical.extend(encode_packet(&set_id, &TYPE_CREATOR, &encode_creator_body(opts.creator.as_bytes())));

    let mut volumes = Vec::new();
    if opts.recovery_blocks > 0 && input_slices > 0 {
        let exponents: Vec<u32> = (0..opts.recovery_blocks).map(|i| opts.first_exponent + i).collect();
        let mut inputs: Vec<&[u8]> = Vec::with_capacity(input_slices);
        for m in &mems {
            inputs.extend(m.data.chunks(ss));
        }
        let rec = crate::reed_solomon::encode_in_memory(ss, &inputs, &exponents, EngineConfig::default(), opts.kernel)?;
        let layout = volume_layout(opts.volumes, opts.recovery_blocks);
        let width = crate::filenames::volume_number_width(opts.first_exponent + opts.recovery_blocks);
        for (first, count) in layout {
            let name = crate::filenames::volume_filename(base, opts.first_exponent + first, count, width);
            let mut vol = Vec::new();
            for i in first..first + count {
                let (e, data) = (exponents[i as usize], &rec[i as usize]);
                vol.extend_from_slice(&crate::packet::encode_recovery_packet_prefix(&set_id, e, data));
                vol.extend_from_slice(data);
            }
            let copies = 1 + (31 - count.max(1).leading_zeros());
            for _ in 0..copies {
                vol.extend_from_slice(&critical);
            }
            volumes.push((name, vol));
        }
    }
    Ok(Par2Set { set_id, index: critical, volumes, input_slices })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{load_par2_bytes, load_par2_file, ScanOptions};

    fn rnd(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 29) as u8
            })
            .collect()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("par-rs-create-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn volume_layouts() {
        assert_eq!(volume_layout(VolumeScheme::Single, 7), vec![(0, 7)]);
        assert_eq!(volume_layout(VolumeScheme::Uniform(3), 7), vec![(0, 3), (3, 3), (6, 1)]);
        assert_eq!(volume_layout(VolumeScheme::Uniform(0), 2), vec![(0, 1), (1, 1)]);
        assert_eq!(volume_layout(VolumeScheme::Exponential, 20), vec![(0, 1), (1, 2), (3, 4), (7, 8), (15, 5)]);
        assert_eq!(volume_layout(VolumeScheme::Exponential, 1), vec![(0, 1)]);
        assert!(volume_layout(VolumeScheme::Exponential, 0).is_empty());
    }

    #[test]
    fn in_memory_set_is_self_consistent() {
        let k = Kernel::detect();
        let a = rnd(5000, 1);
        let b = rnd(1234, 2);
        let (bytes, set_id) = create_in_memory(&[(b"a.bin", &a), (b"b.bin", &b)], 1024, &[0, 1, 2], k).unwrap();
        let set = load_par2_bytes(&bytes, ScanOptions::FULL).unwrap();
        assert_eq!(set.set_id, Some(set_id));
        assert!(set.is_complete());
        assert_eq!(set.recovery.len(), 3);
        assert_eq!(set.total_input_slices(), Some(5 + 2));
        assert!(set.recovery.values().all(|r| r.md5_verified && r.slice_size == 1024));
        // Recovery exponent 0 is the XOR of all (padded) input slices.
        let r0 = set.recovery[&0];
        let mut data = vec![0u8; 1024];
        r0.read_data(&bytes, 0, &mut data).unwrap();
        let mut x = vec![0u8; 1024];
        for f in [&a, &b] {
            for c in f.chunks(1024) {
                for (i, v) in c.iter().enumerate() {
                    x[i] ^= v;
                }
            }
        }
        assert_eq!(data, x);
        assert!(matches!(create_in_memory(&[(b"a", &a)], 1002, &[0], k), Err(CreateError::BadSliceSize(1002))));
        // Empty file and no exponents.
        let (bytes, _) = create_in_memory(&[(b"e", &[])], 1024, &[], k).unwrap();
        let set = load_par2_bytes(&bytes, ScanOptions::FULL).unwrap();
        assert_eq!(set.file_descs.len(), 1);
        assert!(set.ifscs.is_empty());
        assert_eq!(set.total_input_slices(), Some(0));
    }

    #[test]
    fn create_on_disk_matches_in_memory_and_layout() {
        let dir = tmpdir("disk");
        let a = rnd(10_000, 3);
        let b = rnd(3000, 4);
        let e: Vec<u8> = vec![];
        std::fs::write(dir.join("a.bin"), &a).unwrap();
        std::fs::write(dir.join("b.bin"), &b).unwrap();
        std::fs::write(dir.join("empty.bin"), &e).unwrap();
        let sources = vec![SourceFile::new(dir.join("a.bin")), SourceFile::new(dir.join("b.bin")), SourceFile::new(dir.join("empty.bin"))];
        assert_eq!(sources[0].par2_name, b"a.bin");
        let opts = CreateOptions { slice_size: 1024, recovery_blocks: 7, volumes: VolumeScheme::Exponential, ..CreateOptions::default() };
        let mut stages = Vec::new();
        let rep = create(&sources, &dir, "set", &opts, None, &mut |st, d, t| {
            assert!(d <= t);
            stages.push(st);
        })
        .unwrap();
        assert!(stages.contains(&CreateStage::Hashing) && stages.contains(&CreateStage::Computing) && stages.contains(&CreateStage::Writing));
        assert_eq!(rep.input_slices, 10 + 3);
        assert_eq!(rep.recovery_slices, 7);
        let names: Vec<String> = rep.files.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["set.par2", "set.vol00+01.par2", "set.vol01+02.par2", "set.vol03+04.par2"]);

        // Index: complete metadata, no recovery.
        let idx = load_par2_file(&rep.files[0], ScanOptions::FULL).unwrap();
        assert_eq!(idx.set_id, Some(rep.set_id));
        assert!(idx.is_complete());
        assert_eq!(idx.file_descs.len(), 3);
        assert_eq!(idx.ifscs.len(), 2);
        assert!(idx.recovery.is_empty());
        assert_eq!(idx.creator_string(), opts.creator);
        assert_eq!(idx.stats.scan.resyncs, 0);

        // Volumes: recovery slices with verified MD5 plus repeated critical packets.
        let mut all = crate::packet::PacketSet::new();
        for (i, p) in rep.files.iter().enumerate() {
            let st = all.load_file(p, i, ScanOptions::FULL).unwrap();
            assert_eq!(st.scan.resyncs, 0);
            assert_eq!(st.scan.md5_failures, 0);
        }
        assert_eq!(all.recovery.len(), 7);
        assert_eq!(all.recovery.keys().copied().collect::<Vec<u32>>(), (0..7).collect::<Vec<u32>>());
        assert!(all.recovery.values().all(|r| r.md5_verified));
        let v3 = load_par2_file(&rep.files[3], ScanOptions::FULL).unwrap();
        assert_eq!(v3.recovery.len(), 4);
        assert!(v3.stats.duplicates >= 7); // 1 + log2(4) = 3 copies of 7 critical packets → 14 duplicates

        // Recovery data equals the in-memory creator's (same files, same exponents).
        let (mem, mem_set_id) = create_in_memory(&[(b"a.bin", &a), (b"b.bin", &b), (b"empty.bin", &e)], 1024, &(0..7).collect::<Vec<u32>>(), opts.kernel).unwrap();
        assert_eq!(mem_set_id, rep.set_id);
        let mem_set = load_par2_bytes(&mem, ScanOptions::FULL).unwrap();
        for e in 0..7u32 {
            let mut d1 = vec![0u8; 1024];
            let mut d2 = vec![0u8; 1024];
            let r1 = all.recovery[&e];
            let src = crate::packet::FileSource::open(&rep.files[r1.source_id]).unwrap();
            r1.read_data(&src, 0, &mut d1).unwrap();
            mem_set.recovery[&e].read_data(&mem, 0, &mut d2).unwrap();
            assert_eq!(d1, d2, "exponent {e}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn create_errors() {
        let dir = tmpdir("err");
        std::fs::write(dir.join("a.bin"), b"hello world").unwrap();
        let src = vec![SourceFile::new(dir.join("a.bin"))];
        let bad = CreateOptions { slice_size: 6, ..CreateOptions::default() };
        assert!(matches!(create(&src, &dir, "x", &bad, None, &mut |_, _, _| {}), Err(CreateError::BadSliceSize(6))));
        let opts = CreateOptions { slice_size: 4, recovery_blocks: 2, ..CreateOptions::default() };
        assert!(matches!(create(&[], &dir, "x", &opts, None, &mut |_, _, _| {}), Err(CreateError::NoSources)));
        let big = CreateOptions { slice_size: 4, recovery_blocks: 10, first_exponent: 65530, ..CreateOptions::default() };
        assert!(matches!(create(&src, &dir, "x", &big, None, &mut |_, _, _| {}), Err(CreateError::TooManyRecoveryBlocks)));
        let dup = vec![SourceFile::new(dir.join("a.bin")), SourceFile::new(dir.join("a.bin"))];
        assert!(matches!(create(&dup, &dir, "x", &opts, None, &mut |_, _, _| {}), Err(CreateError::DuplicateSource(_))));
        let noname = vec![SourceFile { path: dir.join("a.bin"), par2_name: vec![] }];
        assert!(matches!(create(&noname, &dir, "x", &opts, None, &mut |_, _, _| {}), Err(CreateError::BadSourceName(_))));
        let missing = vec![SourceFile::new(dir.join("nope.bin"))];
        assert!(matches!(create(&missing, &dir, "x", &opts, None, &mut |_, _, _| {}), Err(CreateError::Io(_))));
        let cancel = AtomicBool::new(true);
        assert!(matches!(create(&src, &dir, "x", &opts, Some(&cancel), &mut |_, _, _| {}), Err(CreateError::Cancelled)));
        // Too many input slices (4-byte slices over a 140 KB file → 35840 slices).
        std::fs::write(dir.join("big.bin"), vec![1u8; 140_000]).unwrap();
        let bigsrc = vec![SourceFile::new(dir.join("big.bin"))];
        assert!(matches!(create(&bigsrc, &dir, "x", &opts, None, &mut |_, _, _| {}), Err(CreateError::TooManyInputSlices(35000))));
        // Zero recovery blocks: index only.
        let zero = CreateOptions { slice_size: 4, recovery_blocks: 0, ..CreateOptions::default() };
        let rep = create(&src, &dir, "z", &zero, None, &mut |_, _, _| {}).unwrap();
        assert_eq!(rep.files.len(), 1);
        assert_eq!(rep.recovery_slices, 0);
        for e in [
            CreateError::BadSliceSize(1),
            CreateError::NoSources,
            CreateError::TooManyInputSlices(1),
            CreateError::TooManyRecoveryBlocks,
            CreateError::BadSourceName(PathBuf::new()),
            CreateError::DuplicateSource(PathBuf::new()),
            CreateError::Io(io::Error::other("x")),
            CreateError::Rs(RsError::Singular),
            CreateError::Cancelled,
            CreateError::from(RsError::Cancelled),
            CreateError::from(RsError::Io(io::Error::other("y"))),
        ] {
            assert!(!e.to_string().is_empty());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
