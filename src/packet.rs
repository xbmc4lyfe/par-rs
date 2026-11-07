//! Tolerant, lazy PAR2 packet framing, parsing and serialisation.
//!
//! * [`PacketIter`] walks any [`PacketSource`] (in-memory slice or on-disk file) packet by
//!   packet, validating the 64-byte header and, optionally, the packet MD5. When a header is
//!   corrupt (zero-filled gaps from lost articles, truncated packets, stray prefixes) it
//!   **resynchronises** by searching forward for the next `PAR2\0PKT` magic instead of aborting.
//! * Recovery slice payloads are never copied into memory: [`RecoverySliceRef`] records where
//!   the data lives so the repair engine can stream it later. Metadata-only scans can skip the
//!   (expensive) MD5 verification of recovery packets entirely.
//! * [`PacketSet`] merges the packets of one recovery set with `libpar2` semantics: the first
//!   intact packet of each kind wins, file IDs are ordered exactly like `Par2::MD5Hash::operator<`
//!   (little-endian 128-bit integer order), and packets from other sets are counted but ignored.
//! * The `encode_*` functions build spec-conformant packets for the creator and for tests.

use crate::hasher::md5;
use md5::{Digest, Md5};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::Path;

/// Packet magic.
pub const MAGIC: [u8; 8] = *b"PAR2\0PKT";
/// Packet header length.
pub const HEADER_LEN: usize = 64;
/// `Main` packet type.
pub const TYPE_MAIN: [u8; 16] = *b"PAR 2.0\0Main\0\0\0\0";
/// `FileDesc` packet type.
pub const TYPE_FILEDESC: [u8; 16] = *b"PAR 2.0\0FileDesc";
/// `IFSC` (input file slice checksum) packet type.
pub const TYPE_IFSC: [u8; 16] = *b"PAR 2.0\0IFSC\0\0\0\0";
/// `Creator` packet type.
pub const TYPE_CREATOR: [u8; 16] = *b"PAR 2.0\0Creator\0";
/// `RecvSlic` (recovery slice) packet type.
pub const TYPE_RECVSLIC: [u8; 16] = *b"PAR 2.0\0RecvSlic";

/// Largest slice size accepted (256 MiB).
pub const MAX_SLICE_SIZE: u64 = 256 * 1024 * 1024;
/// Largest file name accepted in a `FileDesc` packet.
pub const MAX_FILENAME_LEN: usize = 100_000;
/// Chunk size used when hashing large packets.
const HASH_CHUNK: usize = 1 << 20;
/// Window used when searching for the next magic during resynchronisation.
const RESYNC_WINDOW: usize = 256 * 1024;

// ---------------------------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------------------------

/// 16-byte PAR2 file identifier with `libpar2` ordering (compares byte 15 first, byte 0 last).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub [u8; 16]);

impl FileId {
    /// Numeric value in `libpar2` / specification order ("treating them as 16-byte unsigned
    /// integers", little-endian).
    #[inline]
    pub fn as_u128(&self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    /// Lower-case hex.
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }
}

impl PartialOrd for FileId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FileId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_u128().cmp(&other.as_u128())
    }
}

impl fmt::Debug for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileId({})", self.to_hex())
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// 16-byte recovery set identifier (MD5 of the main packet body).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SetId(pub [u8; 16]);

impl SetId {
    /// Lower-case hex (the form used by `ParRenamer` for set-id based file names).
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }
}

impl fmt::Debug for SetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SetId({})", self.to_hex())
    }
}

impl fmt::Display for SetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Lower-case hex of a byte string.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xF) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------------------------

/// Packet kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketType {
    /// `PAR 2.0\0Main\0\0\0\0`
    Main,
    /// `PAR 2.0\0FileDesc`
    FileDesc,
    /// `PAR 2.0\0IFSC\0\0\0\0`
    Ifsc,
    /// `PAR 2.0\0Creator\0`
    Creator,
    /// `PAR 2.0\0RecvSlic`
    RecoverySlice,
    /// Any other (application specific or optional) packet type.
    Unknown,
}

impl PacketType {
    /// Classify a raw type field.
    pub fn from_bytes(t: &[u8; 16]) -> Self {
        match *t {
            TYPE_MAIN => PacketType::Main,
            TYPE_FILEDESC => PacketType::FileDesc,
            TYPE_IFSC => PacketType::Ifsc,
            TYPE_CREATOR => PacketType::Creator,
            TYPE_RECVSLIC => PacketType::RecoverySlice,
            _ => PacketType::Unknown,
        }
    }
}

/// Parsed 64-byte packet header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    /// Total packet length including the header.
    pub length: u64,
    /// MD5 of bytes `32..length` of the packet.
    pub packet_md5: [u8; 16],
    /// Recovery set this packet belongs to.
    pub set_id: SetId,
    /// Raw packet type.
    pub packet_type: [u8; 16],
}

impl PacketHeader {
    /// Parse and validate the fixed header fields (magic, `length >= 64`, `length % 4 == 0`).
    /// Does **not** check that the packet fits the source; see [`PacketHeader::fits`].
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN || bytes[..8] != MAGIC {
            return None;
        }
        let length = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        if length < HEADER_LEN as u64 || length % 4 != 0 {
            return None;
        }
        Some(Self {
            length,
            packet_md5: bytes[16..32].try_into().unwrap(),
            set_id: SetId(bytes[32..48].try_into().unwrap()),
            packet_type: bytes[48..64].try_into().unwrap(),
        })
    }

    /// Whether a packet starting at `offset` fits inside a source of `source_len` bytes.
    pub fn fits(&self, offset: u64, source_len: u64) -> bool {
        offset.checked_add(self.length).is_some_and(|end| end <= source_len)
    }

    /// Packet kind.
    pub fn kind(&self) -> PacketType {
        PacketType::from_bytes(&self.packet_type)
    }

    /// Body length (`length - 64`).
    pub fn body_len(&self) -> u64 {
        self.length - HEADER_LEN as u64
    }

    /// Serialise.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(&MAGIC);
        out[8..16].copy_from_slice(&self.length.to_le_bytes());
        out[16..32].copy_from_slice(&self.packet_md5);
        out[32..48].copy_from_slice(&self.set_id.0);
        out[48..64].copy_from_slice(&self.packet_type);
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------------------------

/// Random-access byte source for packet scanning.
pub trait PacketSource {
    /// Total length in bytes.
    fn source_len(&self) -> u64;
    /// Fill `buf` from `offset`. Must fail if the range is out of bounds.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    /// Whether the source is empty.
    fn source_is_empty(&self) -> bool {
        self.source_len() == 0
    }
}

impl PacketSource for [u8] {
    fn source_len(&self) -> u64 {
        self.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let end = start.checked_add(buf.len()).ok_or(io::ErrorKind::UnexpectedEof)?;
        let src = self.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

impl PacketSource for Vec<u8> {
    fn source_len(&self) -> u64 {
        Vec::len(self) as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.as_slice().read_at(offset, buf)
    }
}

impl<T: PacketSource + ?Sized> PacketSource for &T {
    fn source_len(&self) -> u64 {
        (**self).source_len()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_at(offset, buf)
    }
}

/// A file opened for positional reads.
pub struct FileSource {
    file: File,
    len: u64,
    #[cfg(not(unix))]
    lock: std::sync::Mutex<()>,
}

impl FileSource {
    /// Open `path`.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::from_file(File::open(path)?)
    }

    /// Wrap an open file.
    pub fn from_file(file: File) -> io::Result<Self> {
        let len = file.metadata()?.len();
        Ok(Self {
            file,
            len,
            #[cfg(not(unix))]
            lock: std::sync::Mutex::new(()),
        })
    }

    /// Underlying file.
    pub fn file(&self) -> &File {
        &self.file
    }
}

impl PacketSource for FileSource {
    fn source_len(&self) -> u64 {
        self.len
    }

    #[cfg(unix)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.file.read_exact_at(buf, offset)
    }

    #[cfg(not(unix))]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut f = &self.file;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(buf)
    }
}

/// Positional read helper for plain `File`s used outside of packet scanning.
pub fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(not(unix))]
    {
        let mut f = file;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(buf)
    }
}

// Keep `Read`/`Seek` imports used on all platforms.
#[allow(dead_code)]
fn _seek_read_marker(mut f: &File) -> io::Result<u64> {
    let mut b = [0u8; 0];
    f.read_exact(&mut b)?;
    f.stream_position()
}

// ---------------------------------------------------------------------------------------------
// Raw packet iteration
// ---------------------------------------------------------------------------------------------

/// Options for [`PacketIter`].
#[derive(Clone, Copy, Debug)]
pub struct ScanOptions {
    /// Verify the MD5 of metadata packets (Main, FileDesc, IFSC, Creator, unknown).
    pub verify_md5: bool,
    /// Verify the MD5 of recovery slice packets (streams the whole payload). Disable for
    /// metadata-only scans; the repair engine verifies lazily before use.
    pub verify_recovery_md5: bool,
    /// Search forward for the next magic when a header is invalid instead of stopping.
    pub resync: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { verify_md5: true, verify_recovery_md5: true, resync: true }
    }
}

impl ScanOptions {
    /// Verify everything (repair loading).
    pub const FULL: ScanOptions = ScanOptions { verify_md5: true, verify_recovery_md5: true, resync: true };
    /// Verify metadata packets only; recovery payloads are indexed but not hashed.
    pub const METADATA: ScanOptions = ScanOptions { verify_md5: true, verify_recovery_md5: false, resync: true };
    /// No hashing at all (fast fingerprinting of trusted data).
    pub const UNVERIFIED: ScanOptions = ScanOptions { verify_md5: false, verify_recovery_md5: false, resync: true };
}

/// A located packet whose header validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawPacket {
    /// Offset of the packet header within the source.
    pub offset: u64,
    /// The header.
    pub header: PacketHeader,
    /// Whether the packet MD5 was checked and matched. `false` when verification was skipped.
    pub md5_verified: bool,
}

impl RawPacket {
    /// Offset of the body.
    pub fn body_offset(&self) -> u64 {
        self.offset + HEADER_LEN as u64
    }
}

/// Statistics of one scan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Packets returned.
    pub packets: u64,
    /// Headers that looked valid but whose MD5 mismatched (skipped).
    pub md5_failures: u64,
    /// Resynchronisations performed (corrupt regions skipped).
    pub resyncs: u64,
    /// Bytes skipped by resynchronisation.
    pub skipped_bytes: u64,
}

/// Iterator over the valid packets of a source.
pub struct PacketIter<'a, S: PacketSource + ?Sized> {
    src: &'a S,
    len: u64,
    pos: u64,
    opts: ScanOptions,
    stats: ScanStats,
    done: bool,
    window: Vec<u8>,
}

impl<'a, S: PacketSource + ?Sized> PacketIter<'a, S> {
    /// Start scanning `src` at offset 0.
    pub fn new(src: &'a S, opts: ScanOptions) -> Self {
        Self { src, len: src.source_len(), pos: 0, opts, stats: ScanStats::default(), done: false, window: Vec::new() }
    }

    /// Scan statistics so far.
    pub fn stats(&self) -> ScanStats {
        self.stats
    }

    /// Current offset.
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Find the next occurrence of the magic at or after `from`.
    fn find_magic(&mut self, from: u64) -> io::Result<Option<u64>> {
        let mut start = from;
        if self.window.capacity() < RESYNC_WINDOW {
            self.window.reserve(RESYNC_WINDOW);
        }
        let finder = memchr::memmem::Finder::new(&MAGIC);
        while start + MAGIC.len() as u64 <= self.len {
            let avail = (self.len - start).min(RESYNC_WINDOW as u64) as usize;
            self.window.resize(avail, 0);
            self.src.read_at(start, &mut self.window)?;
            if let Some(i) = finder.find(&self.window) {
                return Ok(Some(start + i as u64));
            }
            if avail < RESYNC_WINDOW {
                break;
            }
            // Overlap by `MAGIC.len() - 1` so a magic straddling two windows is found.
            start += (avail - (MAGIC.len() - 1)) as u64;
        }
        Ok(None)
    }

    fn verify_md5(&self, offset: u64, header: &PacketHeader) -> io::Result<bool> {
        verify_packet_md5(self.src, offset, header)
    }

    fn advance_invalid(&mut self, from: u64) -> io::Result<bool> {
        if !self.opts.resync {
            self.done = true;
            return Ok(false);
        }
        match self.find_magic(from)? {
            Some(next) => {
                self.stats.resyncs += 1;
                self.stats.skipped_bytes += next - self.pos;
                self.pos = next;
                Ok(true)
            }
            None => {
                self.stats.skipped_bytes += self.len - self.pos;
                self.pos = self.len;
                self.done = true;
                Ok(false)
            }
        }
    }

    fn next_inner(&mut self) -> io::Result<Option<RawPacket>> {
        let mut hdr = [0u8; HEADER_LEN];
        loop {
            if self.done || self.pos + HEADER_LEN as u64 > self.len {
                self.done = true;
                return Ok(None);
            }
            self.src.read_at(self.pos, &mut hdr)?;
            let header = match PacketHeader::parse(&hdr) {
                Some(h) if h.fits(self.pos, self.len) => h,
                _ => {
                    if !self.advance_invalid(self.pos + 1)? {
                        return Ok(None);
                    }
                    continue;
                }
            };
            let want_md5 = match header.kind() {
                PacketType::RecoverySlice => self.opts.verify_recovery_md5,
                _ => self.opts.verify_md5,
            };
            let mut verified = false;
            if want_md5 {
                if self.verify_md5(self.pos, &header)? {
                    verified = true;
                } else {
                    self.stats.md5_failures += 1;
                    if !self.advance_invalid(self.pos + 1)? {
                        return Ok(None);
                    }
                    continue;
                }
            }
            let raw = RawPacket { offset: self.pos, header, md5_verified: verified };
            self.pos += header.length;
            self.stats.packets += 1;
            return Ok(Some(raw));
        }
    }
}

impl<'a, S: PacketSource + ?Sized> Iterator for PacketIter<'a, S> {
    type Item = io::Result<RawPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_inner() {
            Ok(Some(p)) => Some(Ok(p)),
            Ok(None) => None,
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Verify the MD5 of a packet located at `offset` (hashes bytes `32..length`, streaming).
pub fn verify_packet_md5<S: PacketSource + ?Sized>(src: &S, offset: u64, header: &PacketHeader) -> io::Result<bool> {
    let mut ctx = Md5::new();
    let mut remaining = header.length - 32;
    let mut pos = offset + 32;
    let mut buf = vec![0u8; (remaining as usize).min(HASH_CHUNK)];
    while remaining > 0 {
        let n = (remaining as usize).min(buf.len());
        src.read_at(pos, &mut buf[..n])?;
        ctx.update(&buf[..n]);
        pos += n as u64;
        remaining -= n as u64;
    }
    let digest: [u8; 16] = ctx.finalize().into();
    Ok(digest == header.packet_md5)
}

// ---------------------------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------------------------

/// Reasons a structurally framed packet is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// Body shorter than the fixed part of the payload.
    Truncated,
    /// Slice size is zero, not a multiple of 4, or above [`MAX_SLICE_SIZE`].
    BadSliceSize(u64),
    /// Main packet body is not `12 + 16 * n` bytes.
    BadMainLayout,
    /// `recoverable_count` exceeds the number of file IDs.
    BadRecoverableCount {
        /// Declared recoverable file count.
        count: u32,
        /// File IDs actually present in the body.
        total: usize,
    },
    /// File description name is empty or longer than [`MAX_FILENAME_LEN`].
    BadFileName,
    /// `file_length <= 16384` but the 16k hash differs from the full hash.
    InconsistentHashes,
    /// IFSC body is not `16 + 20 * n` bytes.
    BadIfscLayout,
    /// Recovery slice payload is empty.
    EmptyRecoverySlice,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::Truncated => f.write_str("packet body truncated"),
            PacketError::BadSliceSize(s) => write!(f, "invalid slice size {s}"),
            PacketError::BadMainLayout => f.write_str("main packet body length is not 12 + 16n"),
            PacketError::BadRecoverableCount { count, total } => {
                write!(f, "recoverable file count {count} exceeds {total} file ids")
            }
            PacketError::BadFileName => f.write_str("file description has an empty or oversized name"),
            PacketError::InconsistentHashes => f.write_str("16k hash differs from full hash for a file <= 16 KiB"),
            PacketError::BadIfscLayout => f.write_str("IFSC body length is not 16 + 20n"),
            PacketError::EmptyRecoverySlice => f.write_str("recovery slice packet has no payload"),
        }
    }
}

impl std::error::Error for PacketError {}

/// `Main` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MainPacket {
    /// Set this packet defines (MD5 of its body).
    pub set_id: SetId,
    /// Slice size in bytes.
    pub slice_size: u64,
    /// Number of recoverable files.
    pub recoverable_count: u32,
    /// File IDs of the recovery set, in packet order (ascending `FileId` per spec).
    pub recoverable_file_ids: Vec<FileId>,
    /// File IDs of the non-recovery set.
    pub non_recoverable_file_ids: Vec<FileId>,
}

impl MainPacket {
    /// Parse a body.
    pub fn parse(set_id: SetId, body: &[u8]) -> Result<Self, PacketError> {
        if body.len() < 12 {
            return Err(PacketError::Truncated);
        }
        if !(body.len() - 12).is_multiple_of(16) {
            return Err(PacketError::BadMainLayout);
        }
        let slice_size = u64::from_le_bytes(body[0..8].try_into().unwrap());
        if slice_size == 0 || slice_size % 4 != 0 || slice_size > MAX_SLICE_SIZE {
            return Err(PacketError::BadSliceSize(slice_size));
        }
        let recoverable_count = u32::from_le_bytes(body[8..12].try_into().unwrap());
        let ids: Vec<FileId> = body[12..].as_chunks::<16>().0.iter().map(|c| FileId(*c)).collect();
        if recoverable_count as usize > ids.len() {
            return Err(PacketError::BadRecoverableCount { count: recoverable_count, total: ids.len() });
        }
        let (rec, non) = ids.split_at(recoverable_count as usize);
        Ok(Self {
            set_id,
            slice_size,
            recoverable_count,
            recoverable_file_ids: rec.to_vec(),
            non_recoverable_file_ids: non.to_vec(),
        })
    }

    /// All file IDs, recoverable first.
    pub fn all_file_ids(&self) -> impl Iterator<Item = &FileId> {
        self.recoverable_file_ids.iter().chain(self.non_recoverable_file_ids.iter())
    }

    /// Total number of files.
    pub fn total_file_count(&self) -> usize {
        self.recoverable_file_ids.len() + self.non_recoverable_file_ids.len()
    }

    /// Number of slices needed to cover `file_length` bytes.
    pub fn slice_count_for(&self, file_length: u64) -> u64 {
        file_length.div_ceil(self.slice_size)
    }

    /// Serialise the body (without header).
    pub fn encode_body(&self) -> Vec<u8> {
        encode_main_body(self.slice_size, &self.recoverable_file_ids, &self.non_recoverable_file_ids)
    }
}

/// `FileDesc` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileDescPacket {
    /// File ID.
    pub file_id: FileId,
    /// MD5 of the whole file.
    pub hash_full: [u8; 16],
    /// MD5 of the first 16 KiB.
    pub hash_16k: [u8; 16],
    /// File length.
    pub file_length: u64,
    /// Raw file name bytes with trailing NUL padding removed.
    pub name: Vec<u8>,
}

impl FileDescPacket {
    /// Parse a body.
    pub fn parse(body: &[u8]) -> Result<Self, PacketError> {
        if body.len() < 56 {
            return Err(PacketError::Truncated);
        }
        let name_padded = &body[56..];
        if name_padded.len() > MAX_FILENAME_LEN {
            return Err(PacketError::BadFileName);
        }
        let end = name_padded.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
        let name = name_padded[..end].to_vec();
        if name.is_empty() {
            return Err(PacketError::BadFileName);
        }
        let hash_full: [u8; 16] = body[16..32].try_into().unwrap();
        let hash_16k: [u8; 16] = body[32..48].try_into().unwrap();
        let file_length = u64::from_le_bytes(body[48..56].try_into().unwrap());
        if file_length <= crate::hasher::HASH_16K_LEN && hash_16k != hash_full {
            return Err(PacketError::InconsistentHashes);
        }
        Ok(Self { file_id: FileId(body[0..16].try_into().unwrap()), hash_full, hash_16k, file_length, name })
    }

    /// File ID recomputed from the packet contents.
    pub fn computed_file_id(&self) -> FileId {
        compute_file_id(&self.hash_16k, self.file_length, &self.name)
    }

    /// Whether the stored file ID matches the recomputed one.
    pub fn id_consistent(&self) -> bool {
        self.computed_file_id() == self.file_id
    }

    /// Local (sanitised) file name.
    pub fn local_name(&self) -> String {
        translate_filename_from_par2_to_local(&self.name)
    }

    /// Raw name interpreted as text (UTF-8, or Latin-1 if invalid), without sanitising.
    pub fn name_lossy(&self) -> String {
        bytes_to_string_latin1_fallback(&self.name)
    }

    /// Serialise the body.
    pub fn encode_body(&self) -> Vec<u8> {
        encode_file_desc_body(&self.file_id, &self.hash_full, &self.hash_16k, self.file_length, &self.name)
    }
}

/// Checksums of one input slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SliceChecksum {
    /// MD5 of the (zero padded) slice.
    pub md5: [u8; 16],
    /// CRC-32 of the (zero padded) slice.
    pub crc32: u32,
}

/// `IFSC` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfscPacket {
    /// File ID.
    pub file_id: FileId,
    /// Per-slice checksums in file order.
    pub slices: Vec<SliceChecksum>,
}

impl IfscPacket {
    /// Parse a body.
    pub fn parse(body: &[u8]) -> Result<Self, PacketError> {
        if body.len() < 16 {
            return Err(PacketError::Truncated);
        }
        if !(body.len() - 16).is_multiple_of(20) {
            return Err(PacketError::BadIfscLayout);
        }
        let slices = body[16..]
            .as_chunks::<20>()
            .0
            .iter()
            .map(|e| SliceChecksum {
                md5: e[0..16].try_into().unwrap(),
                crc32: u32::from_le_bytes(e[16..20].try_into().unwrap()),
            })
            .collect();
        Ok(Self { file_id: FileId(body[0..16].try_into().unwrap()), slices })
    }

    /// Number of slices.
    pub fn slice_count(&self) -> usize {
        self.slices.len()
    }

    /// Serialise the body.
    pub fn encode_body(&self) -> Vec<u8> {
        encode_ifsc_body(&self.file_id, &self.slices)
    }
}

/// `Creator` packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatorPacket {
    /// Raw client bytes (NUL padding removed).
    pub raw: Vec<u8>,
}

impl CreatorPacket {
    /// Parse a body.
    pub fn parse(body: &[u8]) -> Self {
        let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
        Self { raw: body[..end].to_vec() }
    }

    /// Client string (lossy UTF-8).
    pub fn client(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }
}

/// Lightweight handle to a recovery slice payload that stays on disk / in the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverySliceRef {
    /// Set this slice belongs to.
    pub set_id: SetId,
    /// Recovery exponent.
    pub exponent: u32,
    /// Caller-defined identifier of the source (e.g. index into a list of par2 files).
    pub source_id: usize,
    /// Offset of the packet header within the source.
    pub packet_offset: u64,
    /// Offset of the recovery data within the source.
    pub data_offset: u64,
    /// Payload length (should equal the set's slice size).
    pub slice_size: u64,
    /// Whether the packet MD5 has been verified.
    pub md5_verified: bool,
}

impl RecoverySliceRef {
    /// Build from a framed recovery packet; reads only the 4-byte exponent.
    pub fn from_raw<S: PacketSource + ?Sized>(src: &S, raw: &RawPacket, source_id: usize) -> io::Result<Result<Self, PacketError>> {
        if raw.header.body_len() < 4 {
            return Ok(Err(PacketError::Truncated));
        }
        let payload = raw.header.body_len() - 4;
        if payload == 0 {
            return Ok(Err(PacketError::EmptyRecoverySlice));
        }
        let mut e = [0u8; 4];
        src.read_at(raw.body_offset(), &mut e)?;
        Ok(Ok(Self {
            set_id: raw.header.set_id,
            exponent: u32::from_le_bytes(e),
            source_id,
            packet_offset: raw.offset,
            data_offset: raw.body_offset() + 4,
            slice_size: payload,
            md5_verified: raw.md5_verified,
        }))
    }

    /// Header of the packet this reference points at, reconstructed for MD5 verification.
    pub fn header_length(&self) -> u64 {
        self.slice_size + 4 + HEADER_LEN as u64
    }

    /// Verify the packet MD5 by streaming the payload from `src`.
    pub fn verify<S: PacketSource + ?Sized>(&self, src: &S) -> io::Result<bool> {
        let mut hdr = [0u8; HEADER_LEN];
        src.read_at(self.packet_offset, &mut hdr)?;
        let Some(h) = PacketHeader::parse(&hdr) else {
            return Ok(false);
        };
        if h.length != self.header_length() || !h.fits(self.packet_offset, src.source_len()) {
            return Ok(false);
        }
        verify_packet_md5(src, self.packet_offset, &h)
    }

    /// Read the payload (or a sub-range `[start, start + buf.len())` of it).
    pub fn read_data<S: PacketSource + ?Sized>(&self, src: &S, start: u64, buf: &mut [u8]) -> io::Result<()> {
        if start + buf.len() as u64 > self.slice_size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read beyond recovery slice"));
        }
        src.read_at(self.data_offset + start, buf)
    }
}

/// A parsed packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// Main packet.
    Main(MainPacket),
    /// File description.
    FileDesc(FileDescPacket),
    /// Slice checksums.
    Ifsc(IfscPacket),
    /// Creator.
    Creator(CreatorPacket),
    /// Recovery slice (payload left in place).
    RecoverySlice(RecoverySliceRef),
    /// Unknown type, skipped.
    Unknown {
        /// Raw type field.
        packet_type: [u8; 16],
    },
}

impl Packet {
    /// Set ID of the packet.
    pub fn set_id(&self, raw: &RawPacket) -> SetId {
        raw.header.set_id
    }
}

/// Parse a framed packet. Recovery slices read only their exponent.
pub fn parse_packet<S: PacketSource + ?Sized>(src: &S, raw: &RawPacket, source_id: usize) -> io::Result<Result<Packet, PacketError>> {
    let kind = raw.header.kind();
    if kind == PacketType::RecoverySlice {
        return Ok(RecoverySliceRef::from_raw(src, raw, source_id)?.map(Packet::RecoverySlice));
    }
    if kind == PacketType::Unknown {
        return Ok(Ok(Packet::Unknown { packet_type: raw.header.packet_type }));
    }
    let body_len = raw.header.body_len();
    if body_len > (64 << 20) {
        // No legitimate metadata packet is this large; refuse to allocate.
        return Ok(Err(PacketError::BadMainLayout));
    }
    let mut body = vec![0u8; body_len as usize];
    src.read_at(raw.body_offset(), &mut body)?;
    Ok(match kind {
        PacketType::Main => MainPacket::parse(raw.header.set_id, &body).map(Packet::Main),
        PacketType::FileDesc => FileDescPacket::parse(&body).map(Packet::FileDesc),
        PacketType::Ifsc => IfscPacket::parse(&body).map(Packet::Ifsc),
        PacketType::Creator => Ok(Packet::Creator(CreatorPacket::parse(&body))),
        PacketType::RecoverySlice | PacketType::Unknown => unreachable!(),
    })
}

// ---------------------------------------------------------------------------------------------
// File name translation
// ---------------------------------------------------------------------------------------------

/// Decode bytes as UTF-8, falling back to Latin-1 (each byte becomes the code point of the
/// same value) when the bytes are not valid UTF-8.
pub fn bytes_to_string_latin1_fallback(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}

fn url_encode_byte(out: &mut Vec<u8>, b: u8) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    out.push(b'%');
    out.push(DIGITS[(b >> 4) as usize]);
    out.push(DIGITS[(b & 0xF) as usize]);
}

/// Port of `Par2::DescriptionPacket::TranslateFilenameFromPar2ToLocal` (POSIX flavour):
///
/// * `\` becomes `/`,
/// * bytes `< 32` are URL-encoded as `%XX` (upper-case hex),
/// * a leading `/` is URL-encoded,
/// * every `..` that is part of a `../` sequence is URL-encoded,
/// * invalid UTF-8 is interpreted as Latin-1.
pub fn translate_filename_from_par2_to_local(raw: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(raw.len() + 8);
    for &b in raw {
        let ch = if b == b'\\' { b'/' } else { b };
        if ch < 32 {
            url_encode_byte(&mut out, ch);
        } else {
            out.push(ch);
        }
    }
    if out.first() == Some(&b'/') {
        out.remove(0);
        let mut enc = Vec::with_capacity(out.len() + 3);
        url_encode_byte(&mut enc, b'/');
        enc.extend_from_slice(&out);
        out = enc;
    }
    // Replace every "../" by "%2E%2E/" (loop until none left, as libpar2 does).
    let finder = memchr::memmem::Finder::new(b"../");
    while let Some(i) = finder.find(&out) {
        let mut enc = Vec::with_capacity(out.len() + 4);
        enc.extend_from_slice(&out[..i]);
        enc.extend_from_slice(b"%2E%2E");
        enc.extend_from_slice(&out[i + 2..]);
        out = enc;
    }
    bytes_to_string_latin1_fallback(&out)
}

// ---------------------------------------------------------------------------------------------
// Identifier computation and serialisation
// ---------------------------------------------------------------------------------------------

/// `file_id = MD5(hash_16k ‖ file_length(LE u64) ‖ name)`.
pub fn compute_file_id(hash_16k: &[u8; 16], file_length: u64, name: &[u8]) -> FileId {
    let mut ctx = Md5::new();
    ctx.update(hash_16k);
    ctx.update(file_length.to_le_bytes());
    ctx.update(name);
    FileId(ctx.finalize().into())
}

/// `set_id = MD5(main packet body)`.
pub fn compute_set_id(main_body: &[u8]) -> SetId {
    SetId(md5(main_body))
}

/// Pad to a multiple of 4 with NULs.
fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

/// Serialise a Main packet body. File IDs are sorted as the specification requires.
pub fn encode_main_body(slice_size: u64, recoverable: &[FileId], non_recoverable: &[FileId]) -> Vec<u8> {
    let mut rec = recoverable.to_vec();
    rec.sort_unstable();
    let mut non = non_recoverable.to_vec();
    non.sort_unstable();
    let mut body = Vec::with_capacity(12 + 16 * (rec.len() + non.len()));
    body.extend_from_slice(&slice_size.to_le_bytes());
    body.extend_from_slice(&(rec.len() as u32).to_le_bytes());
    for id in rec.iter().chain(non.iter()) {
        body.extend_from_slice(&id.0);
    }
    body
}

/// Serialise a FileDesc body.
pub fn encode_file_desc_body(file_id: &FileId, hash_full: &[u8; 16], hash_16k: &[u8; 16], file_length: u64, name: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(56 + name.len() + 3);
    body.extend_from_slice(&file_id.0);
    body.extend_from_slice(hash_full);
    body.extend_from_slice(hash_16k);
    body.extend_from_slice(&file_length.to_le_bytes());
    body.extend_from_slice(name);
    pad4(&mut body);
    body
}

/// Serialise an IFSC body.
pub fn encode_ifsc_body(file_id: &FileId, slices: &[SliceChecksum]) -> Vec<u8> {
    let mut body = Vec::with_capacity(16 + 20 * slices.len());
    body.extend_from_slice(&file_id.0);
    for s in slices {
        body.extend_from_slice(&s.md5);
        body.extend_from_slice(&s.crc32.to_le_bytes());
    }
    body
}

/// Serialise a Creator body.
pub fn encode_creator_body(client: &[u8]) -> Vec<u8> {
    let mut body = client.to_vec();
    pad4(&mut body);
    if body.is_empty() {
        body.resize(4, 0);
    }
    body
}

/// Build a complete packet (header + body) with the correct MD5.
pub fn encode_packet(set_id: &SetId, packet_type: &[u8; 16], body: &[u8]) -> Vec<u8> {
    debug_assert!(body.len().is_multiple_of(4), "packet bodies must be 4-byte aligned");
    let length = (HEADER_LEN + body.len()) as u64;
    let mut ctx = Md5::new();
    ctx.update(set_id.0);
    ctx.update(packet_type);
    ctx.update(body);
    let header = PacketHeader { length, packet_md5: ctx.finalize().into(), set_id: *set_id, packet_type: *packet_type };
    let mut out = Vec::with_capacity(length as usize);
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(body);
    out
}

/// Build the 68-byte prefix (header + exponent) of a recovery slice packet whose payload is
/// `data`. The MD5 covers set id, type, exponent and payload.
pub fn encode_recovery_packet_prefix(set_id: &SetId, exponent: u32, data: &[u8]) -> [u8; HEADER_LEN + 4] {
    let mut ctx = Md5::new();
    ctx.update(set_id.0);
    ctx.update(TYPE_RECVSLIC);
    ctx.update(exponent.to_le_bytes());
    ctx.update(data);
    let header = PacketHeader {
        length: (HEADER_LEN + 4 + data.len()) as u64,
        packet_md5: ctx.finalize().into(),
        set_id: *set_id,
        packet_type: TYPE_RECVSLIC,
    };
    let mut out = [0u8; HEADER_LEN + 4];
    out[..HEADER_LEN].copy_from_slice(&header.to_bytes());
    out[HEADER_LEN..].copy_from_slice(&exponent.to_le_bytes());
    out
}

/// Incremental MD5 for a recovery packet whose payload is produced in pieces.
pub struct RecoveryPacketHasher {
    ctx: Md5,
    set_id: SetId,
    exponent: u32,
    len: u64,
}

impl RecoveryPacketHasher {
    /// Start hashing a recovery packet.
    pub fn new(set_id: SetId, exponent: u32) -> Self {
        let mut ctx = Md5::new();
        ctx.update(set_id.0);
        ctx.update(TYPE_RECVSLIC);
        ctx.update(exponent.to_le_bytes());
        Self { ctx, set_id, exponent, len: 0 }
    }

    /// Feed payload bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
        self.len += data.len() as u64;
    }

    /// Produce the 68-byte header + exponent prefix.
    pub fn finish(self) -> [u8; HEADER_LEN + 4] {
        let header = PacketHeader {
            length: HEADER_LEN as u64 + 4 + self.len,
            packet_md5: self.ctx.finalize().into(),
            set_id: self.set_id,
            packet_type: TYPE_RECVSLIC,
        };
        let mut out = [0u8; HEADER_LEN + 4];
        out[..HEADER_LEN].copy_from_slice(&header.to_bytes());
        out[HEADER_LEN..].copy_from_slice(&self.exponent.to_le_bytes());
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Packet set
// ---------------------------------------------------------------------------------------------

/// Outcome of adding a packet to a [`PacketSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddOutcome {
    /// Stored.
    Added,
    /// A packet of the same identity was already present (first one wins).
    Duplicate,
    /// Belongs to another recovery set.
    ForeignSet,
    /// Recovery slice whose payload length does not match the slice size.
    WrongSliceSize,
    /// Unknown packet type.
    Unknown,
}

/// Counters accumulated while loading.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadStats {
    /// Packets added.
    pub added: u64,
    /// Duplicate packets ignored.
    pub duplicates: u64,
    /// Packets from other sets ignored.
    pub foreign: u64,
    /// Recovery packets with the wrong payload size.
    pub wrong_slice_size: u64,
    /// Structurally invalid payloads.
    pub invalid: u64,
    /// Unknown packet types.
    pub unknown: u64,
    /// Scan statistics (framing).
    pub scan: ScanStats,
}

impl LoadStats {
    fn merge(&mut self, o: &LoadStats) {
        self.added += o.added;
        self.duplicates += o.duplicates;
        self.foreign += o.foreign;
        self.wrong_slice_size += o.wrong_slice_size;
        self.invalid += o.invalid;
        self.unknown += o.unknown;
        self.scan.packets += o.scan.packets;
        self.scan.md5_failures += o.scan.md5_failures;
        self.scan.resyncs += o.scan.resyncs;
        self.scan.skipped_bytes += o.scan.skipped_bytes;
    }
}

/// All packets of one recovery set.
#[derive(Clone, Debug, Default)]
pub struct PacketSet {
    /// Set identifier; `None` until the first packet is added.
    pub set_id: Option<SetId>,
    /// Main packet.
    pub main: Option<MainPacket>,
    /// Creator packet.
    pub creator: Option<CreatorPacket>,
    /// File descriptions in `libpar2` order.
    pub file_descs: BTreeMap<FileId, FileDescPacket>,
    /// Slice checksums in `libpar2` order.
    pub ifscs: BTreeMap<FileId, IfscPacket>,
    /// Recovery slices by exponent (first seen wins).
    pub recovery: BTreeMap<u32, RecoverySliceRef>,
    /// Accumulated statistics.
    pub stats: LoadStats,
}

impl PacketSet {
    /// Empty set bound to nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty set bound to `set_id`.
    pub fn for_set(set_id: SetId) -> Self {
        Self { set_id: Some(set_id), ..Self::default() }
    }

    /// Slice size, if a Main packet is present.
    pub fn slice_size(&self) -> Option<u64> {
        self.main.as_ref().map(|m| m.slice_size)
    }

    /// Creator string, or `""`.
    pub fn creator_string(&self) -> String {
        self.creator.as_ref().map(|c| c.client()).unwrap_or_default()
    }

    /// Add a parsed packet whose header carried `set_id`.
    pub fn add(&mut self, set_id: SetId, packet: Packet) -> AddOutcome {
        if let Packet::Unknown { .. } = packet {
            self.stats.unknown += 1;
            return AddOutcome::Unknown;
        }
        match self.set_id {
            None => {
                // Bind to the first Main packet if possible, otherwise to the first packet.
                self.set_id = Some(set_id);
            }
            Some(s) if s != set_id => {
                self.stats.foreign += 1;
                return AddOutcome::ForeignSet;
            }
            _ => {}
        }
        let outcome = match packet {
            Packet::Main(m) => {
                if self.main.is_some() {
                    AddOutcome::Duplicate
                } else {
                    // Any recovery slices stored before the Main packet must match its size.
                    self.main = Some(m);
                    let ss = self.main.as_ref().unwrap().slice_size;
                    let before = self.recovery.len();
                    self.recovery.retain(|_, r| r.slice_size == ss);
                    self.stats.wrong_slice_size += (before - self.recovery.len()) as u64;
                    AddOutcome::Added
                }
            }
            Packet::FileDesc(fd) => match self.file_descs.entry(fd.file_id) {
                std::collections::btree_map::Entry::Occupied(_) => AddOutcome::Duplicate,
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(fd);
                    AddOutcome::Added
                }
            },
            Packet::Ifsc(p) => match self.ifscs.entry(p.file_id) {
                std::collections::btree_map::Entry::Occupied(_) => AddOutcome::Duplicate,
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(p);
                    AddOutcome::Added
                }
            },
            Packet::Creator(c) => {
                if self.creator.is_some() {
                    AddOutcome::Duplicate
                } else {
                    self.creator = Some(c);
                    AddOutcome::Added
                }
            }
            Packet::RecoverySlice(r) => {
                if let Some(ss) = self.slice_size()
                    && r.slice_size != ss {
                        self.stats.wrong_slice_size += 1;
                        return AddOutcome::WrongSliceSize;
                    }
                match self.recovery.entry(r.exponent) {
                    std::collections::btree_map::Entry::Occupied(_) => AddOutcome::Duplicate,
                    std::collections::btree_map::Entry::Vacant(v) => {
                        v.insert(r);
                        AddOutcome::Added
                    }
                }
            }
            Packet::Unknown { .. } => unreachable!(),
        };
        match outcome {
            AddOutcome::Added => self.stats.added += 1,
            AddOutcome::Duplicate => self.stats.duplicates += 1,
            _ => {}
        }
        outcome
    }

    /// Scan `src` and add every packet of this set. `source_id` is recorded in recovery
    /// slice references. Returns the statistics of this source only.
    pub fn load_source<S: PacketSource + ?Sized>(&mut self, src: &S, source_id: usize, opts: ScanOptions) -> io::Result<LoadStats> {
        let mut local = LoadStats::default();
        let mut iter = PacketIter::new(src, opts);
        // When the set is not bound yet, a Main packet anywhere in the source should
        // determine the set id. Collect packets first, bind, then add.
        let mut pending: Vec<(SetId, Packet)> = Vec::new();
        for raw in iter.by_ref() {
            let raw = raw?;
            match parse_packet(src, &raw, source_id)? {
                Ok(p) => pending.push((raw.header.set_id, p)),
                Err(_) => local.invalid += 1,
            }
        }
        local.scan = iter.stats();
        if self.set_id.is_none()
            && let Some((sid, _)) = pending.iter().find(|(_, p)| matches!(p, Packet::Main(_))) {
                self.set_id = Some(*sid);
            }
        for (sid, p) in pending {
            match self.add(sid, p) {
                AddOutcome::Added => local.added += 1,
                AddOutcome::Duplicate => local.duplicates += 1,
                AddOutcome::ForeignSet => local.foreign += 1,
                AddOutcome::WrongSliceSize => local.wrong_slice_size += 1,
                AddOutcome::Unknown => local.unknown += 1,
            }
        }
        // `add` already counted into self.stats except scan/invalid.
        self.stats.invalid += local.invalid;
        self.stats.scan.packets += local.scan.packets;
        self.stats.scan.md5_failures += local.scan.md5_failures;
        self.stats.scan.resyncs += local.scan.resyncs;
        self.stats.scan.skipped_bytes += local.scan.skipped_bytes;
        Ok(local)
    }

    /// Load a `.par2` file from disk.
    pub fn load_file(&mut self, path: &Path, source_id: usize, opts: ScanOptions) -> io::Result<LoadStats> {
        let src = FileSource::open(path)?;
        self.load_source(&src, source_id, opts)
    }

    /// File id of the description whose name matches `name` (raw PAR2 bytes or the translated
    /// local name; exact match first, then ASCII case-insensitive). Ties resolve in `libpar2`
    /// order (ascending 128-bit file id).
    pub fn file_id_by_name(&self, name: &[u8]) -> Option<FileId> {
        let local = |fd: &FileDescPacket| fd.local_name();
        if let Some((id, _)) = self.file_descs.iter().find(|(_, fd)| fd.name.as_slice() == name || local(fd).as_bytes() == name) {
            return Some(*id);
        }
        let lower: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
        self.file_descs
            .iter()
            .find(|(_, fd)| fd.name.iter().map(|b| b.to_ascii_lowercase()).eq(lower.iter().copied()) || local(fd).to_ascii_lowercase().as_bytes() == lower.as_slice())
            .map(|(id, _)| *id)
    }

    /// File id of the first description (in `libpar2` order) with this 16k hash.
    pub fn file_id_by_hash16k(&self, hash_16k: &[u8; 16]) -> Option<FileId> {
        self.file_descs.iter().find(|(_, fd)| fd.hash_16k == *hash_16k).map(|(id, _)| *id)
    }

    /// File IDs in Main-packet order (recoverable first), or in `libpar2` map order when no
    /// Main packet is available.
    pub fn file_ids_in_main_order(&self) -> Vec<FileId> {
        match &self.main {
            Some(m) => m.all_file_ids().copied().collect(),
            None => self.file_descs.keys().copied().collect(),
        }
    }

    /// Whether the metadata is complete enough for verification/repair: Main present and a
    /// FileDesc for every recoverable file.
    pub fn is_complete(&self) -> bool {
        match &self.main {
            Some(m) => m.recoverable_file_ids.iter().all(|id| self.file_descs.contains_key(id)),
            None => false,
        }
    }

    /// Total number of input slices across the recoverable files (requires Main + FileDescs).
    pub fn total_input_slices(&self) -> Option<u64> {
        let m = self.main.as_ref()?;
        let mut total = 0u64;
        for id in &m.recoverable_file_ids {
            let fd = self.file_descs.get(id)?;
            total += m.slice_count_for(fd.file_length);
        }
        Some(total)
    }

    /// Number of recovery slices available.
    pub fn recovery_count(&self) -> usize {
        self.recovery.len()
    }

    /// Merge another set of the same id (used when loading volumes incrementally).
    pub fn merge(&mut self, other: PacketSet) {
        if let (Some(a), Some(b)) = (self.set_id, other.set_id)
            && a != b {
                self.stats.foreign += other.stats.added;
                return;
            }
        if self.set_id.is_none() {
            self.set_id = other.set_id;
        }
        let other_stats = other.stats;
        if let Some(m) = other.main {
            self.add(m.set_id, Packet::Main(m));
        }
        let sid = self.set_id.unwrap_or(SetId([0; 16]));
        if let Some(c) = other.creator {
            self.add(sid, Packet::Creator(c));
        }
        for (_, fd) in other.file_descs {
            self.add(sid, Packet::FileDesc(fd));
        }
        for (_, p) in other.ifscs {
            self.add(sid, Packet::Ifsc(p));
        }
        for (_, r) in other.recovery {
            self.add(sid, Packet::RecoverySlice(r));
        }
        self.stats.invalid += other_stats.invalid;
        self.stats.scan.packets += other_stats.scan.packets;
        self.stats.scan.md5_failures += other_stats.scan.md5_failures;
        self.stats.scan.resyncs += other_stats.scan.resyncs;
        self.stats.scan.skipped_bytes += other_stats.scan.skipped_bytes;
    }
}

/// Packets of every recovery set found in one or more sources, keyed by set id.
#[derive(Clone, Debug, Default)]
pub struct Par2Collection {
    /// Sets by id.
    pub sets: BTreeMap<SetId, PacketSet>,
    /// Aggregate statistics.
    pub stats: LoadStats,
}

impl Par2Collection {
    /// Empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan `src` and distribute packets into their sets.
    pub fn load_source<S: PacketSource + ?Sized>(&mut self, src: &S, source_id: usize, opts: ScanOptions) -> io::Result<LoadStats> {
        let mut local = LoadStats::default();
        let mut iter = PacketIter::new(src, opts);
        for raw in iter.by_ref() {
            let raw = raw?;
            match parse_packet(src, &raw, source_id)? {
                Ok(Packet::Unknown { .. }) => local.unknown += 1,
                Ok(p) => {
                    let sid = raw.header.set_id;
                    let set = self.sets.entry(sid).or_insert_with(|| PacketSet::for_set(sid));
                    match set.add(sid, p) {
                        AddOutcome::Added => local.added += 1,
                        AddOutcome::Duplicate => local.duplicates += 1,
                        AddOutcome::WrongSliceSize => local.wrong_slice_size += 1,
                        AddOutcome::ForeignSet | AddOutcome::Unknown => unreachable!(),
                    }
                }
                Err(_) => local.invalid += 1,
            }
        }
        local.scan = iter.stats();
        self.stats.merge(&local);
        Ok(local)
    }

    /// Load a file from disk.
    pub fn load_file(&mut self, path: &Path, source_id: usize, opts: ScanOptions) -> io::Result<LoadStats> {
        let src = FileSource::open(path)?;
        self.load_source(&src, source_id, opts)
    }

    /// The set with a Main packet and the most packets, if any (useful when a directory
    /// contains stray packets of another set).
    pub fn primary_set(&self) -> Option<&PacketSet> {
        self.sets.values().filter(|s| s.main.is_some()).max_by_key(|s| s.stats.added)
    }
}

/// Convenience: load one `.par2` file into a fresh set.
pub fn load_par2_file(path: &Path, opts: ScanOptions) -> io::Result<PacketSet> {
    let mut set = PacketSet::new();
    set.load_file(path, 0, opts)?;
    Ok(set)
}

/// Convenience: parse in-memory PAR2 data into a fresh set (first Main packet binds the set).
pub fn load_par2_bytes(data: &[u8], opts: ScanOptions) -> io::Result<PacketSet> {
    let mut set = PacketSet::new();
    set.load_source(data, 0, opts)?;
    Ok(set)
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a small but complete in-memory PAR2 set: returns (bytes, set id, slice size).
    pub(crate) fn build_test_set(files: &[(&[u8], &[u8])], slice_size: u64, recovery_exponents: &[u32]) -> (Vec<u8>, SetId) {
        let mut descs = Vec::new();
        let mut ifscs = Vec::new();
        for (name, data) in files {
            let h = crate::hasher::md5(data);
            let h16 = crate::hasher::md5_16k(data);
            let id = compute_file_id(&h16, data.len() as u64, name);
            descs.push((id, encode_file_desc_body(&id, &h, &h16, data.len() as u64, name)));
            let mut slices = Vec::new();
            for chunk in data.chunks(slice_size as usize) {
                let mut padded = chunk.to_vec();
                padded.resize(slice_size as usize, 0);
                let (crc32, md5) = crate::hasher::slice_checksums(&padded);
                slices.push(SliceChecksum { md5, crc32 });
            }
            ifscs.push(encode_ifsc_body(&id, &slices));
        }
        let ids: Vec<FileId> = descs.iter().map(|(id, _)| *id).collect();
        let main_body = encode_main_body(slice_size, &ids, &[]);
        let set_id = compute_set_id(&main_body);
        let mut out = Vec::new();
        out.extend(encode_packet(&set_id, &TYPE_MAIN, &main_body));
        for (_, b) in &descs {
            out.extend(encode_packet(&set_id, &TYPE_FILEDESC, b));
        }
        for b in &ifscs {
            out.extend(encode_packet(&set_id, &TYPE_IFSC, b));
        }
        out.extend(encode_packet(&set_id, &TYPE_CREATOR, &encode_creator_body(b"par-rs test")));
        for &e in recovery_exponents {
            let data: Vec<u8> = (0..slice_size as usize).map(|i| (i as u32 * (e + 1)) as u8).collect();
            out.extend_from_slice(&encode_recovery_packet_prefix(&set_id, e, &data));
            out.extend_from_slice(&data);
        }
        (out, set_id)
    }

    fn files() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (b"alpha.bin".to_vec(), (0..5000u32).map(|i| (i * 7) as u8).collect()),
            (b"beta.bin".to_vec(), (0..1000u32).map(|i| (i * 13) as u8).collect()),
            (b"sub/g\xE4mma.bin".to_vec(), (0..20_000u32).map(|i| (i ^ 0x55) as u8).collect()),
        ]
    }

    fn file_refs(f: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
        f.iter().map(|(n, d)| (n.as_slice(), d.as_slice())).collect()
    }

    #[test]
    fn file_id_ordering_matches_libpar2() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a[0] = 0xFF; // larger in byte 0 ...
        b[15] = 0x01; // ... but b is larger in byte 15, so b > a.
        assert!(FileId(a) < FileId(b));
        assert!(FileId(b) > FileId(a));
        a[15] = 0x01;
        assert!(FileId(a) > FileId(b));
        assert_eq!(FileId(a).cmp(&FileId(a)), std::cmp::Ordering::Equal);
        assert_eq!(FileId(a).partial_cmp(&FileId(b)), Some(std::cmp::Ordering::Greater));
        assert_eq!(format!("{}", FileId([0xAB; 16])), "ab".repeat(16));
        assert_eq!(format!("{:?}", SetId([1; 16])), format!("SetId({})", "01".repeat(16)));
        assert_eq!(format!("{}", SetId([0x0F; 16])), "0f".repeat(16));
    }

    #[test]
    fn header_roundtrip_and_validation() {
        let h = PacketHeader { length: 128, packet_md5: [1; 16], set_id: SetId([2; 16]), packet_type: TYPE_MAIN };
        let bytes = h.to_bytes();
        assert_eq!(PacketHeader::parse(&bytes), Some(h));
        assert_eq!(h.kind(), PacketType::Main);
        assert_eq!(h.body_len(), 64);
        assert!(h.fits(0, 128));
        assert!(!h.fits(1, 128));
        assert!(!h.fits(u64::MAX, 128));
        let mut bad = bytes;
        bad[0] = b'X';
        assert!(PacketHeader::parse(&bad).is_none());
        let mut bad = bytes;
        bad[8..16].copy_from_slice(&63u64.to_le_bytes());
        assert!(PacketHeader::parse(&bad).is_none());
        bad[8..16].copy_from_slice(&66u64.to_le_bytes());
        assert!(PacketHeader::parse(&bad).is_none());
        assert!(PacketHeader::parse(&bytes[..63]).is_none());
        assert_eq!(PacketType::from_bytes(b"NewsPostUsenet\0\0"), PacketType::Unknown);
        assert_eq!(PacketType::from_bytes(&TYPE_RECVSLIC), PacketType::RecoverySlice);
    }

    #[test]
    fn parse_complete_set_from_memory_and_file() {
        let f = files();
        let (bytes, set_id) = build_test_set(&file_refs(&f), 1024, &[0, 1, 5]);
        let set = load_par2_bytes(&bytes, ScanOptions::FULL).unwrap();
        assert_eq!(set.set_id, Some(set_id));
        let main = set.main.as_ref().unwrap();
        assert_eq!(main.slice_size, 1024);
        assert_eq!(main.recoverable_count, 3);
        assert_eq!(main.total_file_count(), 3);
        assert_eq!(set.file_descs.len(), 3);
        assert_eq!(set.ifscs.len(), 3);
        assert_eq!(set.recovery.len(), 3);
        assert_eq!(set.recovery_count(), 3);
        assert!(set.is_complete());
        assert_eq!(set.total_input_slices(), Some(5 + 1 + 20));
        assert_eq!(set.creator_string(), "par-rs test");
        assert_eq!(set.slice_size(), Some(1024));
        // Main packet ids are sorted ascending and match the BTreeMap order.
        let ids = set.file_ids_in_main_order();
        let keys: Vec<FileId> = set.file_descs.keys().copied().collect();
        assert_eq!(ids, keys);
        for fd in set.file_descs.values() {
            assert!(fd.id_consistent());
            assert_eq!(set.ifscs[&fd.file_id].slice_count() as u64, main.slice_count_for(fd.file_length));
        }
        let gamma = set.file_descs.values().find(|d| d.name.starts_with(b"sub/")).unwrap();
        assert_eq!(gamma.local_name(), "sub/gämma.bin");
        assert_eq!(gamma.name_lossy(), "sub/gämma.bin");
        for r in set.recovery.values() {
            assert!(r.md5_verified);
            assert_eq!(r.slice_size, 1024);
            assert!(r.verify(&bytes).unwrap());
            let mut buf = [0u8; 4];
            r.read_data(&bytes, 0, &mut buf).unwrap();
            assert_eq!(buf, [0, (r.exponent + 1) as u8, (2 * (r.exponent + 1)) as u8, (3 * (r.exponent + 1)) as u8]);
            assert!(r.read_data(&bytes, 1021, &mut buf).is_err());
            assert_eq!(r.header_length(), 1024 + 68);
        }
        assert_eq!(set.stats.added, 1 + 3 + 3 + 1 + 3);
        assert_eq!(set.stats.scan.resyncs, 0);

        // Same through a file.
        let dir = std::env::temp_dir().join(format!("par-rs-packet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("set.par2");
        std::fs::write(&p, &bytes).unwrap();
        let set2 = load_par2_file(&p, ScanOptions::METADATA).unwrap();
        assert_eq!(set2.file_descs, set.file_descs);
        assert_eq!(set2.ifscs, set.ifscs);
        assert_eq!(set2.recovery.len(), 3);
        assert!(set2.recovery.values().all(|r| !r.md5_verified));
        let fsrc = FileSource::open(&p).unwrap();
        assert_eq!(fsrc.source_len(), bytes.len() as u64);
        assert!(!fsrc.source_is_empty());
        let _ = fsrc.file();
        for r in set2.recovery.values() {
            assert!(r.verify(&fsrc).unwrap());
        }
        let mut b = [0u8; 8];
        read_exact_at(fsrc.file(), 0, &mut b).unwrap();
        assert_eq!(b, MAGIC);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resync_across_corruption_and_prefix() {
        let f = files();
        let (bytes, _) = build_test_set(&file_refs(&f), 512, &[3]);
        // Collect packet offsets to corrupt a middle packet.
        let raws: Vec<RawPacket> = PacketIter::new(&bytes[..], ScanOptions::UNVERIFIED).map(|r| r.unwrap()).collect();
        assert_eq!(raws.len(), 1 + 3 + 3 + 1 + 1);
        let mut data = vec![0u8; 4]; // stray 4-byte prefix (misaligned start)
        data.extend_from_slice(&bytes);
        // Zero-fill the second FileDesc packet (simulating a lost article).
        let victim = raws[2];
        let s = victim.offset as usize + 4;
        let e = s + victim.header.length as usize;
        data[s..e].fill(0);
        // Truncate garbage into the middle of the IFSC region: flip bytes in packet 5's body
        let v2 = raws[5];
        data[v2.offset as usize + 4 + 70] ^= 0xFF;
        let set = load_par2_bytes(&data, ScanOptions::FULL).unwrap();
        assert!(set.main.is_some());
        assert_eq!(set.file_descs.len(), 2);
        assert_eq!(set.ifscs.len(), 2);
        assert_eq!(set.recovery.len(), 1);
        assert!(set.stats.scan.resyncs >= 2);
        assert_eq!(set.stats.scan.md5_failures, 1);
        assert!(set.stats.scan.skipped_bytes >= victim.header.length);
        assert!(!set.is_complete());

        // Without resync the scan stops at the first problem (the prefix).
        let set = load_par2_bytes(&data, ScanOptions { resync: false, ..ScanOptions::FULL }).unwrap();
        assert!(set.main.is_none());

        // Truncated trailing packet is ignored, earlier packets survive.
        let cut = &bytes[..bytes.len() - 100];
        let set = load_par2_bytes(cut, ScanOptions::FULL).unwrap();
        assert!(set.main.is_some());
        assert_eq!(set.recovery.len(), 0);
    }

    #[test]
    fn resync_finds_magic_straddling_window_boundary() {
        let f = files();
        let (bytes, _) = build_test_set(&file_refs(&f), 512, &[]);
        let mut data = vec![0xAAu8; RESYNC_WINDOW - 3];
        data.extend_from_slice(&bytes);
        let set = load_par2_bytes(&data, ScanOptions::FULL).unwrap();
        assert!(set.main.is_some());
        assert_eq!(set.file_descs.len(), 3);
        assert_eq!(set.stats.scan.skipped_bytes, (RESYNC_WINDOW - 3) as u64);
    }

    #[test]
    fn foreign_sets_duplicates_and_wrong_sizes() {
        let f = files();
        let (a, sid_a) = build_test_set(&file_refs(&f), 1024, &[0]);
        let (b, sid_b) = build_test_set(&file_refs(&f[..1]), 2048, &[0, 1]);
        assert_ne!(sid_a, sid_b);
        let mut both = a.clone();
        both.extend_from_slice(&b);
        both.extend_from_slice(&a); // duplicates
        let set = load_par2_bytes(&both, ScanOptions::FULL).unwrap();
        assert_eq!(set.set_id, Some(sid_a));
        assert_eq!(set.file_descs.len(), 3);
        assert_eq!(set.recovery.len(), 1);
        assert_eq!(set.stats.foreign, 1 + 1 + 1 + 1 + 2);
        assert_eq!(set.stats.duplicates, 1 + 3 + 3 + 1 + 1);

        // Collection separates the sets.
        let mut coll = Par2Collection::new();
        coll.load_source(&both, 0, ScanOptions::FULL).unwrap();
        assert_eq!(coll.sets.len(), 2);
        assert_eq!(coll.sets[&sid_b].recovery.len(), 2);
        assert_eq!(coll.primary_set().unwrap().set_id, Some(sid_a));
        assert_eq!(coll.stats.duplicates, 9);

        // Recovery slice with the wrong payload size is dropped once Main is known,
        // whether it arrives before or after the Main packet.
        let wrong: Vec<u8> = (0..512).map(|i| i as u8).collect();
        let mut pre = Vec::new();
        pre.extend_from_slice(&encode_recovery_packet_prefix(&sid_a, 9, &wrong));
        pre.extend_from_slice(&wrong);
        pre.extend_from_slice(&a);
        pre.extend_from_slice(&encode_recovery_packet_prefix(&sid_a, 10, &wrong));
        pre.extend_from_slice(&wrong);
        let set = load_par2_bytes(&pre, ScanOptions::FULL).unwrap();
        assert_eq!(set.recovery.len(), 1);
        assert_eq!(set.stats.wrong_slice_size, 2);

        // Volume loaded separately and merged.
        let mut base = load_par2_bytes(&a, ScanOptions::FULL).unwrap();
        let (vol, _) = build_test_set(&file_refs(&f), 1024, &[7, 8]);
        let vol_set = load_par2_bytes(&vol, ScanOptions::FULL).unwrap();
        base.merge(vol_set);
        assert_eq!(base.recovery.len(), 3);
        let other = load_par2_bytes(&b, ScanOptions::FULL).unwrap();
        base.merge(other);
        assert_eq!(base.recovery.len(), 3);
        assert!(base.stats.foreign > 0);
    }

    #[test]
    fn payload_validation_errors() {
        let sid = SetId([0; 16]);
        assert_eq!(MainPacket::parse(sid, &[0; 11]), Err(PacketError::Truncated));
        assert_eq!(MainPacket::parse(sid, &[0; 13]), Err(PacketError::BadMainLayout));
        let mut body = encode_main_body(1002, &[], &[]);
        assert_eq!(MainPacket::parse(sid, &body), Err(PacketError::BadSliceSize(1002)));
        body[0..8].copy_from_slice(&(MAX_SLICE_SIZE + 4).to_le_bytes());
        assert_eq!(MainPacket::parse(sid, &body), Err(PacketError::BadSliceSize(MAX_SLICE_SIZE + 4)));
        body[0..8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(MainPacket::parse(sid, &body), Err(PacketError::BadSliceSize(0)));
        body[0..8].copy_from_slice(&1024u64.to_le_bytes());
        body[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(MainPacket::parse(sid, &body), Err(PacketError::BadRecoverableCount { count: 1, total: 0 }));
        body[8..12].copy_from_slice(&0u32.to_le_bytes());
        let m = MainPacket::parse(sid, &body).unwrap();
        assert_eq!(m.encode_body(), body);
        assert_eq!(m.slice_count_for(0), 0);
        assert_eq!(m.slice_count_for(1), 1);
        assert_eq!(m.slice_count_for(1024), 1);
        assert_eq!(m.slice_count_for(1025), 2);

        assert_eq!(FileDescPacket::parse(&[0; 55]), Err(PacketError::Truncated));
        let h = [7u8; 16];
        let id = compute_file_id(&h, 10, b"x");
        let body = encode_file_desc_body(&id, &h, &h, 10, b"");
        assert_eq!(FileDescPacket::parse(&body), Err(PacketError::BadFileName));
        let body = encode_file_desc_body(&id, &h, &[8u8; 16], 10, b"x");
        assert_eq!(FileDescPacket::parse(&body), Err(PacketError::InconsistentHashes));
        let body = encode_file_desc_body(&id, &h, &[8u8; 16], 16385, b"x");
        assert!(FileDescPacket::parse(&body).is_ok());
        let body = encode_file_desc_body(&id, &h, &h, 10, &vec![b'a'; MAX_FILENAME_LEN + 4]);
        assert_eq!(FileDescPacket::parse(&body), Err(PacketError::BadFileName));
        let body = encode_file_desc_body(&id, &h, &h, 10, b"x");
        let fd = FileDescPacket::parse(&body).unwrap();
        assert!(fd.id_consistent());
        assert_eq!(fd.encode_body(), body);
        let mut other = fd.clone();
        other.name = b"y".to_vec();
        assert!(!other.id_consistent());

        assert_eq!(IfscPacket::parse(&[0; 15]), Err(PacketError::Truncated));
        assert_eq!(IfscPacket::parse(&[0; 36 + 4]), Err(PacketError::BadIfscLayout));
        let p = IfscPacket::parse(&[0; 16]).unwrap();
        assert_eq!(p.slice_count(), 0);
        assert_eq!(p.encode_body(), vec![0; 16]);

        let c = CreatorPacket::parse(b"client\0\0");
        assert_eq!(c.client(), "client");
        assert_eq!(encode_creator_body(b""), vec![0; 4]);
        assert_eq!(encode_creator_body(b"abcde").len(), 8);

        for e in [
            PacketError::Truncated,
            PacketError::BadSliceSize(1),
            PacketError::BadMainLayout,
            PacketError::BadRecoverableCount { count: 1, total: 0 },
            PacketError::BadFileName,
            PacketError::InconsistentHashes,
            PacketError::BadIfscLayout,
            PacketError::EmptyRecoverySlice,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn invalid_payloads_are_counted_not_fatal() {
        let sid = SetId([3; 16]);
        let mut data = Vec::new();
        // Structurally valid packets with bad payloads.
        data.extend(encode_packet(&sid, &TYPE_MAIN, &[0; 12])); // slice size 0
        data.extend(encode_packet(&sid, &TYPE_IFSC, &[0; 12])); // truncated
        data.extend(encode_packet(&sid, &TYPE_RECVSLIC, &0u32.to_le_bytes())); // empty payload
        data.extend(encode_packet(&sid, b"NewsPostUsenet\0\0", &[1, 2, 3, 4]));
        data.extend(encode_packet(&sid, &TYPE_CREATOR, &encode_creator_body(b"c")));
        let set = load_par2_bytes(&data, ScanOptions::FULL).unwrap();
        assert_eq!(set.stats.invalid, 3);
        assert_eq!(set.stats.unknown, 1);
        assert_eq!(set.stats.added, 1);
        assert!(set.main.is_none());
        assert_eq!(set.set_id, Some(sid));
        assert_eq!(set.total_input_slices(), None);
        assert!(set.file_ids_in_main_order().is_empty());
        // Recovery ref errors.
        let raws: Vec<RawPacket> = PacketIter::new(&data[..], ScanOptions::FULL).map(|r| r.unwrap()).collect();
        assert_eq!(RecoverySliceRef::from_raw(&data[..], &raws[2], 0).unwrap(), Err(PacketError::EmptyRecoverySlice));
        let mut short = raws[2];
        short.header.length = 64;
        assert_eq!(RecoverySliceRef::from_raw(&data[..], &short, 0).unwrap(), Err(PacketError::Truncated));
        let p = parse_packet(&data[..], &raws[3], 0).unwrap().unwrap();
        assert!(matches!(p, Packet::Unknown { .. }));
        assert_eq!(p.set_id(&raws[3]), sid);
    }

    #[test]
    fn recovery_ref_verify_detects_corruption() {
        let f = files();
        let (mut bytes, _) = build_test_set(&file_refs(&f), 256, &[2]);
        let set = load_par2_bytes(&bytes, ScanOptions::METADATA).unwrap();
        let r = *set.recovery.values().next().unwrap();
        assert!(!r.md5_verified);
        assert!(r.verify(&bytes).unwrap());
        bytes[(r.data_offset + 100) as usize] ^= 1;
        assert!(!r.verify(&bytes).unwrap());
        // Damaged header → not verifiable.
        bytes[r.packet_offset as usize] = 0;
        assert!(!r.verify(&bytes).unwrap());
    }

    #[test]
    fn filename_translation() {
        assert_eq!(translate_filename_from_par2_to_local(b"plain.bin"), "plain.bin");
        assert_eq!(translate_filename_from_par2_to_local(b"dir\\sub\\f.bin"), "dir/sub/f.bin");
        assert_eq!(translate_filename_from_par2_to_local(b"/etc/passwd"), "%2Fetc/passwd");
        assert_eq!(translate_filename_from_par2_to_local(b"../../x"), "%2E%2E/%2E%2E/x");
        assert_eq!(translate_filename_from_par2_to_local(b"a/../b"), "a/%2E%2E/b");
        assert_eq!(translate_filename_from_par2_to_local(b"..\\x"), "%2E%2E/x");
        assert_eq!(translate_filename_from_par2_to_local(b"a..b/..c"), "a..b/..c");
        assert_eq!(translate_filename_from_par2_to_local(b"tab\there\x01"), "tab%09here%01");
        assert_eq!(translate_filename_from_par2_to_local(b"caf\xE9.txt"), "café.txt");
        assert_eq!(translate_filename_from_par2_to_local("café.txt".as_bytes()), "café.txt");
        assert_eq!(translate_filename_from_par2_to_local(b""), "");
        assert_eq!(translate_filename_from_par2_to_local(b"\\"), "%2F");
        assert_eq!(bytes_to_string_latin1_fallback(b"\xFF\xFE"), "ÿþ");
    }

    #[test]
    fn source_bounds_errors() {
        let v = vec![1u8, 2, 3];
        let mut buf = [0u8; 2];
        assert!(v.read_at(2, &mut buf).is_err());
        assert!(v.read_at(u64::MAX, &mut buf).is_err());
        v.read_at(1, &mut buf).unwrap();
        assert_eq!(buf, [2, 3]);
        assert_eq!(PacketSource::source_len(&v), 3);
        let r: &[u8] = &v;
        assert!(!r.source_is_empty());
        let empty: &[u8] = &[];
        let mut it = PacketIter::new(empty, ScanOptions::FULL);
        assert!(it.next().is_none());
        assert_eq!(it.position(), 0);
        assert_eq!(it.stats(), ScanStats::default());
    }

    #[test]
    fn hex_helper() {
        assert_eq!(hex(&[0x00, 0xAB, 0xFF]), "00abff");
        assert_eq!(hex(&[]), "");
    }
}
