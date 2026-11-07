//! The repairer: load a recovery set, verify the source files, locate every usable block
//! on disk, and reconstruct what is missing.
//!
//! Replaces `libpar2`'s `Par2Repairer` as used by nzbget's `ParChecker`:
//!
//! * **Loading** reads metadata packets only; recovery slice payloads are indexed by offset
//!   and their MD5 is verified lazily, just before the slices that will actually be used are
//!   streamed into the Reed-Solomon engine.
//! * **Verification** per source file tries, in order: the host-supplied download status
//!   (whole-file CRC or per-article CRCs → zero/minimal disk I/O), then a full scan with the
//!   sliding-window block scanner, which also detects complete-but-misnamed files and blocks
//!   belonging to other files of the set.
//! * **Extra files** (renamed downloads, split fragments `.001`, duplicates from other NZBs)
//!   can be scanned at any time to pick up more blocks.
//! * **Repair** copies the located blocks of damaged/missing files into fresh target files and
//!   streams present blocks plus recovery slices through the engine to reconstruct the rest.
//!   Damaged originals are rotated according to [`BackupPolicy`]; repaired files are
//!   re-hashed unless disabled.
//!
//! Source files are kept in Main-packet order (ascending file id), which is also the order of
//! `libpar2`'s `sourcefilemap`, so hosts iterating the files see the same sequence.

use crate::damage::{self, DownloadStatus, QuickVerdict, Segment};
use crate::gf16::input_constant_logs;
use crate::gf16::simd::Kernel;
use crate::packet::{read_exact_at, FileId, PacketSet, RecoverySliceRef, ScanOptions, SetId};
use crate::reed_solomon::{plan_recovery, Engine, EngineConfig, InputKind, InputReader, InputSpec, OutputSink, RsError};
use crate::parhash::{file_hashes_parallel, hash_ranges_parallel, slice_ranges, HashRange};
use crate::scanner::{entries_for_file, scan_file, BlockRef, ChecksumEntry, ChecksumIndex, ScanConfig, ScanReport};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// What to do with a damaged target file before the repaired version is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupPolicy {
    /// Rename to `<name>.1` (`.2`, ... if taken), as `libpar2` does.
    RenameNumbered,
    /// Rename to `<name>.bak` (`.bak.1`, ... if taken).
    RenameBak,
    /// Rename as with `RenameNumbered`, then delete the backup once the repaired file verified.
    DeleteAfterRepair,
}

/// Repair options.
#[derive(Clone, Debug)]
pub struct RepairOptions {
    /// Worker threads for the Reed-Solomon engine (0 = all cores).
    pub num_threads: usize,
    /// Memory budget for engine buffers (minimum 16 MiB).
    pub mem_limit_bytes: u64,
    /// Handling of damaged originals.
    pub backup: BackupPolicy,
    /// Re-hash repaired files and fail if they do not match.
    pub verify_repaired: bool,
    /// `fsync` repaired files before returning (off by default; the OS flushes them anyway).
    pub sync_repaired: bool,
    /// Rename complete files found under wrong names to their target names during repair.
    pub rename_misnamed: bool,
    /// Scanner buffer size.
    pub scan_buffer: usize,
    /// Extensions (with the dot, case-insensitive, e.g. `.sfv`, `.nfo`, `.nzb`) of files whose
    /// damage or absence must not trigger a repair (nzbget's `ParIgnoreExt`). They are still
    /// repaired when a repair runs for other reasons.
    pub ignore_extensions: Vec<String>,
    /// Also require the whole-file MD5 (and 16k MD5) to match before calling a file complete.
    /// Off by default: a file whose every slice matches its IFSC CRC-32 + MD5 at the expected
    /// offset and whose length matches is complete; the serial whole-file MD5 only repeats that
    /// verdict at one core's speed. Files without IFSC checksums are always hashed in full.
    pub full_file_md5: bool,
    /// SIMD kernel.
    pub kernel: Kernel,
}

impl Default for RepairOptions {
    fn default() -> Self {
        Self {
            num_threads: 0,
            mem_limit_bytes: 256 << 20,
            backup: BackupPolicy::RenameNumbered,
            verify_repaired: true,
            sync_repaired: false,
            rename_misnamed: true,
            scan_buffer: 8 << 20,
            full_file_md5: false,
            ignore_extensions: Vec::new(),
            kernel: Kernel::detect(),
        }
    }
}

/// Verification status of a source file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileStatus {
    /// Not verified yet.
    Unknown,
    /// Target does not exist and no complete copy was found.
    Missing,
    /// Target exists and matches.
    Complete,
    /// Target exists but some blocks are bad or missing.
    Damaged,
    /// A complete copy exists under another name (`complete_file`).
    Misnamed,
}

/// Per-file state exposed to hosts.
#[derive(Clone, Debug)]
pub struct SourceFileState {
    /// PAR2 file id.
    pub file_id: FileId,
    /// Sanitised local name (relative to the base directory).
    pub target_filename: String,
    /// Raw PAR2 name bytes.
    pub raw_name: Vec<u8>,
    /// Expected length.
    pub file_length: u64,
    /// Expected MD5.
    pub hash_full: [u8; 16],
    /// Expected 16k MD5.
    pub hash_16k: [u8; 16],
    /// Number of slices.
    pub block_count: u32,
    /// Global index of the first slice.
    pub first_block: usize,
    /// Slices located so far.
    pub available_blocks: u32,
    /// Whether the target path exists.
    pub target_exists: bool,
    /// Absolute target path.
    pub target_path: PathBuf,
    /// Path of a complete copy (the target itself when `Complete`).
    pub complete_file: Option<PathBuf>,
    /// Status.
    pub status: FileStatus,
    /// Verified without a full scan (download CRCs).
    pub quick_verified: bool,
    /// Whether an IFSC packet exists (without it only the whole-file hash can be checked).
    pub verifiable: bool,
    /// Matches `RepairOptions::ignore_extensions`: its damage does not count as repair-worthy.
    pub ignored: bool,
}

impl SourceFileState {
    /// Slices still missing.
    pub fn missing_blocks(&self) -> u32 {
        self.block_count - self.available_blocks
    }
}

/// Where a located block can be read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockLocation {
    /// Index into [`Par2Repairer::disk_files`].
    pub file: usize,
    /// Byte offset of the block within that file (data may be shorter than a slice at EOF).
    pub offset: u64,
}

/// Download information a host can provide to avoid reading intact files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuickInfo {
    /// Every article arrived; CRC of the whole file.
    Success {
        /// Whole-file CRC-32.
        crc: u32,
    },
    /// Some articles failed.
    Partial {
        /// Sorted, non-overlapping segments.
        segments: Vec<Segment>,
    },
    /// Nothing arrived.
    Failure,
}

/// Supplies [`QuickInfo`] per target file name.
pub trait QuickVerifier {
    /// Download status of the file with the given local name, if known.
    fn quick_info(&mut self, target_filename: &str) -> Option<QuickInfo>;
}

impl<F: FnMut(&str) -> Option<QuickInfo>> QuickVerifier for F {
    fn quick_info(&mut self, target_filename: &str) -> Option<QuickInfo> {
        self(target_filename)
    }
}

/// Stages reported to the observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Loading par2 files.
    Loading,
    /// Verifying source files.
    Verifying,
    /// Scanning extra files.
    ScanningExtra,
    /// Reconstructing data.
    Repairing,
    /// Re-verifying repaired files.
    VerifyingRepaired,
}

/// Message severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// Detail.
    Detail,
    /// Info.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

/// Progress/event sink.
pub trait RepairObserver {
    /// Stage changed.
    fn stage(&mut self, _stage: Stage) {}
    /// Progress within the stage, in permille (0..=1000) of the stage plus a label.
    fn progress(&mut self, _permille: u32, _label: &str) {}
    /// A file finished verification.
    fn file_verified(&mut self, _file: &SourceFileState) {}
    /// Diagnostic message.
    fn message(&mut self, _level: Level, _text: &str) {}
}

/// Observer that ignores everything.
pub struct NullObserver;
impl RepairObserver for NullObserver {}

/// Repair errors.
#[derive(Debug)]
pub enum RepairError {
    /// No Main packet loaded.
    NoMainPacket,
    /// Main packet present but file descriptions are missing for some files.
    IncompleteMetadata {
        /// Ids without a description.
        missing_descriptions: Vec<FileId>,
    },
    /// `finalize` has not been called.
    NotFinalized,
    /// A par2 file belongs to another set.
    WrongSet {
        /// Expected set.
        expected: SetId,
        /// Found set.
        found: SetId,
    },
    /// Fewer recovery blocks than missing blocks.
    NotEnoughRecovery {
        /// Blocks missing.
        needed: u64,
        /// Recovery blocks available.
        available: u64,
    },
    /// Recovery matrix singular even after trying all recovery slices.
    Singular,
    /// Repaired files failed verification.
    VerificationFailed {
        /// Local names of the files that did not verify.
        files: Vec<String>,
    },
    /// I/O error with context.
    Io {
        /// What was being done.
        context: String,
        /// Underlying error.
        source: io::Error,
    },
    /// Cancelled.
    Cancelled,
    /// A file id that is not part of the recovery set.
    UnknownFile(FileId),
}

impl fmt::Display for RepairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepairError::NoMainPacket => f.write_str("no main packet found in the loaded par2 files"),
            RepairError::IncompleteMetadata { missing_descriptions } => {
                write!(f, "file descriptions missing for {} file(s)", missing_descriptions.len())
            }
            RepairError::NotFinalized => f.write_str("repairer not finalized"),
            RepairError::WrongSet { expected, found } => write!(f, "par2 file belongs to set {found}, expected {expected}"),
            RepairError::NotEnoughRecovery { needed, available } => {
                write!(f, "not enough recovery blocks: {needed} needed, {available} available")
            }
            RepairError::Singular => f.write_str("recovery matrix is singular"),
            RepairError::VerificationFailed { files } => write!(f, "repaired files failed verification: {}", files.join(", ")),
            RepairError::Io { context, source } => write!(f, "{context}: {source}"),
            RepairError::Cancelled => f.write_str("cancelled"),
            RepairError::UnknownFile(id) => write!(f, "file {id} is not part of the recovery set"),
        }
    }
}

impl std::error::Error for RepairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RepairError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Map a parallel-hashing error (cancellation is reported as `Interrupted`).
fn hash_err(e: io::Error) -> RepairError {
    if e.kind() == io::ErrorKind::Interrupted {
        RepairError::Cancelled
    } else {
        io_ctx("hashing")(e)
    }
}

pub(crate) fn io_ctx(context: impl Into<String>) -> impl FnOnce(io::Error) -> RepairError {
    move |source| RepairError::Io { context: context.into(), source }
}

/// Outcome of [`Par2Repairer::verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyResult {
    /// Every target file is complete.
    pub all_complete: bool,
    /// Blocks missing across all files.
    pub missing_blocks: u64,
    /// Recovery blocks available.
    pub recovery_blocks: u64,
    /// Some file needs rebuilding (missing blocks, misnamed, or relocated blocks).
    pub repair_needed: bool,
    /// Reconstruction is possible with the loaded recovery blocks.
    pub repair_possible: bool,
    /// Files quick-verified.
    pub quick_verified_files: usize,
    /// Incomplete files that match `RepairOptions::ignore_extensions` (not counted in
    /// `repair_needed`).
    pub ignored_damaged: Vec<String>,
}

impl VerifyResult {
    /// Recovery blocks still needed (0 if repair is possible).
    pub fn blocks_needed(&self) -> u64 {
        self.missing_blocks.saturating_sub(self.recovery_blocks)
    }
}

/// Outcome of [`Par2Repairer::repair`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepairResult {
    /// Nothing needed repair.
    NotNeeded,
    /// Repaired.
    Repaired {
        /// Files rebuilt or renamed.
        files: Vec<String>,
        /// Blocks reconstructed via Reed-Solomon.
        blocks_recovered: u64,
        /// Backups of damaged originals and split fragments that supplied blocks: nzbget's
        /// `DeleteLeftovers` set. Already deleted under `BackupPolicy::DeleteAfterRepair`.
        leftovers: Vec<PathBuf>,
    },
}

/// The repairer.
pub struct Par2Repairer {
    pub(crate) options: RepairOptions,
    pub(crate) base_dir: PathBuf,
    pub(crate) packets: PacketSet,
    /// Par2 files, indexed by `RecoverySliceRef::source_id`.
    pub(crate) par_files: Vec<PathBuf>,
    pub(crate) files: Vec<SourceFileState>,
    pub(crate) file_by_id: HashMap<FileId, usize>,
    /// Checksums per file in `files` order (`None` without IFSC).
    pub(crate) checksums: Vec<Option<Vec<ChecksumEntry>>>,
    /// Global block → location.
    pub(crate) locations: Vec<Option<BlockLocation>>,
    /// Files blocks can be read from.
    pub(crate) disk_files: Vec<PathBuf>,
    pub(crate) disk_index: HashMap<PathBuf, usize>,
    pub(crate) index: Option<ChecksumIndex>,
    pub(crate) finalized: bool,
    pub(crate) verified: bool,
    pub(crate) scanned_extra: HashSet<PathBuf>,
    /// Block CRCs that occur more than once across the set (quick verification is unsafe for them).
    pub(crate) duplicate_crcs: HashSet<u32>,
    /// Split fragments scanned via `add_split_fragments` (deleted after a successful repair under
    /// `BackupPolicy::DeleteAfterRepair`, like nzbget's `DeleteLeftovers`).
    pub(crate) split_fragments: Vec<PathBuf>,
    pub(crate) cancel: Arc<AtomicBool>,
    pub(crate) quick_verified_files: usize,
    /// Streaming (incremental syndrome) state, see [`crate::streaming`].
    pub(crate) streaming: Option<crate::streaming::SyndromeState>,
}

impl Par2Repairer {
    /// New repairer; target files are resolved relative to `base_dir`.
    pub fn new(base_dir: impl Into<PathBuf>, options: RepairOptions) -> Self {
        Self {
            options,
            base_dir: base_dir.into(),
            packets: PacketSet::new(),
            par_files: Vec::new(),
            files: Vec::new(),
            file_by_id: HashMap::new(),
            checksums: Vec::new(),
            locations: Vec::new(),
            disk_files: Vec::new(),
            disk_index: HashMap::new(),
            index: None,
            finalized: false,
            verified: false,
            scanned_extra: HashSet::new(),
            duplicate_crcs: HashSet::new(),
            split_fragments: Vec::new(),
            cancel: Arc::new(AtomicBool::new(false)),
            quick_verified_files: 0,
            streaming: None,
        }
    }

    /// Cancellation flag shared with long operations.
    pub fn cancel_token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Options.
    pub fn options(&self) -> &RepairOptions {
        &self.options
    }

    /// Base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Loaded packets.
    pub fn packets(&self) -> &PacketSet {
        &self.packets
    }

    /// Set id, once known.
    pub fn set_id(&self) -> Option<SetId> {
        self.packets.set_id
    }

    /// Slice size.
    pub fn block_size(&self) -> u64 {
        self.packets.slice_size().unwrap_or(0)
    }

    /// Creator string or `""`.
    pub fn creator(&self) -> String {
        self.packets.creator_string()
    }

    /// Source files in Main-packet (`libpar2`) order.
    pub fn source_files(&self) -> &[SourceFileState] {
        &self.files
    }

    /// Files blocks may be read from (targets, backups, extra files).
    pub fn disk_files(&self) -> &[PathBuf] {
        &self.disk_files
    }

    /// Location of every global input block.
    pub fn block_locations(&self) -> &[Option<BlockLocation>] {
        &self.locations
    }

    /// Recovery slices loaded.
    pub fn recovery_blocks(&self) -> u64 {
        self.packets.recovery.len() as u64
    }

    /// Total input blocks.
    pub fn total_blocks(&self) -> u64 {
        self.locations.len() as u64
    }

    /// Blocks located.
    pub fn available_blocks(&self) -> u64 {
        self.locations.iter().filter(|l| l.is_some()).count() as u64
    }

    /// Blocks missing.
    pub fn missing_blocks(&self) -> u64 {
        self.total_blocks() - self.available_blocks()
    }

    /// Recovery blocks still needed for a repair (0 if enough are loaded).
    pub fn blocks_needed(&self) -> u64 {
        self.missing_blocks().saturating_sub(self.recovery_blocks())
    }

    /// Whether the Reed-Solomon step is currently possible.
    pub fn repair_possible(&self) -> bool {
        self.finalized && self.missing_blocks() <= self.recovery_blocks()
    }

    // -----------------------------------------------------------------------------------------
    // Loading
    // -----------------------------------------------------------------------------------------

    /// Load one par2 file (index or volume). Metadata is verified; recovery payloads are only
    /// indexed. Returns the number of recovery slices added.
    pub fn load_par2_file(&mut self, path: &Path) -> Result<usize, RepairError> {
        let before = self.packets.recovery.len();
        let source_id = self.par_files.len();
        let stats = self.packets.load_file(path, source_id, ScanOptions::METADATA).map_err(io_ctx(format!("loading {}", path.display())))?;
        self.par_files.push(path.to_path_buf());
        if stats.foreign > 0 && stats.added == 0 {
            // Entire file belongs to another set.
            if let Some(expected) = self.packets.set_id {
                let mut other = PacketSet::new();
                let _ = other.load_file(path, 0, ScanOptions::UNVERIFIED);
                if let Some(found) = other.set_id {
                    return Err(RepairError::WrongSet { expected, found });
                }
            }
        }
        if self.finalized {
            // New recovery slices may have arrived; nothing else changes.
            let ss = self.block_size();
            self.packets.recovery.retain(|_, r| r.slice_size == ss);
        }
        Ok(self.packets.recovery.len() - before)
    }

    /// Load `main_path` and every other file of the same collection in its directory
    /// (`name.par2`, `name.volXX+YY.par2`). Returns the files loaded.
    pub fn load_par2_set(&mut self, main_path: &Path) -> Result<Vec<PathBuf>, RepairError> {
        let mut loaded = vec![main_path.to_path_buf()];
        self.load_par2_file(main_path)?;
        let dir = main_path.parent().filter(|p| !p.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
        let main_name = main_path.file_name().map(crate::filenames::os_str_bytes).unwrap_or_default();
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(io_ctx(format!("reading {}", dir.display())))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for p in entries {
            if p.file_name() == main_path.file_name() || p.is_dir() {
                continue;
            }
            let name = p.file_name().map(crate::filenames::os_str_bytes).unwrap_or_default();
            if crate::filenames::same_par_collection(&name, &main_name, true) {
                match self.load_par2_file(&p) {
                    Ok(_) => loaded.push(p),
                    Err(RepairError::WrongSet { .. }) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(loaded)
    }

    /// Load in-memory par2 data (e.g. a volume kept in RAM). `label` names the source.
    pub fn load_par2_bytes(&mut self, data: Vec<u8>, label: &str) -> Result<usize, RepairError> {
        // Materialise to a temporary file so recovery payloads can be streamed later.
        let tmp = std::env::temp_dir().join(format!("par-rs-{}-{}.par2", std::process::id(), self.par_files.len()));
        std::fs::write(&tmp, &data).map_err(io_ctx(format!("writing temporary copy of {label}")))?;
        self.load_par2_file(&tmp)
    }

    /// Build the file and block tables. Must be called after loading and before verifying.
    pub fn finalize(&mut self) -> Result<(), RepairError> {
        let main = self.packets.main.clone().ok_or(RepairError::NoMainPacket)?;
        let missing: Vec<FileId> = main.recoverable_file_ids.iter().filter(|id| !self.packets.file_descs.contains_key(id)).copied().collect();
        if !missing.is_empty() {
            return Err(RepairError::IncompleteMetadata { missing_descriptions: missing });
        }
        let ss = main.slice_size;
        self.files.clear();
        self.file_by_id.clear();
        self.checksums.clear();
        self.locations.clear();
        self.disk_files.clear();
        self.disk_index.clear();
        let mut entries: Vec<ChecksumEntry> = Vec::new();
        let mut first_block = 0usize;
        for id in &main.recoverable_file_ids {
            let fd = &self.packets.file_descs[id];
            let block_count = main.slice_count_for(fd.file_length) as u32;
            let local = fd.local_name();
            let target_path = self.base_dir.join(&local);
            let fi = self.files.len();
            let ifsc = self.packets.ifscs.get(id);
            let verifiable = match ifsc {
                Some(p) if p.slices.len() == block_count as usize => true,
                _ => block_count == 0,
            };
            let cs = if verifiable && block_count > 0 {
                let es = entries_for_file(fi as u32, &ifsc.unwrap().slices);
                entries.extend_from_slice(&es);
                Some(es)
            } else {
                None
            };
            self.checksums.push(cs);
            let ignored = self.options.ignore_extensions.iter().any(|e| local.len() >= e.len() && local.get(local.len() - e.len()..).is_some_and(|t| t.eq_ignore_ascii_case(e)));
            self.files.push(SourceFileState {
                file_id: *id,
                target_filename: local,
                raw_name: fd.name.clone(),
                file_length: fd.file_length,
                hash_full: fd.hash_full,
                hash_16k: fd.hash_16k,
                block_count,
                first_block,
                available_blocks: 0,
                target_exists: target_path.exists(),
                target_path,
                complete_file: None,
                status: FileStatus::Unknown,
                quick_verified: false,
                verifiable,
                ignored,
            });
            self.file_by_id.insert(*id, fi);
            first_block += block_count as usize;
        }
        self.locations = vec![None; first_block];
        // CRCs shared by several blocks of the set.
        {
            let mut seen: HashSet<u32> = HashSet::new();
            self.duplicate_crcs.clear();
            for e in self.checksums.iter().flatten().flatten() {
                if !seen.insert(e.crc32) {
                    self.duplicate_crcs.insert(e.crc32);
                }
            }
        }
        self.index = Some(ChecksumIndex::new(ss, entries));
        self.packets.recovery.retain(|_, r| r.slice_size == ss);
        self.finalized = true;
        self.verified = false;
        self.streaming = None;
        Ok(())
    }

    pub(crate) fn disk_file_index_pub(&mut self, path: &Path) -> usize {
        self.disk_file_index(path)
    }

    pub(crate) fn set_location_pub(&mut self, block: BlockRef, loc: BlockLocation) -> bool {
        self.set_location(block, loc)
    }

    /// Choose recovery slices for the missing blocks, verifying the MD5 of every slice that
    /// will be used (lazily) and dropping corrupt ones. `allowed` restricts the candidate
    /// exponents (streaming mode tracks syndromes only for some of them).
    pub(crate) fn plan_with_verified_recovery(
        &mut self,
        logs: &[u16],
        present: &[bool],
        allowed: Option<&[u32]>,
        observer: &mut dyn RepairObserver,
    ) -> Result<(crate::reed_solomon::RecoveryPlan, BTreeMap<u32, RecoverySliceRef>), RepairError> {
        let mut usable: BTreeMap<u32, RecoverySliceRef> = self.packets.recovery.clone();
        if let Some(a) = allowed {
            usable.retain(|e, _| a.contains(e));
        }
        let mut verified_ok: HashSet<u32> = HashSet::new();
        loop {
            let exps: Vec<u32> = usable.keys().copied().collect();
            let plan = match plan_recovery(logs, present, &exps, &self.options.kernel) {
                Ok(p) => p,
                Err(RsError::NotEnoughRecovery { needed, available }) => {
                    return Err(RepairError::NotEnoughRecovery { needed: needed as u64, available: available as u64 })
                }
                Err(RsError::Singular) => return Err(RepairError::Singular),
                Err(RsError::Io(e)) => return Err(RepairError::Io { context: "planning recovery".into(), source: e }),
                Err(_) => return Err(RepairError::Singular),
            };
            let mut bad = Vec::new();
            let mut pending: Vec<u32> = Vec::new();
            for &e in &plan.used_exponents {
                if verified_ok.contains(&e) {
                    continue;
                }
                if usable[&e].md5_verified {
                    verified_ok.insert(e);
                } else {
                    pending.push(e);
                }
            }
            if !pending.is_empty() {
                let refs: Vec<RecoverySliceRef> = pending.iter().map(|e| usable[e]).collect();
                let ok = self.verify_recovery_parallel(&refs)?;
                for (&e, ok) in pending.iter().zip(ok) {
                    if ok {
                        verified_ok.insert(e);
                    } else {
                        observer.message(Level::Warning, &format!("Recovery block {e} in {} is corrupt, ignoring", self.par_files[usable[&e].source_id].display()));
                        bad.push(e);
                    }
                }
            }
            if bad.is_empty() {
                return Ok((plan, usable));
            }
            for e in bad {
                usable.remove(&e);
                self.packets.recovery.remove(&e);
            }
        }
    }

    /// Verify the packet MD5 of several recovery slices (all cores). A packet whose header no
    /// longer parses or fits its file counts as corrupt.
    fn verify_recovery_parallel(&self, refs: &[RecoverySliceRef]) -> Result<Vec<bool>, RepairError> {
        use crate::packet::{PacketHeader, HEADER_LEN};
        let paths: Vec<&Path> = self.par_files.iter().map(|p| p.as_path()).collect();
        let mut ranges: Vec<HashRange> = Vec::new();
        let mut expected: Vec<Option<[u8; 16]>> = Vec::with_capacity(refs.len());
        let mut lens: HashMap<usize, u64> = HashMap::new();
        for r in refs {
            let path = paths[r.source_id];
            let file = File::open(path).map_err(io_ctx(format!("opening {}", path.display())))?;
            let flen = match lens.get(&r.source_id) {
                Some(&l) => l,
                None => {
                    let l = file.metadata().map(|m| m.len()).map_err(io_ctx(format!("reading {}", path.display())))?;
                    lens.insert(r.source_id, l);
                    l
                }
            };
            let mut hdr = [0u8; HEADER_LEN];
            let parsed = match read_exact_at(&file, r.packet_offset, &mut hdr) {
                Ok(()) => PacketHeader::parse(&hdr).filter(|h| h.length == r.header_length() && h.fits(r.packet_offset, flen)),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => None,
                Err(e) => return Err(io_ctx(format!("reading {}", path.display()))(e)),
            };
            match parsed {
                Some(h) => {
                    let body = h.length - 32;
                    ranges.push(HashRange { file: r.source_id, offset: r.packet_offset + 32, len: body, pad_to: body });
                    expected.push(Some(h.packet_md5));
                }
                None => expected.push(None),
            }
        }
        let digests = hash_ranges_parallel(&paths, &ranges, self.options.num_threads, Some(&self.cancel), &mut |_| {}).map_err(hash_err)?;
        let mut d = digests.iter();
        Ok(expected.iter().map(|e| e.is_some_and(|md5| d.next().is_some_and(|(_, got)| *got == md5))).collect())
    }

    fn disk_file_index(&mut self, path: &Path) -> usize {
        if let Some(&i) = self.disk_index.get(path) {
            return i;
        }
        let i = self.disk_files.len();
        self.disk_files.push(path.to_path_buf());
        self.disk_index.insert(path.to_path_buf(), i);
        i
    }

    fn set_location(&mut self, block: BlockRef, loc: BlockLocation) -> bool {
        let fi = block.file_index as usize;
        let g = self.files[fi].first_block + block.block_index as usize;
        if self.locations[g].is_some() {
            return false;
        }
        self.locations[g] = Some(loc);
        self.files[fi].available_blocks += 1;
        true
    }

    // -----------------------------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------------------------

    /// Verify all source files. `quick` may supply download status to skip reading intact
    /// files. Safe to call again after loading more par2 files or extra files.
    ///
    /// Three phases: zero-read checks (existence, empty files, streaming probes, the quick
    /// verifier), then one slice-level pass over every remaining file on all cores (multi-lane
    /// MD5 + hardware CRC), then the sliding scan of the files that pass is not enough for,
    /// in parallel across files, reusing the slices the second phase already verified.
    pub fn verify(&mut self, mut quick: Option<&mut dyn QuickVerifier>, observer: &mut dyn RepairObserver) -> Result<VerifyResult, RepairError> {
        if !self.finalized {
            return Err(RepairError::NotFinalized);
        }
        observer.stage(Stage::Verifying);
        let ss = self.block_size();
        let total_files = self.files.len().max(1);
        // ---- phase 1: zero-read checks ----
        let mut pending: Vec<usize> = Vec::new();
        for fi in 0..self.files.len() {
            if self.cancelled() {
                return Err(RepairError::Cancelled);
            }
            if matches!(self.files[fi].status, FileStatus::Complete) {
                continue;
            }
            observer.progress((fi * 1000 / total_files) as u32, &format!("Verifying {}", self.files[fi].target_filename));
            let path = self.files[fi].target_path.clone();
            let exists = path.is_file();
            self.files[fi].target_exists = exists;
            if !exists {
                if self.files[fi].status == FileStatus::Unknown {
                    self.files[fi].status = if self.files[fi].complete_file.is_some() { FileStatus::Misnamed } else { FileStatus::Missing };
                }
                observer.file_verified(&self.files[fi]);
                continue;
            }
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            // Empty expected file.
            if self.files[fi].block_count == 0 {
                let ok = size == 0 || crate::hasher::hash_file(&path).map(|h| h.md5_full == self.files[fi].hash_full).unwrap_or(false);
                self.files[fi].status = if ok { FileStatus::Complete } else { FileStatus::Damaged };
                if ok {
                    self.files[fi].complete_file = Some(path.clone());
                }
                observer.file_verified(&self.files[fi]);
                continue;
            }
            // Streaming mode: the downloader wrote articles in place; probe the unverified
            // blocks at their natural offsets instead of scanning the whole file.
            let mut handled = false;
            if self.streaming.is_some() {
                self.streaming_probe_remaining(fi)?;
                handled = true;
            }
            // Quick path (skipped when one of the file's block CRCs is not unique in the set:
            // a CRC-only verdict could then be fooled by another file's block, as in nzbget).
            let has_dup_crc = self.checksums[fi].as_ref().is_some_and(|cs| cs.iter().any(|e| self.duplicate_crcs.contains(&e.crc32)));
            if let (false, false, Some(q), Some(cs)) = (handled, has_dup_crc, quick.as_deref_mut(), self.checksums[fi].as_ref())
                && let Some(info) = q.quick_info(&self.files[fi].target_filename) {
                    let crcs: Vec<u32> = cs.iter().map(|e| e.crc32).collect();
                    let verdict = match &info {
                        QuickInfo::Success { crc } => {
                            damage::quick_verify(&DownloadStatus::Success { crc: *crc }, size, &crcs, ss, &mut damage::NoDiskAccess)
                        }
                        QuickInfo::Partial { segments } => {
                            let mut f = File::open(&path).map_err(io_ctx(format!("opening {}", path.display())))?;
                            damage::quick_verify(&DownloadStatus::Partial { segments }, size, &crcs, ss, &mut f)
                        }
                        QuickInfo::Failure => Ok(QuickVerdict::Partial(vec![false; crcs.len()])),
                    }
                    .map_err(io_ctx(format!("quick-verifying {}", path.display())))?;
                    match verdict {
                        QuickVerdict::Complete if size == self.files[fi].file_length => {
                            let di = self.disk_file_index(&path);
                            for b in 0..self.files[fi].block_count {
                                self.set_location(BlockRef { file_index: fi as u32, block_index: b }, BlockLocation { file: di, offset: b as u64 * ss });
                            }
                            self.files[fi].status = FileStatus::Complete;
                            self.files[fi].complete_file = Some(path.clone());
                            self.files[fi].quick_verified = true;
                            self.quick_verified_files += 1;
                            observer.message(Level::Detail, &format!("Quickly verified good file {}", self.files[fi].target_filename));
                            handled = true;
                        }
                        QuickVerdict::Partial(valid) if size <= self.files[fi].file_length => {
                            let di = self.disk_file_index(&path);
                            for (b, ok) in valid.iter().enumerate() {
                                if *ok {
                                    self.set_location(BlockRef { file_index: fi as u32, block_index: b as u32 }, BlockLocation { file: di, offset: b as u64 * ss });
                                }
                            }
                            self.files[fi].status = FileStatus::Damaged;
                            self.files[fi].quick_verified = true;
                            self.quick_verified_files += 1;
                            observer.message(Level::Detail, &format!("Quickly verified damaged file {}", self.files[fi].target_filename));
                            handled = true;
                        }
                        _ => {
                            observer.message(
                                Level::Warning,
                                &format!("Quick verification failed for file {}, performing full verification instead", self.files[fi].target_filename),
                            );
                        }
                    }
                }
            if handled {
                observer.file_verified(&self.files[fi]);
            } else {
                pending.push(fi);
            }
        }

        // ---- phase 2: slice-level check of every pending file on all cores ----
        let mut need_scan: Vec<(usize, Option<Vec<bool>>)> = Vec::new();
        let with_cs: Vec<usize> = pending.iter().copied().filter(|&fi| self.checksums[fi].is_some()).collect();
        need_scan.extend(pending.iter().copied().filter(|&fi| self.checksums[fi].is_none()).map(|fi| (fi, None)));
        if !with_cs.is_empty() {
            let paths: Vec<&Path> = with_cs.iter().map(|&fi| self.files[fi].target_path.as_path()).collect();
            let mut ranges: Vec<HashRange> = Vec::new();
            let mut sizes: Vec<u64> = Vec::with_capacity(with_cs.len());
            for (k, &fi) in with_cs.iter().enumerate() {
                let size = std::fs::metadata(paths[k]).map(|m| m.len()).unwrap_or(0);
                sizes.push(size);
                ranges.extend(slice_ranges(k, size, ss, self.files[fi].block_count as u64));
            }
            let total_bytes = sizes.iter().sum::<u64>().max(1);
            let results = hash_ranges_parallel(&paths, &ranges, self.options.num_threads, Some(&self.cancel), &mut |done| {
                observer.progress((done * 1000 / total_bytes).min(1000) as u32, "Verifying slices");
            })
            .map_err(hash_err)?;
            let full = if self.options.full_file_md5 {
                Some(file_hashes_parallel(&paths, self.options.num_threads, Some(&self.cancel)).map_err(hash_err)?)
            } else {
                None
            };
            let mut cursor = 0usize;
            for (k, &fi) in with_cs.iter().enumerate() {
                let n = self.files[fi].block_count as usize;
                let got = &results[cursor..cursor + n];
                cursor += n;
                let exp = self.checksums[fi].as_deref().unwrap_or(&[]);
                let matches: Vec<bool> = got.iter().zip(exp).map(|((c, m), e)| *c == e.crc32 && *m == e.md5).collect();
                let size_ok = sizes[k] == self.files[fi].file_length;
                let hash_ok = full.as_ref().is_none_or(|h| h[k].md5_full == self.files[fi].hash_full && h[k].md5_16k == self.files[fi].hash_16k);
                if size_ok && hash_ok && matches.len() == n && matches.iter().all(|&m| m) {
                    let path = self.files[fi].target_path.clone();
                    let di = self.disk_file_index(&path);
                    for b in 0..n {
                        self.set_location(BlockRef { file_index: fi as u32, block_index: b as u32 }, BlockLocation { file: di, offset: b as u64 * ss });
                    }
                    self.files[fi].status = FileStatus::Complete;
                    self.files[fi].complete_file = Some(path);
                    observer.file_verified(&self.files[fi]);
                } else {
                    need_scan.push((fi, Some(matches)));
                }
            }
        }

        // ---- phase 3: sliding scans of the damaged files, parallel across files ----
        if !need_scan.is_empty() {
            let reports = self.scan_many(&need_scan, observer)?;
            for (fi, report) in reports {
                let path = self.files[fi].target_path.clone();
                let label = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                self.apply_scan(&path, &label, Some(fi), &report, observer);
                if self.files[fi].status == FileStatus::Unknown {
                    self.files[fi].status = FileStatus::Damaged;
                }
                observer.file_verified(&self.files[fi]);
            }
        }
        for f in self.files.iter().filter(|f| f.ignored && f.status != FileStatus::Complete) {
            let msg = if f.target_exists {
                format!("File {} has {} bad block(s) of total {} block(s) (ignored)", f.target_filename, f.missing_blocks(), f.block_count)
            } else {
                format!("File {} is missing (ignored)", f.target_filename)
            };
            observer.message(Level::Info, &msg);
        }
        observer.progress(1000, "Verification finished");
        self.verified = true;
        Ok(self.verify_result())
    }

    /// Scan several files (sliding window) on up to `num_threads` threads; `known` is the
    /// slice-level verdict of an earlier aligned pass. Reports come back in input order.
    fn scan_many(&self, items: &[(usize, Option<Vec<bool>>)], observer: &mut dyn RepairObserver) -> Result<Vec<(usize, ScanReport)>, RepairError> {
        let Some(index) = self.index.as_ref() else {
            return Err(RepairError::NotFinalized);
        };
        let threads = crate::parhash::thread_count(self.options.num_threads).clamp(1, items.len());
        let next = AtomicUsize::new(0);
        let cancel = &self.cancel;
        let results: Mutex<Vec<Option<io::Result<ScanReport>>>> = Mutex::new((0..items.len()).map(|_| None).collect());
        let work = |progress: &mut dyn FnMut(u64, u64, &str)| loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some((fi, known)) = items.get(i) else {
                return;
            };
            let path = &self.files[*fi].target_path;
            // A target that already matched some of its own slices is not a complete copy of
            // another source file, so its whole-file hash is not needed.
            let hash_file = !known.as_ref().is_some_and(|k| k.iter().any(|&b| b));
            let cfg = ScanConfig { buffer_size: self.options.scan_buffer, known_aligned: known.as_deref(), hash_file, ..ScanConfig::default() };
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0).max(1);
            let label = &self.files[*fi].target_filename;
            let r = scan_file(path, index, self.checksums[*fi].as_deref(), &cfg, Some(cancel), &mut |done| progress(done, size, label));
            results.lock().unwrap_or_else(|p| p.into_inner())[i] = Some(r);
            if cancel.load(Ordering::Relaxed) {
                return;
            }
        };
        std::thread::scope(|s| {
            for _ in 1..threads {
                s.spawn(|| work(&mut |_, _, _| {}));
            }
            work(&mut |done, size, label| observer.progress(((done.min(size) * 1000) / size) as u32, &format!("Scanning {label}")));
        });
        let results = results.into_inner().unwrap_or_else(|p| p.into_inner());
        let mut out = Vec::with_capacity(items.len());
        for ((fi, _), r) in items.iter().zip(results) {
            let path = &self.files[*fi].target_path;
            let report = r.ok_or(RepairError::Cancelled)?.map_err(io_ctx(format!("scanning {}", path.display())))?;
            if report.cancelled {
                return Err(RepairError::Cancelled);
            }
            out.push((*fi, report));
        }
        Ok(out)
    }

    /// Current verification summary.
    pub fn verify_result(&self) -> VerifyResult {
        let missing = self.missing_blocks();
        let recovery = self.recovery_blocks();
        let all_complete = self.files.iter().all(|f| f.status == FileStatus::Complete);
        let ignored_damaged: Vec<String> = self.files.iter().filter(|f| f.ignored && f.status != FileStatus::Complete).map(|f| f.target_filename.clone()).collect();
        // nzbget: damage confined to ignored files (`ParIgnoreExt`) is reported but does not
        // trigger a repair (or `.vol` unpausing).
        let repair_needed = self.files.iter().any(|f| !f.ignored && f.status != FileStatus::Complete);
        VerifyResult {
            all_complete,
            missing_blocks: missing,
            recovery_blocks: recovery,
            repair_needed,
            repair_possible: missing <= recovery,
            quick_verified_files: self.quick_verified_files,
            ignored_damaged,
        }
    }

    /// Scan a file for blocks; `expected` is the source file it is believed to be.
    fn scan_path_into(&mut self, path: &Path, expected: Option<usize>, observer: &mut dyn RepairObserver) -> Result<usize, RepairError> {
        let Some(index) = self.index.as_ref() else {
            return Err(RepairError::NotFinalized);
        };
        let exp_entries = expected.and_then(|fi| self.checksums[fi].as_deref());
        let cfg = ScanConfig { buffer_size: self.options.scan_buffer, ..ScanConfig::default() };
        let cancel = self.cancel.clone();
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0).max(1);
        let label = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let report = scan_file(path, index, exp_entries, &cfg, Some(&cancel), &mut |done| {
            observer.progress(((done.min(size) * 1000) / size) as u32, &format!("Scanning {label}"));
        })
        .map_err(io_ctx(format!("scanning {}", path.display())))?;
        if report.cancelled {
            return Err(RepairError::Cancelled);
        }
        Ok(self.apply_scan(path, &label, expected, &report, observer))
    }

    /// Record the blocks and whole-file identities a scan of `path` found. Returns the number
    /// of previously missing blocks it supplied.
    fn apply_scan(&mut self, path: &Path, label: &str, expected: Option<usize>, report: &ScanReport, observer: &mut dyn RepairObserver) -> usize {
        let di = self.disk_file_index(path);
        let mut new_blocks = 0usize;
        for f in &report.found {
            if self.set_location(f.block, BlockLocation { file: di, offset: f.offset }) {
                new_blocks += 1;
            }
        }
        // Whole-file identity: a complete (possibly misnamed) copy of some source file?
        if let Some(h) = report.file_hashes {
            for fi in 0..self.files.len() {
                if self.files[fi].file_length == h.len && self.files[fi].hash_full == h.md5_full && self.files[fi].hash_16k == h.md5_16k {
                    if self.files[fi].complete_file.is_none() || expected == Some(fi) {
                        self.files[fi].complete_file = Some(path.to_path_buf());
                    }
                    if expected == Some(fi) && path == self.files[fi].target_path {
                        self.files[fi].status = FileStatus::Complete;
                        // Unverifiable files have no block entries; mark their blocks located.
                        if self.checksums[fi].is_none() {
                            for b in 0..self.files[fi].block_count {
                                let g = self.files[fi].first_block + b as usize;
                                if self.locations[g].is_none() {
                                    self.locations[g] = Some(BlockLocation { file: di, offset: b as u64 * self.block_size() });
                                    self.files[fi].available_blocks += 1;
                                }
                            }
                        }
                    } else if self.files[fi].status != FileStatus::Complete {
                        self.files[fi].status = FileStatus::Misnamed;
                        if self.checksums[fi].is_none() {
                            for b in 0..self.files[fi].block_count {
                                let g = self.files[fi].first_block + b as usize;
                                if self.locations[g].is_none() {
                                    self.locations[g] = Some(BlockLocation { file: di, offset: b as u64 * self.block_size() });
                                    self.files[fi].available_blocks += 1;
                                }
                            }
                        }
                        observer.message(Level::Info, &format!("File {} is a complete copy of {}", label, self.files[fi].target_filename));
                    }
                }
            }
        }
        if let Some(fi) = expected {
            let f = &self.files[fi];
            if f.status != FileStatus::Complete {
                let found_here = report.found.iter().filter(|b| b.block.file_index as usize == fi).count();
                observer.message(
                    Level::Detail,
                    &format!("File {}: {} of {} blocks found ({} other-file blocks)", f.target_filename, found_here, f.block_count, report.found.len() - found_here),
                );
            }
        }
        new_blocks
    }

    /// Scan an additional file (renamed download, duplicate, fragment). Returns the number of
    /// previously missing blocks it supplied.
    pub fn add_extra_file(&mut self, path: &Path, observer: &mut dyn RepairObserver) -> Result<usize, RepairError> {
        if !self.finalized {
            return Err(RepairError::NotFinalized);
        }
        let canonical = path.to_path_buf();
        if self.scanned_extra.contains(&canonical) || self.files.iter().any(|f| f.target_path == canonical && f.status == FileStatus::Complete) {
            return Ok(0);
        }
        if self.missing_blocks() == 0 && self.files.iter().all(|f| f.status == FileStatus::Complete) {
            return Ok(0);
        }
        observer.stage(Stage::ScanningExtra);
        observer.message(Level::Info, &format!("Scanning extra file {}", path.display()));
        let n = self.scan_path_into(path, None, observer)?;
        self.scanned_extra.insert(canonical);
        Ok(n)
    }

    /// Scan every regular file in `dir` that is neither a target, a par2 file of this set, nor
    /// already scanned, for missing blocks. Stops early once nothing is missing.
    pub fn add_extra_files_from_dir(&mut self, dir: &Path, observer: &mut dyn RepairObserver) -> Result<usize, RepairError> {
        if !self.finalized {
            return Err(RepairError::NotFinalized);
        }
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir).map_err(io_ctx(format!("reading {}", dir.display())))?.filter_map(|e| e.ok().map(|e| e.path())).collect();
        entries.sort();
        let mut total = 0;
        for p in entries {
            if self.cancelled() {
                return Err(RepairError::Cancelled);
            }
            if self.missing_blocks() == 0 && self.files.iter().all(|f| f.status == FileStatus::Complete || f.complete_file.is_some()) {
                break;
            }
            if p.is_dir() || self.par_files.contains(&p) || self.files.iter().any(|f| f.target_path == p) {
                continue;
            }
            total += self.add_extra_file(&p, observer)?;
        }
        Ok(total)
    }

    /// Scan files in `dir` whose names look like split fragments of a target
    /// (`target.001`, `target.bin.002`, ...). Returns blocks gained.
    pub fn add_split_fragments(&mut self, dir: &Path, observer: &mut dyn RepairObserver) -> Result<usize, RepairError> {
        if !self.finalized {
            return Err(RepairError::NotFinalized);
        }
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir).map_err(io_ctx(format!("reading {}", dir.display())))?.filter_map(|e| e.ok().map(|e| e.path())).collect();
        entries.sort();
        let targets: Vec<Vec<u8>> = self.files.iter().map(|f| f.target_filename.as_bytes().to_vec()).collect();
        let mut total = 0;
        for p in entries {
            if p.is_dir() || self.files.iter().any(|f| f.target_path == p) {
                continue;
            }
            let name = p.file_name().map(crate::filenames::os_str_bytes).unwrap_or_default();
            if targets.iter().any(|t| crate::renamer::maybe_split_fragment(&name, t)) {
                observer.message(Level::Detail, &format!("Found split fragment {}", p.display()));
                total += self.add_extra_file(&p, observer)?;
                if !self.split_fragments.contains(&p) {
                    self.split_fragments.push(p.clone());
                }
            }
        }
        Ok(total)
    }

    // -----------------------------------------------------------------------------------------
    // Repair
    // -----------------------------------------------------------------------------------------

    /// Preserve the damaged original under its backup name. The backup is a copy (a reflink
    /// clone where the file system offers one, so it costs nothing) and the original stays in
    /// place to be patched; returns `(backup, in_place)`. When the copy fails (no space on a
    /// file system without reflinks) the original is renamed instead and `in_place` is false.
    fn make_backup(&self, path: &Path) -> Result<(PathBuf, bool), RepairError> {
        let mut n = 1;
        loop {
            let candidate = match self.options.backup {
                BackupPolicy::RenameNumbered | BackupPolicy::DeleteAfterRepair => {
                    let mut s = path.as_os_str().to_owned();
                    s.push(format!(".{n}"));
                    PathBuf::from(s)
                }
                BackupPolicy::RenameBak => {
                    let mut s = path.as_os_str().to_owned();
                    s.push(if n == 1 { ".bak".to_string() } else { format!(".bak.{}", n - 1) });
                    PathBuf::from(s)
                }
            };
            if !candidate.exists() {
                if std::fs::copy(path, &candidate).is_ok() {
                    return Ok((candidate, true));
                }
                let _ = std::fs::remove_file(&candidate);
                std::fs::rename(path, &candidate).map_err(io_ctx(format!("renaming {} to {}", path.display(), candidate.display())))?;
                return Ok((candidate, false));
            }
            n += 1;
        }
    }

    /// Repair all incomplete files. Call after [`verify`](Self::verify).
    pub fn repair(&mut self, observer: &mut dyn RepairObserver) -> Result<RepairResult, RepairError> {
        if !self.finalized {
            return Err(RepairError::NotFinalized);
        }
        if !self.verified {
            self.verify(None, observer)?;
        }
        let ss = self.block_size();
        let incomplete: Vec<usize> = (0..self.files.len()).filter(|&i| self.files[i].status != FileStatus::Complete).collect();
        if incomplete.is_empty() {
            return Ok(RepairResult::NotNeeded);
        }
        let missing_total = self.missing_blocks();
        let recovery_total = self.recovery_blocks();
        if missing_total > recovery_total {
            return Err(RepairError::NotEnoughRecovery { needed: missing_total, available: recovery_total });
        }
        observer.stage(Stage::Repairing);
        let t_start = std::time::Instant::now();
        let lap = |observer: &mut dyn RepairObserver, what: &str| observer.message(Level::Detail, &format!("{what} done at t+{:.3}s", t_start.elapsed().as_secs_f64()));

        // ---- 1. rotate damaged targets, rename misnamed complete copies ----
        let mut backups: Vec<PathBuf> = Vec::new();
        let mut repaired_names: Vec<String> = Vec::new();
        let mut to_rebuild: Vec<usize> = Vec::new();
        // Per file: the disk index of its backup when the original is patched in place (its
        // own blocks at natural offsets are already there and are read from the target).
        let mut in_place: HashMap<usize, usize> = HashMap::new();
        for &fi in &incomplete {
            if self.cancelled() {
                return Err(RepairError::Cancelled);
            }
            let target = self.files[fi].target_path.clone();
            if target.is_file() {
                let (backup, patched_in_place) = self.make_backup(&target)?;
                observer.message(Level::Info, &format!("Kept damaged file {} as {}", target.display(), backup.display()));
                // Blocks located in the target are read from the pristine backup from now on
                // (the target is about to be rewritten).
                let di = self.disk_index.get(&target).copied();
                if let Some(di) = di {
                    self.disk_files[di] = backup.clone();
                    self.disk_index.remove(&target);
                    self.disk_index.insert(backup.clone(), di);
                    if patched_in_place {
                        in_place.insert(fi, di);
                    }
                }
                if self.files[fi].complete_file.as_deref() == Some(target.as_path()) {
                    self.files[fi].complete_file = Some(backup.clone());
                }
                backups.push(backup);
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(io_ctx(format!("creating {}", parent.display())))?;
            }
            let complete_copy = self.files[fi].complete_file.clone().filter(|p| p.is_file() && p != &target);
            if let (Some(copy), true) = (complete_copy, self.options.rename_misnamed) {
                // Is the copy an exclusive source? Other files may read blocks from it; copying
                // is safer than renaming when any other file's blocks live there.
                let di = self.disk_index.get(&copy).copied();
                let shared = di.is_some_and(|di| {
                    self.locations.iter().enumerate().any(|(g, l)| {
                        l.as_ref().is_some_and(|l| l.file == di) && !(self.files[fi].first_block..self.files[fi].first_block + self.files[fi].block_count as usize).contains(&g)
                    })
                });
                if !shared {
                    std::fs::rename(&copy, &target).map_err(io_ctx(format!("renaming {} to {}", copy.display(), target.display())))?;
                    observer.message(Level::Info, &format!("Renamed {} to {}", copy.display(), target.display()));
                    if let Some(di) = di {
                        self.disk_files[di] = target.clone();
                        self.disk_index.remove(&copy);
                        self.disk_index.insert(target.clone(), di);
                    }
                    self.files[fi].complete_file = Some(target.clone());
                    self.files[fi].status = FileStatus::Complete;
                    self.files[fi].target_exists = true;
                    repaired_names.push(self.files[fi].target_filename.clone());
                    continue;
                }
            }
            to_rebuild.push(fi);
        }

        lap(observer, "backups");
        // ---- 2. create targets, copy located blocks ----
        let mut targets: HashMap<usize, File> = HashMap::new();
        let mut copy_total: u64 = 0;
        for &fi in &to_rebuild {
            copy_total += self.files[fi].available_blocks as u64;
        }
        let mut copied: u64 = 0;
        let mut buf = vec![0u8; (ss as usize).clamp(4, 4 << 20)];
        for &fi in &to_rebuild {
            let f = &self.files[fi];
            // A damaged original patched in place already holds its good blocks at their
            // natural offsets; only blocks that live elsewhere are copied in.
            let cloned_from = in_place.get(&fi).copied();
            let target = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(cloned_from.is_none())
                .open(&f.target_path)
                .map_err(io_ctx(format!("creating {}", f.target_path.display())))?;
            target.set_len(f.file_length).map_err(io_ctx(format!("sizing {}", f.target_path.display())))?;
            let mut sources: HashMap<usize, File> = HashMap::new();
            for b in 0..f.block_count {
                if self.cancelled() {
                    return Err(RepairError::Cancelled);
                }
                let g = f.first_block + b as usize;
                let Some(loc) = self.locations[g].clone() else {
                    continue;
                };
                if cloned_from == Some(loc.file) && loc.offset == b as u64 * ss {
                    // Already in place through the clone.
                    copied += 1;
                    continue;
                }
                let src = match sources.get(&loc.file) {
                    Some(s) => s,
                    None => {
                        let p = &self.disk_files[loc.file];
                        sources.insert(loc.file, File::open(p).map_err(io_ctx(format!("opening {}", p.display())))?);
                        &sources[&loc.file]
                    }
                };
                let dst_off = b as u64 * ss;
                let want = (f.file_length - dst_off).min(ss);
                let src_len = src.metadata().map(|m| m.len()).unwrap_or(0);
                let avail = src_len.saturating_sub(loc.offset).min(want);
                let mut done = 0u64;
                while done < avail {
                    let n = ((avail - done) as usize).min(buf.len());
                    read_exact_at(src, loc.offset + done, &mut buf[..n]).map_err(io_ctx(format!("reading {}", self.disk_files[loc.file].display())))?;
                    write_all_at(&target, dst_off + done, &buf[..n]).map_err(io_ctx(format!("writing {}", f.target_path.display())))?;
                    done += n as u64;
                }
                // Any shortfall (block located at the end of a shorter file) stays zero, which
                // is exactly the padded content the checksum covered.
                copied += 1;
                if let Some(p) = (copied * 500).checked_div(copy_total) {
                    observer.progress(p as u32, &format!("Copying blocks of {}", f.target_filename));
                }
            }
            targets.insert(fi, target);
        }

        lap(observer, "target files");
        // ---- 3. Reed-Solomon for missing blocks ----
        let missing_globals: Vec<usize> = (0..self.locations.len()).filter(|&g| self.locations[g].is_none()).collect();
        let mut blocks_recovered = 0u64;
        if !missing_globals.is_empty() {
            let logs = input_constant_logs(self.locations.len()).map_err(|_| RepairError::Singular)?;
            let present: Vec<bool> = self.locations.iter().map(|l| l.is_some()).collect();
            let streaming = self.streaming.is_some();
            if streaming {
                // Fold every located block that has not been accumulated yet (e.g. blocks found
                // by `verify` or extra-file scans after streaming started).
                self.streaming_backfill(observer)?;
            }
            let allowed: Option<Vec<u32>> = self.streaming.as_ref().map(|st| st.exponents.clone());
            let (plan, usable) = self.plan_with_verified_recovery(&logs, &present, allowed.as_deref(), observer)?;
            lap(observer, "recovery plan + packet verification");

            let mut reader = RepairReader { files: Vec::new(), by_path: HashMap::new(), slices: Vec::new(), mem: &[], kernel: self.options.kernel };
            let mut specs: Vec<InputSpec> = Vec::with_capacity(present.len());
            if let Some(st) = self.streaming.as_ref() {
                // Present blocks are already folded into the syndromes: inputs are the
                // syndromes plus the recovery slices, both contributing 1 to output j.
                reader.mem = &st.syndromes;
                for (j, &e) in plan.used_exponents.iter().enumerate() {
                    let si = st.exponents.iter().position(|&x| x == e).expect("tracked exponent");
                    let sidx = reader.slices.len();
                    reader.slices.push(SliceSrc::Mem(si));
                    specs.push(InputSpec { kind: InputKind::Recovery { output: j }, source: sidx });
                }
            } else {
                // Blocks of an in-place target at their natural offsets are read from the
                // target itself (same bytes, page cache hot) rather than its backup.
                let natural: HashMap<usize, usize> = in_place.iter().map(|(&fi, &di)| (di, fi)).collect();
                for (g, loc) in self.locations.iter().enumerate() {
                    if let Some(loc) = loc {
                        let mut path = &self.disk_files[loc.file];
                        if let Some(&fi) = natural.get(&loc.file) {
                            let f = &self.files[fi];
                            if g >= f.first_block && g < f.first_block + f.block_count as usize && loc.offset == (g - f.first_block) as u64 * ss {
                                path = &f.target_path;
                            }
                        }
                        let fidx = reader.file_index(path).map_err(io_ctx(format!("opening {}", path.display())))?;
                        let src_len = reader.files[fidx].metadata().map(|m| m.len()).unwrap_or(0);
                        let avail = src_len.saturating_sub(loc.offset).min(ss);
                        let sidx = reader.slices.len();
                        reader.slices.push(SliceSrc::File(fidx, loc.offset, avail));
                        specs.push(InputSpec { kind: InputKind::Data { logbase: logs[g] }, source: sidx });
                    }
                }
            }
            for (j, &e) in plan.used_exponents.iter().enumerate() {
                let r = usable[&e];
                let path = &self.par_files[r.source_id];
                let fidx = reader.file_index(path).map_err(io_ctx(format!("opening {}", path.display())))?;
                let sidx = reader.slices.len();
                reader.slices.push(SliceSrc::File(fidx, r.data_offset, r.slice_size));
                specs.push(InputSpec { kind: InputKind::Recovery { output: j }, source: sidx });
            }
            // Outputs: missing blocks → (target file, offset, length).
            let mut out_map: Vec<(usize, u64, u64)> = Vec::with_capacity(plan.missing.len());
            for &g in &plan.missing {
                let fi = self.files.iter().position(|f| g >= f.first_block && g < f.first_block + f.block_count as usize).expect("block belongs to a file");
                let b = (g - self.files[fi].first_block) as u64;
                let off = b * ss;
                let len = (self.files[fi].file_length - off).min(ss);
                out_map.push((fi, off, len));
            }
            let config = EngineConfig { num_threads: self.options.num_threads, mem_limit_bytes: self.options.mem_limit_bytes, ..EngineConfig::default() };
            let engine = Engine {
                slice_size: ss,
                inputs: &specs,
                output_exponents: &plan.used_exponents,
                post_transform: Some(&plan.inverse),
                config,
                kernel: self.options.kernel,
            };
            let mut sink = TargetSink { targets: &targets, map: &out_map };
            let cancel = self.cancel.clone();
            let total_inputs = specs.len().max(1);
            observer.message(
                Level::Info,
                &format!(
                    "Reconstructing {} block(s) from {} recovery block(s){}",
                    plan.missing.len(),
                    plan.used_exponents.len(),
                    if streaming { " using streamed syndromes" } else { "" }
                ),
            );
            engine
                .run(&reader, &mut sink, Some(&cancel), &mut |c, ct, i, it| {
                    let done = (c * it + i).min(ct * it);
                    let total = (ct * total_inputs).max(1);
                    observer.progress((500 + done * 500 / total) as u32, "Repairing");
                })
                .map_err(|e| match e {
                    RsError::Cancelled => RepairError::Cancelled,
                    RsError::Io(e) => RepairError::Io { context: "reconstructing blocks".into(), source: e },
                    RsError::NotEnoughRecovery { needed, available } => RepairError::NotEnoughRecovery { needed: needed as u64, available: available as u64 },
                    _ => RepairError::Singular,
                })?;
            blocks_recovered = plan.missing.len() as u64;
            lap(observer, "reconstruction");
        }

        if self.options.sync_repaired {
            for (&fi, t) in &targets {
                t.sync_data().map_err(io_ctx(format!("syncing {}", self.files[fi].target_path.display())))?;
            }
        }
        drop(targets);
        lap(observer, "sync");

        // ---- 4. verify repaired files ----
        let mut failed: Vec<String> = Vec::new();
        if self.options.verify_repaired {
            observer.stage(Stage::VerifyingRepaired);
            let ss = self.block_size();
            let paths: Vec<&Path> = to_rebuild.iter().map(|&fi| self.files[fi].target_path.as_path()).collect();
            let mut ranges: Vec<HashRange> = Vec::new();
            let mut sizes: Vec<u64> = Vec::with_capacity(to_rebuild.len());
            let mut full_idx: Vec<usize> = Vec::new();
            for (k, &fi) in to_rebuild.iter().enumerate() {
                let size = std::fs::metadata(paths[k]).map(|m| m.len()).unwrap_or(0);
                sizes.push(size);
                if self.checksums[fi].is_some() {
                    ranges.extend(slice_ranges(k, size, ss, self.files[fi].block_count as u64));
                }
                if self.checksums[fi].is_none() || self.options.full_file_md5 {
                    full_idx.push(k);
                }
            }
            let total_bytes = sizes.iter().sum::<u64>().max(1);
            let results = hash_ranges_parallel(&paths, &ranges, self.options.num_threads, Some(&self.cancel), &mut |done| {
                observer.progress((done * 1000 / total_bytes).min(1000) as u32, "Verifying repaired files");
            })
            .map_err(hash_err)?;
            let full_paths: Vec<&Path> = full_idx.iter().map(|&k| paths[k]).collect();
            let full = file_hashes_parallel(&full_paths, self.options.num_threads, Some(&self.cancel)).map_err(hash_err)?;
            let mut cursor = 0usize;
            for (k, &fi) in to_rebuild.iter().enumerate() {
                let mut ok = sizes[k] == self.files[fi].file_length;
                if let Some(exp) = self.checksums[fi].as_deref() {
                    let n = self.files[fi].block_count as usize;
                    let got = &results[cursor..cursor + n];
                    cursor += n;
                    ok &= got.iter().zip(exp).all(|((c, m), e)| *c == e.crc32 && *m == e.md5);
                }
                if let Some(j) = full_idx.iter().position(|&x| x == k) {
                    ok &= full[j].md5_full == self.files[fi].hash_full && full[j].len == self.files[fi].file_length;
                }
                if ok {
                    self.mark_rebuilt_complete(fi);
                } else {
                    failed.push(self.files[fi].target_filename.clone());
                }
            }
        } else {
            for &fi in &to_rebuild {
                self.mark_rebuilt_complete(fi);
            }
        }
        for &fi in &to_rebuild {
            repaired_names.push(self.files[fi].target_filename.clone());
        }
        if !failed.is_empty() {
            return Err(RepairError::VerificationFailed { files: failed });
        }
        // Leftovers: backups plus split fragments whose blocks were used and that are not targets.
        let mut leftovers: Vec<PathBuf> = backups;
        for frag in &self.split_fragments {
            let used = self.disk_index.get(frag).is_some_and(|&di| self.locations.iter().flatten().any(|l| l.file == di));
            let is_target = self.files.iter().any(|f| &f.target_path == frag);
            if used && !is_target && frag.is_file() && !leftovers.contains(frag) {
                leftovers.push(frag.clone());
            }
        }
        if self.options.backup == BackupPolicy::DeleteAfterRepair {
            for b in &leftovers {
                if let Err(e) = std::fs::remove_file(b) {
                    observer.message(Level::Warning, &format!("Could not delete {}: {e}", b.display()));
                } else {
                    observer.message(Level::Info, &format!("Deleted {}", b.display()));
                }
            }
        }
        observer.progress(1000, "Repair complete");
        Ok(RepairResult::Repaired { files: repaired_names, blocks_recovered, leftovers })
    }

    fn mark_rebuilt_complete(&mut self, fi: usize) {
        let target = self.files[fi].target_path.clone();
        let di = self.disk_file_index(&target);
        let ss = self.block_size();
        let (first, count) = (self.files[fi].first_block, self.files[fi].block_count as usize);
        for b in 0..count {
            self.locations[first + b] = Some(BlockLocation { file: di, offset: b as u64 * ss });
        }
        self.files[fi].available_blocks = count as u32;
        self.files[fi].status = FileStatus::Complete;
        self.files[fi].complete_file = Some(target);
        self.files[fi].target_exists = true;
    }
}

/// Where an engine input comes from.
pub(crate) enum SliceSrc {
    /// `(file index, offset, available bytes)`.
    File(usize, u64, u64),
    /// In-memory syndrome (split layout) by index.
    Mem(usize),
}

/// Reads input slices from located blocks, recovery packets and in-memory syndromes.
pub(crate) struct RepairReader<'a> {
    pub(crate) files: Vec<File>,
    pub(crate) by_path: HashMap<PathBuf, usize>,
    pub(crate) slices: Vec<SliceSrc>,
    /// Split-layout syndrome buffers (`slice_size` bytes each).
    pub(crate) mem: &'a [Vec<u8>],
    pub(crate) kernel: Kernel,
}

impl RepairReader<'_> {
    fn file_index(&mut self, path: &Path) -> io::Result<usize> {
        if let Some(&i) = self.by_path.get(path) {
            return Ok(i);
        }
        let f = File::open(path)?;
        let i = self.files.len();
        self.files.push(f);
        self.by_path.insert(path.to_path_buf(), i);
        Ok(i)
    }
}

impl InputReader for RepairReader<'_> {
    fn read_input(&self, source: usize, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        match self.slices[source] {
            SliceSrc::File(fi, base, avail) => {
                if offset >= avail {
                    buf.fill(0);
                    return Ok(());
                }
                let n = ((avail - offset) as usize).min(buf.len());
                read_exact_at(&self.files[fi], base + offset, &mut buf[..n])?;
                buf[n..].fill(0);
                Ok(())
            }
            SliceSrc::Mem(si) => {
                let s = &self.mem[si];
                let words = s.len() / 2;
                let w0 = (offset / 2) as usize;
                let n = buf.len() / 2;
                if w0 + n > words || !offset.is_multiple_of(2) || !buf.len().is_multiple_of(2) {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "syndrome range out of bounds"));
                }
                self.kernel.interleave(&s[w0..w0 + n], &s[words + w0..words + w0 + n], buf);
                Ok(())
            }
        }
    }
}

/// Writes reconstructed blocks into target files, truncating the padded tail.
struct TargetSink<'a> {
    targets: &'a HashMap<usize, File>,
    /// Per output: `(file index, block offset, block length within the file)`.
    map: &'a [(usize, u64, u64)],
}

impl OutputSink for TargetSink<'_> {
    fn write_output(&mut self, output: usize, offset: u64, data: &[u8]) -> io::Result<()> {
        let (fi, block_off, block_len) = self.map[output];
        if offset >= block_len {
            return Ok(());
        }
        let n = ((block_len - offset) as usize).min(data.len());
        let f = self.targets.get(&fi).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "target not open"))?;
        write_all_at(f, block_off + offset, &data[..n])
    }
}

pub(crate) fn write_all_at(file: &File, offset: u64, data: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(data, offset)
    }
    #[cfg(not(unix))]
    {
        use std::io::{Seek, Write};
        let mut f = file;
        f.seek(io::SeekFrom::Start(offset))?;
        f.write_all(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{create, CreateOptions, SourceFile, VolumeScheme};

    fn rnd(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 37) as u8
            })
            .collect()
    }

    struct Fixture {
        dir: PathBuf,
        files: Vec<(String, Vec<u8>)>,
        main: PathBuf,
    }

    fn fixture(tag: &str, sizes: &[usize], slice: u64, recovery: u32) -> Fixture {
        let dir = std::env::temp_dir().join(format!("par-rs-repair-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut files = Vec::new();
        let mut sources = Vec::new();
        for (i, &n) in sizes.iter().enumerate() {
            let name = format!("file{i}.bin");
            let data = rnd(n, 1000 + i as u64);
            std::fs::write(dir.join(&name), &data).unwrap();
            sources.push(SourceFile::new(dir.join(&name)));
            files.push((name, data));
        }
        let opts = CreateOptions { slice_size: slice, recovery_blocks: recovery, volumes: VolumeScheme::Exponential, ..CreateOptions::default() };
        create(&sources, &dir, "set", &opts, None, &mut |_, _, _| {}).unwrap();
        Fixture { dir: dir.clone(), files, main: dir.join("set.par2") }
    }

    fn check_all(fx: &Fixture) {
        for (name, data) in &fx.files {
            assert_eq!(std::fs::read(fx.dir.join(name)).unwrap(), *data, "{name}");
        }
    }

    fn by_name<'a>(r: &'a Par2Repairer, name: &str) -> &'a SourceFileState {
        r.source_files().iter().find(|f| f.target_filename == name).unwrap()
    }

    fn repairer(fx: &Fixture) -> Par2Repairer {
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        let loaded = r.load_par2_set(&fx.main).unwrap();
        assert!(!loaded.is_empty());
        r.finalize().unwrap();
        r
    }

    #[derive(Default)]
    struct Collect {
        stages: Vec<Stage>,
        messages: Vec<(Level, String)>,
        verified: Vec<(String, FileStatus)>,
    }
    impl RepairObserver for Collect {
        fn stage(&mut self, s: Stage) {
            self.stages.push(s);
        }
        fn message(&mut self, l: Level, t: &str) {
            self.messages.push((l, t.to_string()));
        }
        fn file_verified(&mut self, f: &SourceFileState) {
            self.verified.push((f.target_filename.clone(), f.status.clone()));
        }
        fn progress(&mut self, p: u32, _l: &str) {
            assert!(p <= 1000);
        }
    }

    #[test]
    fn intact_set_verifies_without_repair() {
        let fx = fixture("intact", &[10_000, 2500, 0, 777], 1024, 3);
        let mut r = repairer(&fx);
        assert_eq!(r.block_size(), 1024);
        assert!(r.set_id().is_some());
        assert!(r.creator().contains("par-rs"));
        assert_eq!(r.source_files().len(), 4);
        assert_eq!(r.total_blocks(), 10 + 3 + 1);
        assert_eq!(r.recovery_blocks(), 3);
        let mut obs = Collect::default();
        let v = r.verify(None, &mut obs).unwrap();
        assert!(v.all_complete && !v.repair_needed && v.repair_possible);
        assert_eq!(v.missing_blocks, 0);
        assert_eq!(v.blocks_needed(), 0);
        assert_eq!(r.available_blocks(), 14);
        assert!(r.source_files().iter().all(|f| f.status == FileStatus::Complete && f.missing_blocks() == 0 && f.verifiable));
        assert_eq!(r.repair(&mut obs).unwrap(), RepairResult::NotNeeded);
        assert!(obs.stages.contains(&Stage::Verifying));
        assert_eq!(obs.verified.len(), 4);
        check_all(&fx);
        assert!(r.block_locations().iter().all(|l| l.is_some()));
        assert_eq!(r.disk_files().len(), 3); // the empty file has no blocks
        let _ = r.options();
        assert_eq!(r.base_dir(), fx.dir.as_path());
        assert!(r.packets().is_complete());
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn repairs_corruption_missing_and_truncation() {
        let fx = fixture("damage", &[20_000, 5000, 3333], 1000, 12);
        // file0: corrupt blocks 2 and 7; file1: delete entirely (5 blocks); file2: truncate to 1 block.
        let p0 = fx.dir.join("file0.bin");
        let mut d0 = std::fs::read(&p0).unwrap();
        d0[2 * 1000 + 5] ^= 0xFF;
        d0[7 * 1000 + 999] ^= 0x01;
        std::fs::write(&p0, &d0).unwrap();
        std::fs::remove_file(fx.dir.join("file1.bin")).unwrap();
        let p2 = fx.dir.join("file2.bin");
        let d2 = std::fs::read(&p2).unwrap();
        std::fs::write(&p2, &d2[..1200]).unwrap();

        let mut r = repairer(&fx);
        let mut obs = Collect::default();
        let v = r.verify(None, &mut obs).unwrap();
        assert!(!v.all_complete && v.repair_needed);
        assert_eq!(v.missing_blocks, 2 + 5 + 3); // file2 had 4 blocks (3333 bytes), 1 intact
        assert!(v.repair_possible);
        assert_eq!(v.blocks_needed(), 0);
        assert_eq!(by_name(&r, "file0.bin").status, FileStatus::Damaged);
        assert_eq!(by_name(&r, "file0.bin").available_blocks, 18);
        assert_eq!(by_name(&r, "file1.bin").status, FileStatus::Missing);
        assert_eq!(by_name(&r, "file2.bin").status, FileStatus::Damaged);
        assert_eq!(by_name(&r, "file2.bin").available_blocks, 1);
        let res = r.repair(&mut obs).unwrap();
        match res {
            RepairResult::Repaired { files, blocks_recovered, .. } => {
                assert_eq!(blocks_recovered, 10);
                assert_eq!(files.len(), 3);
            }
            _ => panic!("expected repair"),
        }
        check_all(&fx);
        assert!(fx.dir.join("file0.bin.1").exists());
        assert!(fx.dir.join("file2.bin.1").exists());
        assert!(!fx.dir.join("file1.bin.1").exists());
        assert!(obs.stages.contains(&Stage::Repairing) && obs.stages.contains(&Stage::VerifyingRepaired));
        assert!(r.source_files().iter().all(|f| f.status == FileStatus::Complete));
        // Re-verify from scratch.
        let mut r2 = repairer(&fx);
        assert!(r2.verify(None, &mut NullObserver).unwrap().all_complete);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn not_enough_recovery_then_more_volumes_arrive() {
        let fx = fixture("more", &[12_000], 1000, 6);
        let p = fx.dir.join("file0.bin");
        let mut d = std::fs::read(&p).unwrap();
        for b in 0..5 {
            d[b * 1000] ^= 1;
        }
        std::fs::write(&p, &d).unwrap();
        // Load only the index + the 1-block volume (vol00+01).
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        r.load_par2_file(&fx.main).unwrap();
        r.load_par2_file(&fx.dir.join("set.vol00+01.par2")).unwrap();
        r.finalize().unwrap();
        let v = r.verify(None, &mut NullObserver).unwrap();
        assert_eq!(v.missing_blocks, 5);
        assert_eq!(v.recovery_blocks, 1);
        assert!(!v.repair_possible);
        assert_eq!(v.blocks_needed(), 4);
        assert!(matches!(r.repair(&mut NullObserver), Err(RepairError::NotEnoughRecovery { needed: 5, available: 1 })));
        // More volumes arrive (as nzbget's ParChecker::AddParFile does).
        assert_eq!(r.load_par2_file(&fx.dir.join("set.vol01+02.par2")).unwrap(), 2);
        assert_eq!(r.blocks_needed(), 2);
        assert!(!r.repair_possible());
        assert_eq!(r.load_par2_file(&fx.dir.join("set.vol03+03.par2")).unwrap(), 3);
        assert!(r.repair_possible());
        let res = r.repair(&mut NullObserver).unwrap();
        assert!(matches!(res, RepairResult::Repaired { blocks_recovered: 5, .. }));
        check_all(&fx);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn misnamed_and_split_and_extra_files() {
        let fx = fixture("extra", &[9000, 4000, 6000], 1000, 4);
        // file0 renamed; file1 split into fragments at odd offsets with original deleted;
        // file2 partially present with its missing blocks available in a "dupe" copy.
        std::fs::rename(fx.dir.join("file0.bin"), fx.dir.join("obfuscated.dat")).unwrap();
        let d1 = fx.files[1].1.clone();
        std::fs::write(fx.dir.join("file1.bin.001"), &d1[..1500]).unwrap();
        std::fs::write(fx.dir.join("file1.bin.002"), &d1[1500..]).unwrap();
        std::fs::remove_file(fx.dir.join("file1.bin")).unwrap();
        let d2 = fx.files[2].1.clone();
        let mut dmg = d2.clone();
        dmg[100] ^= 1;
        dmg[2100] ^= 1;
        dmg[5100] ^= 1;
        std::fs::write(fx.dir.join("file2.bin"), &dmg).unwrap();
        std::fs::write(fx.dir.join("dupe_copy.bin"), &d2).unwrap();
        // Also a random unrelated file.
        std::fs::write(fx.dir.join("notes.txt"), b"unrelated").unwrap();

        let mut r = repairer(&fx);
        let mut obs = Collect::default();
        let v = r.verify(None, &mut obs).unwrap();
        assert_eq!(v.missing_blocks, 9 + 4 + 3);
        assert!(!v.repair_possible); // 16 missing, 4 recovery
        // Split fragments: block 1 straddles the split point and cannot be found in either part.
        let gained = r.add_split_fragments(&fx.dir, &mut obs).unwrap();
        assert_eq!(gained, 3, "{:?}", obs.messages);
        // Everything else in the directory.
        let gained = r.add_extra_files_from_dir(&fx.dir, &mut obs).unwrap();
        assert_eq!(gained, 9 + 3);
        assert_eq!(r.missing_blocks(), 1);
        assert!(r.repair_possible());
        assert_eq!(by_name(&r, "file0.bin").status, FileStatus::Misnamed);
        assert_eq!(by_name(&r, "file0.bin").complete_file, Some(fx.dir.join("obfuscated.dat")));
        assert_eq!(by_name(&r, "file1.bin").status, FileStatus::Missing);
        // The dupe copy is a complete copy of file2 → treated as misnamed (used whole).
        assert_eq!(by_name(&r, "file2.bin").status, FileStatus::Misnamed);
        assert_eq!(by_name(&r, "file2.bin").complete_file, Some(fx.dir.join("dupe_copy.bin")));
        let res = r.repair(&mut obs).unwrap();
        match res {
            RepairResult::Repaired { files, blocks_recovered, .. } => {
                assert_eq!(blocks_recovered, 1);
                assert_eq!(files.len(), 3);
            }
            _ => panic!(),
        }
        check_all(&fx);
        assert!(!fx.dir.join("obfuscated.dat").exists()); // renamed into place
        assert!(!fx.dir.join("dupe_copy.bin").exists()); // renamed over the damaged target
        assert!(fx.dir.join("file2.bin.1").exists()); // damaged original rotated away
        assert!(fx.dir.join("file1.bin.001").exists());
        // Scanning an already scanned file is a no-op; scanning when complete is a no-op.
        assert_eq!(r.add_extra_file(&fx.dir.join("notes.txt"), &mut obs).unwrap(), 0);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn quick_verification_paths() {
        let fx = fixture("quick", &[8000, 3000], 1000, 4);
        let crc0 = crate::crc::crc32(&fx.files[0].1);
        // Damage file1 block 1 on disk; simulate its article (700-byte articles) 2 failed.
        let p1 = fx.dir.join("file1.bin");
        let mut d1 = std::fs::read(&p1).unwrap();
        d1[1400..2100].fill(0);
        std::fs::write(&p1, &d1).unwrap();
        let segments: Vec<Segment> = fx.files[1]
            .1
            .chunks(700)
            .enumerate()
            .map(|(i, c)| Segment { offset: (i * 700) as i64, size: c.len() as i64, crc: crate::crc::crc32(c), success: i != 2 })
            .collect();
        let mut r = repairer(&fx);
        let mut asked = Vec::new();
        let mut quick = |name: &str| -> Option<QuickInfo> {
            asked.push(name.to_string());
            match name {
                "file0.bin" => Some(QuickInfo::Success { crc: crc0 }),
                "file1.bin" => Some(QuickInfo::Partial { segments: segments.clone() }),
                _ => None,
            }
        };
        let mut obs = Collect::default();
        let v = r.verify(Some(&mut quick), &mut obs).unwrap();
        asked.sort();
        assert_eq!(asked, vec!["file0.bin", "file1.bin"]);
        assert_eq!(v.quick_verified_files, 2);
        assert_eq!(v.missing_blocks, 2); // article 2 = bytes 1400..2099 → blocks 1 and 2
        assert!(r.source_files().iter().all(|f| f.quick_verified));
        assert!(r.repair(&mut obs).unwrap() != RepairResult::NotNeeded);
        check_all(&fx);

        // Wrong CRC → falls back to full scan (still correct).
        let mut r = repairer(&fx);
        let mut quick = |_: &str| Some(QuickInfo::Success { crc: 0xDEAD_BEEF });
        let mut obs = Collect::default();
        let v = r.verify(Some(&mut quick), &mut obs).unwrap();
        assert!(v.all_complete);
        assert_eq!(v.quick_verified_files, 0);
        assert!(obs.messages.iter().any(|(l, m)| *l == Level::Warning && m.contains("Quick verification failed")));
        // Failure status → all blocks missing without reading.
        let mut r = repairer(&fx);
        let mut quick = |n: &str| if n == "file1.bin" { Some(QuickInfo::Failure) } else { None };
        let v = r.verify(Some(&mut quick), &mut NullObserver).unwrap();
        assert_eq!(v.missing_blocks, 3);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn corrupt_recovery_packet_is_skipped_and_backup_policies() {
        let fx = fixture("badrec", &[6000], 1000, 4);
        // Corrupt the payload of recovery block 0 (in vol00+01) — header MD5 will mismatch.
        let v0 = fx.dir.join("set.vol00+01.par2");
        let mut d = std::fs::read(&v0).unwrap();
        d[68 + 10] ^= 0xFF;
        std::fs::write(&v0, &d).unwrap();
        let p = fx.dir.join("file0.bin");
        let mut f0 = std::fs::read(&p).unwrap();
        f0[10] ^= 1;
        std::fs::write(&p, &f0).unwrap();
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions { backup: BackupPolicy::RenameBak, ..RepairOptions::default() });
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        assert_eq!(r.recovery_blocks(), 4); // metadata scan does not hash payloads
        let mut obs = Collect::default();
        r.verify(None, &mut obs).unwrap();
        let res = r.repair(&mut obs).unwrap();
        assert!(matches!(res, RepairResult::Repaired { blocks_recovered: 1, .. }));
        assert!(obs.messages.iter().any(|(l, m)| *l == Level::Warning && m.contains("corrupt")));
        assert_eq!(r.recovery_blocks(), 3);
        check_all(&fx);
        assert!(fx.dir.join("file0.bin.bak").exists());
        // Damage again: .bak exists → .bak.1
        std::fs::write(&p, &f0).unwrap();
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions { backup: BackupPolicy::RenameBak, ..RepairOptions::default() });
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        r.verify(None, &mut NullObserver).unwrap();
        r.repair(&mut NullObserver).unwrap();
        assert!(fx.dir.join("file0.bin.bak.1").exists());
        // Delete-after-repair policy.
        std::fs::write(&p, &f0).unwrap();
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions { backup: BackupPolicy::DeleteAfterRepair, ..RepairOptions::default() });
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        r.verify(None, &mut NullObserver).unwrap();
        r.repair(&mut NullObserver).unwrap();
        assert!(!fx.dir.join("file0.bin.1").exists());
        check_all(&fx);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn errors_and_edge_cases() {
        let fx = fixture("errs", &[2000], 1000, 2);
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        assert!(matches!(r.finalize(), Err(RepairError::NoMainPacket)));
        assert!(matches!(r.verify(None, &mut NullObserver), Err(RepairError::NotFinalized)));
        assert!(matches!(r.repair(&mut NullObserver), Err(RepairError::NotFinalized)));
        assert!(matches!(r.add_extra_file(&fx.main, &mut NullObserver), Err(RepairError::NotFinalized)));
        assert!(matches!(r.add_extra_files_from_dir(&fx.dir, &mut NullObserver), Err(RepairError::NotFinalized)));
        assert!(matches!(r.add_split_fragments(&fx.dir, &mut NullObserver), Err(RepairError::NotFinalized)));
        assert!(matches!(r.load_par2_file(&fx.dir.join("nope.par2")), Err(RepairError::Io { .. })));
        r.load_par2_file(&fx.main).unwrap();
        // A file of another set is rejected.
        let other = fixture("errs-other", &[1000], 1000, 1);
        assert!(matches!(r.load_par2_file(&other.main), Err(RepairError::WrongSet { .. })));
        std::fs::remove_dir_all(&other.dir).unwrap();
        r.finalize().unwrap();
        // Repair without verify first auto-verifies.
        assert_eq!(r.repair(&mut NullObserver).unwrap(), RepairResult::NotNeeded);
        // Cancellation.
        let fx2 = fixture("errs2", &[5000], 1000, 2);
        let mut r = repairer(&fx2);
        let token = r.cancel_token();
        token.store(true, Ordering::Relaxed);
        assert!(matches!(r.verify(None, &mut NullObserver), Err(RepairError::Cancelled)));
        r.cancel();
        assert!(r.cancel_token().load(Ordering::Relaxed));
        // In-memory par2 data.
        let mut r = Par2Repairer::new(&fx2.dir, RepairOptions::default());
        let bytes = std::fs::read(&fx2.main).unwrap();
        r.load_par2_bytes(bytes, "index").unwrap();
        r.finalize().unwrap();
        assert!(r.verify(None, &mut NullObserver).unwrap().all_complete);
        // Error display.
        for e in [
            RepairError::NoMainPacket,
            RepairError::IncompleteMetadata { missing_descriptions: vec![] },
            RepairError::NotFinalized,
            RepairError::WrongSet { expected: SetId([0; 16]), found: SetId([1; 16]) },
            RepairError::NotEnoughRecovery { needed: 2, available: 1 },
            RepairError::Singular,
            RepairError::VerificationFailed { files: vec!["a".into()] },
            RepairError::Io { context: "x".into(), source: io::Error::other("y") },
            RepairError::Cancelled,
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert!(std::error::Error::source(&RepairError::Io { context: "x".into(), source: io::Error::other("y") }).is_some());
        std::fs::remove_dir_all(&fx.dir).unwrap();
        std::fs::remove_dir_all(&fx2.dir).unwrap();
    }

    #[test]
    fn incomplete_metadata_is_reported() {
        let fx = fixture("meta", &[3000, 3000], 1000, 1);
        // Build an index with the Main packet but drop one FileDesc.
        let bytes = std::fs::read(&fx.main).unwrap();
        let raws: Vec<_> = crate::packet::PacketIter::new(&bytes[..], ScanOptions::UNVERIFIED).map(|x| x.unwrap()).collect();
        let mut trimmed = Vec::new();
        let mut dropped = false;
        for r in raws {
            if r.header.kind() == crate::packet::PacketType::FileDesc && !dropped {
                dropped = true;
                continue;
            }
            trimmed.extend_from_slice(&bytes[r.offset as usize..(r.offset + r.header.length) as usize]);
        }
        let p = fx.dir.join("trimmed.par2");
        std::fs::write(&p, &trimmed).unwrap();
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        r.load_par2_file(&p).unwrap();
        match r.finalize() {
            Err(RepairError::IncompleteMetadata { missing_descriptions }) => assert_eq!(missing_descriptions.len(), 1),
            other => panic!("{other:?}"),
        }
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn unverifiable_file_without_ifsc() {
        let fx = fixture("noifsc", &[2500, 1000], 1000, 3);
        // Strip the IFSC packet of file0 from the index and volumes.
        let id0 = {
            let set = crate::packet::load_par2_file(&fx.main, ScanOptions::FULL).unwrap();
            set.file_descs.values().find(|d| d.name == b"file0.bin").unwrap().file_id
        };
        for entry in std::fs::read_dir(&fx.dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().is_some_and(|e| e == "par2") {
                let bytes = std::fs::read(&p).unwrap();
                let raws: Vec<_> = crate::packet::PacketIter::new(&bytes[..], ScanOptions::UNVERIFIED).map(|x| x.unwrap()).collect();
                let mut out = Vec::new();
                for r in raws {
                    let s = r.offset as usize;
                    let e = s + r.header.length as usize;
                    if r.header.kind() == crate::packet::PacketType::Ifsc && bytes[s + 64..s + 80] == id0.0 {
                        continue;
                    }
                    out.extend_from_slice(&bytes[s..e]);
                }
                std::fs::write(&p, &out).unwrap();
            }
        }
        // Intact: verified by whole-file hash.
        let mut r = repairer(&fx);
        assert!(!by_name(&r, "file0.bin").verifiable);
        assert!(by_name(&r, "file1.bin").verifiable);
        let v = r.verify(None, &mut NullObserver).unwrap();
        assert!(v.all_complete, "{:?}", r.source_files());
        // Damaged: all 3 blocks count as missing and are reconstructed.
        let p0 = fx.dir.join("file0.bin");
        let mut d = std::fs::read(&p0).unwrap();
        d[5] ^= 1;
        std::fs::write(&p0, &d).unwrap();
        let mut r = repairer(&fx);
        let v = r.verify(None, &mut NullObserver).unwrap();
        assert_eq!(v.missing_blocks, 3);
        assert!(v.repair_possible);
        assert!(matches!(r.repair(&mut NullObserver).unwrap(), RepairResult::Repaired { blocks_recovered: 3, .. }));
        check_all(&fx);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn many_missing_blocks_large_matrix() {
        // 60 missing blocks out of 80 with 64 recovery blocks: exercises the k×k solve path.
        let fx = fixture("big", &[80_000], 1000, 64);
        let p = fx.dir.join("file0.bin");
        let d = std::fs::read(&p).unwrap();
        std::fs::write(&p, &d[..20_000]).unwrap();
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions { num_threads: 3, mem_limit_bytes: 0, ..RepairOptions::default() });
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        let v = r.verify(None, &mut NullObserver).unwrap();
        assert_eq!(v.missing_blocks, 60);
        assert!(matches!(r.repair(&mut NullObserver).unwrap(), RepairResult::Repaired { blocks_recovered: 60, .. }));
        check_all(&fx);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }
}
