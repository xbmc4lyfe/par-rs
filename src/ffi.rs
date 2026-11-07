//! C ABI for hosts that embed the engine from C/C++ (or from Rust through a stable boundary).
//!
//! Every function is `extern "C"`, panics are caught at the boundary (with `panic = "abort"`
//! builds they abort as configured), and all strings are NUL-terminated UTF-8 (file names
//! that are not valid UTF-8 are lossily converted). Objects are opaque handles freed with
//! their `*_free` function. Status codes are [`NzbParStatus`]; the last error message of a
//! repairer is available through [`nzbpar_repairer_last_error`].

use crate::repairer::{BackupPolicy, Level, Par2Repairer, QuickInfo, QuickVerifier, RepairError, RepairObserver, RepairOptions, RepairResult, Stage};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::PathBuf;
use std::ptr;

/// Status codes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NzbParStatus {
    /// Success.
    Ok = 0,
    /// Null pointer or invalid argument.
    InvalidArgument = 1,
    /// No Main packet.
    NoMainPacket = 2,
    /// Metadata incomplete.
    IncompleteMetadata = 3,
    /// Not finalized.
    NotFinalized = 4,
    /// Par2 file of another set.
    WrongSet = 5,
    /// Not enough recovery blocks.
    NotEnoughRecovery = 6,
    /// Singular matrix.
    Singular = 7,
    /// Repaired files failed verification.
    VerificationFailed = 8,
    /// I/O error.
    Io = 9,
    /// Cancelled.
    Cancelled = 10,
    /// Nothing to repair.
    RepairNotNeeded = 11,
    /// Internal panic.
    Panic = 12,
}

impl From<&RepairError> for NzbParStatus {
    fn from(e: &RepairError) -> Self {
        match e {
            RepairError::NoMainPacket => NzbParStatus::NoMainPacket,
            RepairError::IncompleteMetadata { .. } => NzbParStatus::IncompleteMetadata,
            RepairError::NotFinalized => NzbParStatus::NotFinalized,
            RepairError::WrongSet { .. } => NzbParStatus::WrongSet,
            RepairError::NotEnoughRecovery { .. } => NzbParStatus::NotEnoughRecovery,
            RepairError::Singular => NzbParStatus::Singular,
            RepairError::VerificationFailed { .. } => NzbParStatus::VerificationFailed,
            RepairError::Io { .. } => NzbParStatus::Io,
            RepairError::Cancelled => NzbParStatus::Cancelled,
            RepairError::UnknownFile(_) => NzbParStatus::InvalidArgument,
        }
    }
}

/// Repair options as seen from C. Zero-initialise and set what you need.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NzbParRepairOptions {
    /// Worker threads (0 = all cores).
    pub num_threads: u32,
    /// Memory budget in bytes (0 = default 256 MiB; minimum 16 MiB).
    pub mem_limit_bytes: u64,
    /// 0 = rename damaged files to `.1`, 1 = `.bak`, 2 = delete backups after repair.
    pub backup_policy: c_int,
    /// Re-hash repaired files (non-zero = yes).
    pub verify_repaired: c_int,
    /// Rename misnamed complete files into place (non-zero = yes).
    pub rename_misnamed: c_int,
}

/// Per-file state snapshot.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NzbParFileInfo {
    /// Expected file length.
    pub file_length: u64,
    /// Slices.
    pub block_count: u32,
    /// Slices located.
    pub available_blocks: u32,
    /// 0 unknown, 1 missing, 2 complete, 3 damaged, 4 misnamed.
    pub status: c_int,
    /// Non-zero when the target path exists.
    pub target_exists: c_int,
    /// Non-zero when verified from download CRCs.
    pub quick_verified: c_int,
    /// MD5 of the whole file.
    pub hash_full: [u8; 16],
    /// MD5 of the first 16 KiB.
    pub hash_16k: [u8; 16],
}

/// Verification summary.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NzbParVerifyResult {
    /// Non-zero when every file is complete.
    pub all_complete: c_int,
    /// Non-zero when some file needs rebuilding.
    pub repair_needed: c_int,
    /// Non-zero when the Reed-Solomon step is possible.
    pub repair_possible: c_int,
    /// Blocks missing.
    pub missing_blocks: u64,
    /// Recovery blocks loaded.
    pub recovery_blocks: u64,
    /// Files quick-verified.
    pub quick_verified_files: u64,
}

/// Article segment for quick verification of partially downloaded files.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NzbParSegment {
    /// Offset in file.
    pub offset: i64,
    /// Size in bytes.
    pub size: i64,
    /// Decoded CRC-32.
    pub crc: u32,
    /// Non-zero when downloaded successfully.
    pub success: c_int,
}

/// Quick-verification callback: fill `*out_status` with 0 (unknown / no info), 1 (success,
/// `*out_crc` set), 2 (partial, `*out_segments`/`*out_count` point at an array that must stay
/// valid until the next callback) or 3 (failure).
pub type NzbParQuickFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        filename: *const c_char,
        out_status: *mut c_int,
        out_crc: *mut u32,
        out_segments: *mut *const NzbParSegment,
        out_count: *mut usize,
    ),
>;

/// Progress callback: `stage` (0 loading, 1 verifying, 2 scanning extra, 3 repairing,
/// 4 verifying repaired), `permille` 0..=1000, `label` NUL-terminated.
pub type NzbParProgressFn = Option<unsafe extern "C" fn(ctx: *mut c_void, stage: c_int, permille: u32, label: *const c_char)>;

/// Message callback: `level` (0 detail, 1 info, 2 warning, 3 error).
pub type NzbParMessageFn = Option<unsafe extern "C" fn(ctx: *mut c_void, level: c_int, text: *const c_char)>;

/// Opaque repairer handle.
pub struct NzbParRepairer {
    inner: Par2Repairer,
    last_error: CString,
    callbacks: Callbacks,
}

#[derive(Clone, Copy)]
struct Callbacks {
    ctx: *mut c_void,
    progress: NzbParProgressFn,
    message: NzbParMessageFn,
    stage: Stage,
}

impl RepairObserver for Callbacks {
    fn stage(&mut self, stage: Stage) {
        self.stage = stage;
    }
    fn progress(&mut self, permille: u32, label: &str) {
        if let Some(cb) = self.progress {
            let c = CString::new(label.replace('\0', " ")).unwrap_or_default();
            let st = match self.stage {
                Stage::Loading => 0,
                Stage::Verifying => 1,
                Stage::ScanningExtra => 2,
                Stage::Repairing => 3,
                Stage::VerifyingRepaired => 4,
            };
            // SAFETY: caller-provided callback with caller-provided context.
            unsafe { cb(self.ctx, st, permille, c.as_ptr()) }
        }
    }
    fn message(&mut self, level: Level, text: &str) {
        if let Some(cb) = self.message {
            let c = CString::new(text.replace('\0', " ")).unwrap_or_default();
            let lv = match level {
                Level::Detail => 0,
                Level::Info => 1,
                Level::Warning => 2,
                Level::Error => 3,
            };
            // SAFETY: as above.
            unsafe { cb(self.ctx, lv, c.as_ptr()) }
        }
    }
}

struct QuickCb {
    ctx: *mut c_void,
    f: unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_int, *mut u32, *mut *const NzbParSegment, *mut usize),
}

impl QuickVerifier for QuickCb {
    fn quick_info(&mut self, target_filename: &str) -> Option<QuickInfo> {
        let name = CString::new(target_filename.replace('\0', " ")).ok()?;
        let mut status: c_int = 0;
        let mut crc: u32 = 0;
        let mut segs: *const NzbParSegment = ptr::null();
        let mut count: usize = 0;
        // SAFETY: caller-provided callback contract.
        unsafe { (self.f)(self.ctx, name.as_ptr(), &mut status, &mut crc, &mut segs, &mut count) };
        match status {
            1 => Some(QuickInfo::Success { crc }),
            2 => {
                if segs.is_null() || count == 0 {
                    return Some(QuickInfo::Failure);
                }
                // SAFETY: the callback promises `count` valid segments.
                let arr = unsafe { std::slice::from_raw_parts(segs, count) };
                let mut v: Vec<crate::damage::Segment> =
                    arr.iter().map(|s| crate::damage::Segment { offset: s.offset, size: s.size, crc: s.crc, success: s.success != 0 }).collect();
                v.sort_by_key(|s| s.offset);
                Some(QuickInfo::Partial { segments: v })
            }
            3 => Some(QuickInfo::Failure),
            _ => None,
        }
    }
}

fn cstr_to_path(p: *const c_char) -> Option<PathBuf> {
    if p.is_null() {
        return None;
    }
    // SAFETY: caller guarantees a NUL-terminated string.
    let s = unsafe { CStr::from_ptr(p) };
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(s.to_bytes())))
    }
    #[cfg(not(unix))]
    {
        Some(PathBuf::from(s.to_string_lossy().into_owned()))
    }
}

fn guard<F: FnOnce() -> NzbParStatus>(f: F) -> NzbParStatus {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(_) => NzbParStatus::Panic,
    }
}

impl NzbParRepairer {
    fn fail(&mut self, e: &RepairError) -> NzbParStatus {
        self.last_error = CString::new(e.to_string().replace('\0', " ")).unwrap_or_default();
        NzbParStatus::from(e)
    }
}

/// Create a repairer for files in `base_dir`. `options` may be NULL for defaults.
///
/// # Safety
/// `base_dir` must be a valid NUL-terminated string; `options`, if non-NULL, must point to a
/// valid [`NzbParRepairOptions`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_new(base_dir: *const c_char, options: *const NzbParRepairOptions) -> *mut NzbParRepairer {
    let Some(dir) = cstr_to_path(base_dir) else {
        return ptr::null_mut();
    };
    let mut opts = RepairOptions::default();
    if !options.is_null() {
        // SAFETY: caller guarantees validity.
        let o = unsafe { &*options };
        opts.num_threads = o.num_threads as usize;
        if o.mem_limit_bytes > 0 {
            opts.mem_limit_bytes = o.mem_limit_bytes;
        }
        opts.backup = match o.backup_policy {
            1 => BackupPolicy::RenameBak,
            2 => BackupPolicy::DeleteAfterRepair,
            _ => BackupPolicy::RenameNumbered,
        };
        opts.verify_repaired = o.verify_repaired != 0;
        opts.rename_misnamed = o.rename_misnamed != 0;
    }
    let r = std::panic::catch_unwind(|| Par2Repairer::new(dir, opts));
    match r {
        Ok(inner) => Box::into_raw(Box::new(NzbParRepairer {
            inner,
            last_error: CString::default(),
            callbacks: Callbacks { ctx: ptr::null_mut(), progress: None, message: None, stage: Stage::Loading },
        })),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a repairer.
///
/// # Safety
/// `r` must come from [`nzbpar_repairer_new`] and not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_free(r: *mut NzbParRepairer) {
    if !r.is_null() {
        // SAFETY: ownership returned by `Box::into_raw`.
        drop(unsafe { Box::from_raw(r) });
    }
}

/// Install progress/message callbacks (either may be NULL).
///
/// # Safety
/// `r` must be a valid handle; callbacks must remain valid for the handle's lifetime.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_set_callbacks(r: *mut NzbParRepairer, ctx: *mut c_void, progress: NzbParProgressFn, message: NzbParMessageFn) -> NzbParStatus {
    if r.is_null() {
        return NzbParStatus::InvalidArgument;
    }
    // SAFETY: valid handle.
    let h = unsafe { &mut *r };
    h.callbacks = Callbacks { ctx, progress, message, stage: Stage::Loading };
    NzbParStatus::Ok
}

/// Load one par2 file. `out_recovery_added` (may be NULL) receives the recovery slices added.
///
/// # Safety
/// `r` valid handle, `path` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_load_file(r: *mut NzbParRepairer, path: *const c_char, out_recovery_added: *mut u64) -> NzbParStatus {
    let (Some(h), Some(p)) = (unsafe { r.as_mut() }, cstr_to_path(path)) else {
        return NzbParStatus::InvalidArgument;
    };
    guard(|| match h.inner.load_par2_file(&p) {
        Ok(n) => {
            if !out_recovery_added.is_null() {
                // SAFETY: caller-provided out pointer.
                unsafe { *out_recovery_added = n as u64 };
            }
            NzbParStatus::Ok
        }
        Err(e) => h.fail(&e),
    })
}

/// Load a main par2 file and all volumes of the same collection in its directory.
///
/// # Safety
/// `r` valid handle, `main_path` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_load_set(r: *mut NzbParRepairer, main_path: *const c_char, out_files_loaded: *mut u64) -> NzbParStatus {
    let (Some(h), Some(p)) = (unsafe { r.as_mut() }, cstr_to_path(main_path)) else {
        return NzbParStatus::InvalidArgument;
    };
    guard(|| match h.inner.load_par2_set(&p) {
        Ok(v) => {
            if !out_files_loaded.is_null() {
                // SAFETY: caller-provided out pointer.
                unsafe { *out_files_loaded = v.len() as u64 };
            }
            NzbParStatus::Ok
        }
        Err(e) => h.fail(&e),
    })
}

/// Build file/block tables after loading.
///
/// # Safety
/// `r` valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_finalize(r: *mut NzbParRepairer) -> NzbParStatus {
    let Some(h) = (unsafe { r.as_mut() }) else {
        return NzbParStatus::InvalidArgument;
    };
    guard(|| match h.inner.finalize() {
        Ok(()) => NzbParStatus::Ok,
        Err(e) => h.fail(&e),
    })
}

/// Verify source files. `quick` may be NULL. `out` may be NULL.
///
/// # Safety
/// `r` valid handle; `quick`, if set, must follow the [`NzbParQuickFn`] contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_verify(r: *mut NzbParRepairer, quick_ctx: *mut c_void, quick: NzbParQuickFn, out: *mut NzbParVerifyResult) -> NzbParStatus {
    let Some(h) = (unsafe { r.as_mut() }) else {
        return NzbParStatus::InvalidArgument;
    };
    guard(|| {
        let mut cb = h.callbacks;
        let mut q = quick.map(|f| QuickCb { ctx: quick_ctx, f });
        let qv: Option<&mut dyn QuickVerifier> = q.as_mut().map(|x| x as &mut dyn QuickVerifier);
        match h.inner.verify(qv, &mut cb) {
            Ok(v) => {
                if !out.is_null() {
                    // SAFETY: caller-provided out pointer.
                    unsafe {
                        *out = NzbParVerifyResult {
                            all_complete: v.all_complete as c_int,
                            repair_needed: v.repair_needed as c_int,
                            repair_possible: v.repair_possible as c_int,
                            missing_blocks: v.missing_blocks,
                            recovery_blocks: v.recovery_blocks,
                            quick_verified_files: v.quick_verified_files as u64,
                        }
                    };
                }
                NzbParStatus::Ok
            }
            Err(e) => h.fail(&e),
        }
    })
}

/// Scan an extra file for blocks. `out_blocks` (may be NULL) receives blocks gained.
///
/// # Safety
/// `r` valid handle, `path` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_add_extra_file(r: *mut NzbParRepairer, path: *const c_char, out_blocks: *mut u64) -> NzbParStatus {
    let (Some(h), Some(p)) = (unsafe { r.as_mut() }, cstr_to_path(path)) else {
        return NzbParStatus::InvalidArgument;
    };
    guard(|| {
        let mut cb = h.callbacks;
        match h.inner.add_extra_file(&p, &mut cb) {
            Ok(n) => {
                if !out_blocks.is_null() {
                    // SAFETY: caller-provided out pointer.
                    unsafe { *out_blocks = n as u64 };
                }
                NzbParStatus::Ok
            }
            Err(e) => h.fail(&e),
        }
    })
}

/// Scan a directory for split fragments (`mode` 0) or all extra files (`mode` 1).
///
/// # Safety
/// `r` valid handle, `dir` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_add_extra_dir(r: *mut NzbParRepairer, dir: *const c_char, mode: c_int, out_blocks: *mut u64) -> NzbParStatus {
    let (Some(h), Some(p)) = (unsafe { r.as_mut() }, cstr_to_path(dir)) else {
        return NzbParStatus::InvalidArgument;
    };
    guard(|| {
        let mut cb = h.callbacks;
        let res = if mode == 0 { h.inner.add_split_fragments(&p, &mut cb) } else { h.inner.add_extra_files_from_dir(&p, &mut cb) };
        match res {
            Ok(n) => {
                if !out_blocks.is_null() {
                    // SAFETY: caller-provided out pointer.
                    unsafe { *out_blocks = n as u64 };
                }
                NzbParStatus::Ok
            }
            Err(e) => h.fail(&e),
        }
    })
}

/// Repair. Returns `RepairNotNeeded` when everything was already complete; `out_blocks`
/// (may be NULL) receives the number of blocks reconstructed.
///
/// # Safety
/// `r` valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_repair(r: *mut NzbParRepairer, out_blocks: *mut u64) -> NzbParStatus {
    let Some(h) = (unsafe { r.as_mut() }) else {
        return NzbParStatus::InvalidArgument;
    };
    guard(|| {
        let mut cb = h.callbacks;
        match h.inner.repair(&mut cb) {
            Ok(RepairResult::NotNeeded) => NzbParStatus::RepairNotNeeded,
            Ok(RepairResult::Repaired { blocks_recovered, .. }) => {
                if !out_blocks.is_null() {
                    // SAFETY: caller-provided out pointer.
                    unsafe { *out_blocks = blocks_recovered };
                }
                NzbParStatus::Ok
            }
            Err(e) => h.fail(&e),
        }
    })
}

/// Request cancellation (thread-safe; may be called from another thread).
///
/// # Safety
/// `r` must be a valid handle that is not freed concurrently.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_cancel(r: *const NzbParRepairer) {
    if let Some(h) = unsafe { r.as_ref() } {
        h.inner.cancel();
    }
}

/// Numeric status helpers.
///
/// # Safety
/// `r` valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_stats(r: *const NzbParRepairer, out_total_blocks: *mut u64, out_missing_blocks: *mut u64, out_recovery_blocks: *mut u64, out_block_size: *mut u64) -> NzbParStatus {
    let Some(h) = (unsafe { r.as_ref() }) else {
        return NzbParStatus::InvalidArgument;
    };
    // SAFETY: caller-provided out pointers, each checked for NULL.
    unsafe {
        if !out_total_blocks.is_null() {
            *out_total_blocks = h.inner.total_blocks();
        }
        if !out_missing_blocks.is_null() {
            *out_missing_blocks = h.inner.missing_blocks();
        }
        if !out_recovery_blocks.is_null() {
            *out_recovery_blocks = h.inner.recovery_blocks();
        }
        if !out_block_size.is_null() {
            *out_block_size = h.inner.block_size();
        }
    }
    NzbParStatus::Ok
}

/// Number of source files.
///
/// # Safety
/// `r` valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_file_count(r: *const NzbParRepairer) -> usize {
    unsafe { r.as_ref() }.map(|h| h.inner.source_files().len()).unwrap_or(0)
}

/// Snapshot of file `index`; `out_name` receives a pointer to a NUL-terminated name owned by
/// the handle and valid until the next call that mutates the repairer.
///
/// # Safety
/// `r` valid handle; `out`/`out_name` valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_file_info(r: *mut NzbParRepairer, index: usize, out: *mut NzbParFileInfo, out_name: *mut *const c_char) -> NzbParStatus {
    let Some(h) = (unsafe { r.as_mut() }) else {
        return NzbParStatus::InvalidArgument;
    };
    let Some(f) = h.inner.source_files().get(index) else {
        return NzbParStatus::InvalidArgument;
    };
    if !out.is_null() {
        // SAFETY: caller-provided out pointer.
        unsafe {
            *out = NzbParFileInfo {
                file_length: f.file_length,
                block_count: f.block_count,
                available_blocks: f.available_blocks,
                status: match f.status {
                    crate::repairer::FileStatus::Unknown => 0,
                    crate::repairer::FileStatus::Missing => 1,
                    crate::repairer::FileStatus::Complete => 2,
                    crate::repairer::FileStatus::Damaged => 3,
                    crate::repairer::FileStatus::Misnamed => 4,
                },
                target_exists: f.target_exists as c_int,
                quick_verified: f.quick_verified as c_int,
                hash_full: f.hash_full,
                hash_16k: f.hash_16k,
            }
        };
    }
    if !out_name.is_null() {
        h.last_error = CString::new(f.target_filename.replace('\0', " ")).unwrap_or_default();
        // SAFETY: caller-provided out pointer.
        unsafe { *out_name = h.last_error.as_ptr() };
    }
    NzbParStatus::Ok
}

/// Last error message (empty string if none). Valid until the next call on the handle.
///
/// # Safety
/// `r` valid handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_repairer_last_error(r: *const NzbParRepairer) -> *const c_char {
    match unsafe { r.as_ref() } {
        Some(h) => h.last_error.as_ptr(),
        None => c"".as_ptr(),
    }
}

// ---------------------------------------------------------------------------------------------
// Stateless helpers
// ---------------------------------------------------------------------------------------------

/// CRC-32 of a buffer.
///
/// # Safety
/// `data` must point to `len` readable bytes (or be NULL with `len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_crc32(data: *const u8, len: usize) -> u32 {
    if data.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: caller guarantees the buffer.
    crate::crc::crc32(unsafe { std::slice::from_raw_parts(data, len) })
}

/// `crc32(A ‖ B)` from `crc32(A)`, `crc32(B)` and `|B|`.
#[unsafe(no_mangle)]
pub extern "C" fn nzbpar_crc32_combine(crc_a: u32, crc_b: u32, len_b: u64) -> u32 {
    crate::crc::crc32_combine(crc_a, crc_b, len_b)
}

/// CRC of `data ‖ 0^n` from `crc32(data)`.
#[unsafe(no_mangle)]
pub extern "C" fn nzbpar_crc32_zeros(crc: u32, n: u64) -> u32 {
    crate::crc::crc32_zeros(crc, n)
}

/// Parse a par2 file name: returns 1 if it is a par2 name and fills `out_base_len` and
/// `out_blocks` (0 main, >0 volume block count, -1 unknown).
///
/// # Safety
/// `name` NUL-terminated; out pointers valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_parse_par_filename(name: *const c_char, confirmed: c_int, out_base_len: *mut usize, out_blocks: *mut c_int) -> c_int {
    if name.is_null() {
        return 0;
    }
    // SAFETY: NUL-terminated string.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    match crate::filenames::parse_par_filename(bytes, confirmed != 0, crate::filenames::ascii_lower) {
        Some(p) => {
            // SAFETY: out pointers checked for NULL.
            unsafe {
                if !out_base_len.is_null() {
                    *out_base_len = p.base_len;
                }
                if !out_blocks.is_null() {
                    *out_blocks = p.blocks;
                }
            }
            1
        }
        None => 0,
    }
}

/// Run the par-renamer on `dir`. Returns the number of renames or -1 on error.
///
/// # Safety
/// `dir` NUL-terminated; `message` callback optional.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nzbpar_rename_dir(dir: *const c_char, detect_missing: c_int, dry_run: c_int, ctx: *mut c_void, message: NzbParMessageFn) -> c_int {
    let Some(d) = cstr_to_path(dir) else {
        return -1;
    };
    let opts = crate::renamer::RenamerOptions { detect_missing: detect_missing != 0, dry_run: dry_run != 0, ignore_extensions: Vec::new() };
    let res = std::panic::catch_unwind(|| {
        crate::renamer::ParRenamer::new(d, opts).run(None, &mut |ev| {
            if let Some(cb) = message {
                let (lv, text) = match ev {
                    crate::renamer::RenamerEvent::Info(t) => (1, t),
                    crate::renamer::RenamerEvent::Warning(t) => (2, t),
                    crate::renamer::RenamerEvent::Error(t) => (3, t),
                    crate::renamer::RenamerEvent::Renamed { from, to } => (1, format!("Renamed {} to {}", from.display(), to.display())),
                    crate::renamer::RenamerEvent::Progress(_, _) => return,
                };
                let c = CString::new(text.replace('\0', " ")).unwrap_or_default();
                // SAFETY: caller-provided callback.
                unsafe { cb(ctx, lv, c.as_ptr()) }
            }
        })
    });
    match res {
        Ok(Ok(rep)) => rep.renamed_count() as c_int,
        _ => -1,
    }
}

/// Library version string.
#[unsafe(no_mangle)]
pub extern "C" fn nzbpar_version() -> *const c_char {
    static V: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    V.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{create, CreateOptions, SourceFile};

    unsafe extern "C" fn msg_cb(ctx: *mut c_void, _level: c_int, text: *const c_char) {
        // SAFETY: ctx is a `*mut Vec<String>` set up by the test.
        let v = unsafe { &mut *(ctx as *mut Vec<String>) };
        v.push(unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned());
    }

    unsafe extern "C" fn progress_cb(ctx: *mut c_void, _stage: c_int, permille: u32, _label: *const c_char) {
        assert!(permille <= 1000);
        let v = unsafe { &mut *(ctx as *mut Vec<String>) };
        v.push(format!("p{permille}"));
    }

    unsafe extern "C" fn quick_cb(ctx: *mut c_void, filename: *const c_char, out_status: *mut c_int, out_crc: *mut u32, _segs: *mut *const NzbParSegment, _count: *mut usize) {
        let crc = unsafe { *(ctx as *const u32) };
        let name = unsafe { CStr::from_ptr(filename) }.to_string_lossy();
        unsafe {
            if name == "f.bin" {
                *out_status = 1;
                *out_crc = crc;
            } else {
                *out_status = 0;
            }
        }
    }

    #[test]
    fn ffi_roundtrip() {
        let dir = std::env::temp_dir().join(format!("par-rs-ffi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..7000u32).map(|i| (i * 31 % 251) as u8).collect();
        std::fs::write(dir.join("f.bin"), &data).unwrap();
        let opts = CreateOptions { slice_size: 1000, recovery_blocks: 3, ..CreateOptions::default() };
        create(&[SourceFile::new(dir.join("f.bin"))], &dir, "s", &opts, None, &mut |_, _, _| {}).unwrap();
        let crc = crate::crc::crc32(&data);

        let cdir = CString::new(dir.to_string_lossy().as_bytes()).unwrap();
        let copts = NzbParRepairOptions { num_threads: 2, mem_limit_bytes: 0, backup_policy: 1, verify_repaired: 1, rename_misnamed: 1 };
        let r = unsafe { nzbpar_repairer_new(cdir.as_ptr(), &copts) };
        assert!(!r.is_null());
        assert!(unsafe { nzbpar_repairer_new(ptr::null(), ptr::null()) }.is_null());
        let mut msgs: Vec<String> = Vec::new();
        unsafe { nzbpar_repairer_set_callbacks(r, &mut msgs as *mut _ as *mut c_void, Some(progress_cb), Some(msg_cb)) };
        let main = CString::new(dir.join("s.par2").to_string_lossy().as_bytes()).unwrap();
        let mut loaded = 0u64;
        assert_eq!(unsafe { nzbpar_repairer_load_set(r, main.as_ptr(), &mut loaded) }, NzbParStatus::Ok);
        assert!(loaded >= 2);
        assert_eq!(unsafe { nzbpar_repairer_finalize(r) }, NzbParStatus::Ok);
        let mut out = NzbParVerifyResult::default();
        let crc_ctx = crc;
        assert_eq!(unsafe { nzbpar_repairer_verify(r, &crc_ctx as *const u32 as *mut c_void, Some(quick_cb), &mut out) }, NzbParStatus::Ok);
        assert_eq!(out.all_complete, 1);
        assert_eq!(out.quick_verified_files, 1);
        assert_eq!(unsafe { nzbpar_repairer_repair(r, ptr::null_mut()) }, NzbParStatus::RepairNotNeeded);
        let (mut t, mut m, mut rc, mut bs) = (0u64, 0u64, 0u64, 0u64);
        assert_eq!(unsafe { nzbpar_repairer_stats(r, &mut t, &mut m, &mut rc, &mut bs) }, NzbParStatus::Ok);
        assert_eq!((t, m, rc, bs), (7, 0, 3, 1000));
        assert_eq!(unsafe { nzbpar_repairer_file_count(r) }, 1);
        let mut info = NzbParFileInfo { file_length: 0, block_count: 0, available_blocks: 0, status: 0, target_exists: 0, quick_verified: 0, hash_full: [0; 16], hash_16k: [0; 16] };
        let mut name: *const c_char = ptr::null();
        assert_eq!(unsafe { nzbpar_repairer_file_info(r, 0, &mut info, &mut name) }, NzbParStatus::Ok);
        assert_eq!(unsafe { CStr::from_ptr(name) }.to_str().unwrap(), "f.bin");
        assert_eq!(info.status, 2);
        assert_eq!(info.block_count, 7);
        assert_eq!(unsafe { nzbpar_repairer_file_info(r, 5, &mut info, &mut name) }, NzbParStatus::InvalidArgument);
        unsafe { nzbpar_repairer_free(r) };

        // Damage and repair through the C API.
        let mut d = data.clone();
        d[1500] ^= 1;
        std::fs::write(dir.join("f.bin"), &d).unwrap();
        let r = unsafe { nzbpar_repairer_new(cdir.as_ptr(), ptr::null()) };
        unsafe { nzbpar_repairer_set_callbacks(r, &mut msgs as *mut _ as *mut c_void, Some(progress_cb), Some(msg_cb)) };
        let mut added = 0u64;
        assert_eq!(unsafe { nzbpar_repairer_load_file(r, main.as_ptr(), &mut added) }, NzbParStatus::Ok);
        assert_eq!(added, 0);
        let vol = CString::new(dir.join("s.vol00+01.par2").to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { nzbpar_repairer_load_file(r, vol.as_ptr(), &mut added) }, NzbParStatus::Ok);
        assert_eq!(added, 1);
        assert_eq!(unsafe { nzbpar_repairer_finalize(r) }, NzbParStatus::Ok);
        assert_eq!(unsafe { nzbpar_repairer_verify(r, ptr::null_mut(), None, &mut out) }, NzbParStatus::Ok);
        assert_eq!(out.missing_blocks, 1);
        assert_eq!(out.repair_possible, 1);
        let mut blocks = 0u64;
        let extra = CString::new(dir.join("nonexistent").to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { nzbpar_repairer_add_extra_file(r, extra.as_ptr(), &mut blocks) }, NzbParStatus::Io);
        assert!(!unsafe { CStr::from_ptr(nzbpar_repairer_last_error(r)) }.to_str().unwrap().is_empty());
        assert_eq!(unsafe { nzbpar_repairer_add_extra_dir(r, cdir.as_ptr(), 0, &mut blocks) }, NzbParStatus::Ok);
        assert_eq!(unsafe { nzbpar_repairer_add_extra_dir(r, cdir.as_ptr(), 1, &mut blocks) }, NzbParStatus::Ok);
        assert_eq!(unsafe { nzbpar_repairer_repair(r, &mut blocks) }, NzbParStatus::Ok);
        assert_eq!(blocks, 1);
        assert_eq!(std::fs::read(dir.join("f.bin")).unwrap(), data);
        assert!(msgs.iter().any(|m| m.starts_with('p')));
        unsafe { nzbpar_repairer_cancel(r) };
        unsafe { nzbpar_repairer_free(r) };
        unsafe { nzbpar_repairer_free(ptr::null_mut()) };

        // Null handle paths.
        assert_eq!(unsafe { nzbpar_repairer_finalize(ptr::null_mut()) }, NzbParStatus::InvalidArgument);
        assert_eq!(unsafe { nzbpar_repairer_verify(ptr::null_mut(), ptr::null_mut(), None, ptr::null_mut()) }, NzbParStatus::InvalidArgument);
        assert_eq!(unsafe { nzbpar_repairer_repair(ptr::null_mut(), ptr::null_mut()) }, NzbParStatus::InvalidArgument);
        assert_eq!(unsafe { nzbpar_repairer_load_file(ptr::null_mut(), main.as_ptr(), ptr::null_mut()) }, NzbParStatus::InvalidArgument);
        assert_eq!(unsafe { nzbpar_repairer_file_count(ptr::null()) }, 0);
        assert_eq!(unsafe { CStr::from_ptr(nzbpar_repairer_last_error(ptr::null())) }.to_bytes(), b"");

        // Stateless helpers.
        assert_eq!(unsafe { nzbpar_crc32(data.as_ptr(), data.len()) }, crc);
        assert_eq!(unsafe { nzbpar_crc32(ptr::null(), 0) }, 0);
        assert_eq!(nzbpar_crc32_combine(crate::crc::crc32(&data[..3000]), crate::crc::crc32(&data[3000..]), 4000), crc);
        assert_eq!(nzbpar_crc32_zeros(crc, 10), crate::crc::crc32_zeros(crc, 10));
        let n = CString::new("abc.vol01+02.par2").unwrap();
        let (mut bl, mut blocks) = (0usize, 0i32);
        assert_eq!(unsafe { nzbpar_parse_par_filename(n.as_ptr(), 1, &mut bl, &mut blocks) }, 1);
        assert_eq!((bl, blocks), (3, 2));
        let n = CString::new("abc.rar").unwrap();
        assert_eq!(unsafe { nzbpar_parse_par_filename(n.as_ptr(), 1, &mut bl, &mut blocks) }, 0);
        assert_eq!(unsafe { nzbpar_parse_par_filename(ptr::null(), 1, &mut bl, &mut blocks) }, 0);
        assert_eq!(unsafe { CStr::from_ptr(nzbpar_version()) }.to_str().unwrap(), env!("CARGO_PKG_VERSION"));

        // Renamer.
        std::fs::rename(dir.join("f.bin"), dir.join("obf")).unwrap();
        let mut rmsgs: Vec<String> = Vec::new();
        let n = unsafe { nzbpar_rename_dir(cdir.as_ptr(), 1, 0, &mut rmsgs as *mut _ as *mut c_void, Some(msg_cb)) };
        assert_eq!(n, 1);
        assert!(dir.join("f.bin").exists());
        assert!(rmsgs.iter().any(|m| m.contains("Renaming")));
        assert_eq!(unsafe { nzbpar_rename_dir(ptr::null(), 0, 0, ptr::null_mut(), None) }, -1);
        let bad = CString::new(dir.join("nope").to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { nzbpar_rename_dir(bad.as_ptr(), 0, 0, ptr::null_mut(), None) }, -1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
