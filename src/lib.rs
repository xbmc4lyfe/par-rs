//! # par-rs
//!
//! A general-purpose, SIMD-accelerated PAR2 parity crate: packet parsing and deep
//! introspection (PAR1 / PAR2 / PAR3), file-name handling and obfuscated-file resolution,
//! zero-read and sliding-window verification, GF(2^16) Reed-Solomon reconstruction (batch,
//! surgical and streaming while a download is still in flight), par-renaming and set
//! creation — everything a downloader (rustyget / nzbget) or an indexer (Atlas) needs from
//! PAR2 in one crate.
//!
//! ## Module map
//!
//! | Module | Purpose |
//! |---|---|
//! | [`gf2`] | GF(2) polynomial algebra over the CRC-32 polynomial: combine / zero-pad / un-pad / un-combine, yEnc and IFSC folding, `O(1)` rolling CRC, LCM grids |
//! | [`crc`] | CRC-32 kernels (hardware / slice-by-8), streaming hasher, register-level GF(2) helpers |
//! | [`hasher`], [`md5simd`], [`parhash`] | fused CRC-32 + MD5 + 16k-MD5 hashing, 16-lane SIMD MD5, all-core slice/file hashing pool |
//! | [`gf16`], [`gf16::simd`] | GF(2^16) arithmetic, PAR2 input constants, Vandermonde solving, NEON / SSSE3 / AVX2 / AVX-512 kernels |
//! | [`packet`] | tolerant, resynchronising, lazy PAR2 packet parser and packet encoders |
//! | [`inspect`] | zero-copy deep introspection of all 12 PAR2 v2.0 packet types, PAR1 / PAR3 headers, creator fingerprinting, `.volNNN+MM.par2` analysis |
//! | [`par2`] | indexer-facing `Inventory` / `Par2File` summary of a par2 buffer |
//! | [`bridge`] | obfuscated-file resolution: size chains, 16 KiB MD5, folded CRC vs IFSC, RAR5 volume numbers |
//! | [`verify`] | in-memory slice verification with rolling-CRC discovery of misplaced slices and repair assessment |
//! | [`repair`] | in-memory batch / surgical Reed-Solomon repair with the exponent-0 fast path, and multi-file disk repair |
//! | [`stream`] | streaming syndrome bank, out-of-order yEnc byte-range slice assembler and early-cutoff solver |
//! | [`filenames`] | `.par2` / `.volXX+YY.par2` parsing, collection grouping, volume selection heuristics |
//! | [`twin`] | set fingerprinting and twin / near-twin classification |
//! | [`damage`] | download hole tracking, damage projection, article-CRC based quick verification |
//! | [`scanner`] | aligned + sliding-window block scanner with CRC hash index and MD5 confirmation |
//! | [`reed_solomon`] | recovery planning, matrix inversion, chunked multi-threaded streaming engine |
//! | [`repairer`] | `Par2Repairer`: load, verify, locate blocks, repair on disk |
//! | [`streaming`] | repair-while-downloading for a downloader: syndrome accumulation, live slice tracking, `.vol` unpause scheduling |
//! | [`renamer`] | `ParRenamer`: restore obfuscated file names from PAR2 metadata |
//! | [`create`](mod@create) | PAR2 set creation (in memory or index + volumes on disk) |
//! | [`ffi`] | C ABI |
//!
//! ## Quick start (downloader)
//!
//! ```no_run
//! use par_rs::{Par2Repairer, RepairOptions, NullObserver, RepairResult};
//! let mut r = Par2Repairer::new("/downloads/release", RepairOptions::default());
//! r.load_par2_set(std::path::Path::new("/downloads/release/release.par2"))?;
//! r.finalize()?;
//! let verdict = r.verify(None, &mut NullObserver)?;
//! if verdict.repair_needed {
//!     match r.repair(&mut NullObserver)? {
//!         RepairResult::Repaired { blocks_recovered, .. } => println!("recovered {blocks_recovered} blocks"),
//!         RepairResult::NotNeeded => {}
//!     }
//! }
//! # Ok::<(), par_rs::RepairError>(())
//! ```
//!
//! ## Quick start (indexer)
//!
//! ```
//! let inv = par_rs::par2::inventory(b"not a par2 file");
//! assert!(inv.files.is_empty());
//! let report = par_rs::inspect::inspect_par2(b"PAR2\0PKT garbage", false);
//! assert_eq!(report.packets.len(), 0);
//! ```

#![cfg_attr(not(test), deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// Lint policy: the modules that parse untrusted input or were written for the unified
// specification (`gf2`, `par2`, `inspect`, `bridge`, `verify`, `repair`, `stream`) compile with
// indexing, `unwrap`, `expect` and `panic!` denied. The older engine modules predate that rule and
// carry a module-level allow; they are fuzz- and differential-tested instead.
mod bytes;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod crc;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod create;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod damage;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod ffi;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod filenames;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod gf16;
pub mod gf2;
pub mod inspect;
pub mod par2;
pub mod bridge;
pub mod verify;
pub mod repair;
pub mod stream;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod hasher;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod md5simd;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod packet;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod parhash;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod reed_solomon;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod renamer;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod repairer;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod scanner;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod streaming;
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod twin;

// The GF(2) algebra re-exported at the root follows `gf2`'s signatures (`crc32_zeros(len)`,
// `crc32_combine(crc1, crc2, len2: usize)`); the older register-level variants with other
// signatures remain available under `crc::`.
pub use crc::{Crc32, Crc32Combiner, WindowTable};
pub use gf2::{
    Crc32Shift, FoldError, GF2_ORDER, GF2_POLY, RollingCrc32, compute_interval_crcs, crc32, crc32_combine, crc32_combine_u64, crc32_uncombine_prefix,
    crc32_uncombine_suffix, crc32_unzero, crc32_zero_unpad, crc32_zeros, fold_ifsc_crcs, fold_ifsc_crcs_with, fold_yenc_indexed_parts, fold_yenc_parts,
    ifsc_interval_crcs, lcm_grid, multmodp, x2nmodp, xpow,
};
pub use inspect::{CreatorInfo, CreatorTool, PacketKind, Par1Header, Par2FileName, Par2Inspection, Par3PacketHeader, ParFormat, VerifyMode, detect_format, inspect_par2, inspect_par2_with, parse_par2_filename};
pub use par2::{Inventory, Par2File, display_name, file_descriptions, inventory, is_base_par2};
pub use bridge::{BridgeReport, Candidate, Par2Bridge, ResolveMethod, Resolution, rar5_volume_number};
pub use verify::{FileVerification, FoundSlice, RepairAssessment, SetVerifier, SliceStatus, SourceSpec, VerificationReport};
pub use repair::{DiskFile, DiskLocation, DiskRecovery, DiskRepairPlan, DiskRepairReport, RepairPlan, repair_on_disk, repair_selected_slices, repair_slices};
pub use stream::{FileLayout, StreamEvent, StreamStatus, StreamingSliceAssembler, SyndromeBank};
pub use create::{build_set, create, create_in_memory, CreateError, CreateOptions, CreateReport, CreateStage, Par2Set, SetOptions, SourceFile, VolumeScheme};
pub use damage::{
    blocks_touched, compute_holes, par_cannot_cover, project_par_damage, quick_verify, range_covered, smart_calc_range_crc, verify_partial_file,
    verify_success_file_crc, ByteRange, DownloadStatus, FileDamage, QuickVerdict, RangeReader, Segment,
};
pub use filenames::{
    calc_completed_volume_blocks, calc_queued_volume_blocks, find_main_pars, parse_par_filename, pick_twin_volume, same_par_collection, select_more_pars,
    volume_blocks_bytes, ParName,
};
pub use gf16::simd::{Isa, Kernel};
pub use hasher::{hash_file, hash_reader, FileHasher, FileHashes};
pub use packet::{
    load_par2_bytes, load_par2_file, translate_filename_from_par2_to_local, FileDescPacket, FileId, IfscPacket, MainPacket, PacketSet, Par2Collection,
    RecoverySliceRef, ScanOptions, SetId, SliceChecksum,
};
pub use reed_solomon::{EngineConfig, RsError};
pub use renamer::{ParRenamer, RenamerEvent, RenamerOptions, RenamerReport};
pub use repairer::{
    BackupPolicy, FileStatus, Level, NullObserver, Par2Repairer, QuickInfo, QuickVerifier, RepairError, RepairObserver, RepairOptions, RepairResult,
    SourceFileState, Stage, VerifyResult,
};
pub use scanner::{scan_file, ChecksumIndex, ScanConfig, ScanReport};
pub use streaming::{
    ArticleOutcome, BitVec, BlockEvent, BlockState, EarlyRepairReport, LiveStatus, QueuedVolume, SessionOptions, SliceEvent, SliceState, StreamingOptions,
    StreamingParSession, StreamingStats, StreamingStatus, UnpauseAction, VolumeStatus,
};
pub use twin::{block_size, compare_twin_par2_data, fingerprint, par2_set, FileSig, TwinRelation};

#[cfg(test)]
mod diagnostics {
    /// Prints the detected kernels; run with `--nocapture` to inspect which SIMD paths the
    /// host (or emulator) exercises.
    #[test]
    fn print_detected_kernels() {
        println!("crc kernel: {:?}", crate::crc::kernel());
        for &isa in crate::gf16::simd::Isa::candidates() {
            println!("gf16 isa {isa}: supported={} verified={}", isa.is_supported(), crate::gf16::simd::Kernel::with_isa(isa).is_some());
        }
        println!("gf16 selected: {}", crate::gf16::simd::Kernel::detect().isa());
    }
}
