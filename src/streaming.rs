//! Streaming repair: verify and fold blocks into Reed-Solomon syndromes **while the download
//! is still running**, so that the repair at the end costs `O(missing × recovery)` instead of a
//! full pass over every file, and so that reconstruction can start the moment the damaged and
//! not-yet-arrived blocks fit within the tracked recovery blocks.
//!
//! # How it works
//!
//! For every tracked recovery exponent `e_j` the repairer keeps a syndrome buffer
//! `S_j = Σ_{verified i} C_i^{e_j} · D_i` (split-plane layout, `slice_size` bytes each). As the
//! downloader writes articles it reports them with [`Par2Repairer::streaming_segment_written`]
//! (data on disk) or [`Par2Repairer::streaming_segment_data`] (decoded article in memory).
//! Once a block is fully covered by successful segments it is verified against its IFSC
//! CRC-32 + MD5 and multiplied into every syndrome. Failed articles mark their blocks damaged;
//! a later successful retry re-verifies them.
//!
//! At repair time the present blocks are already folded in, so the engine only has to add the
//! recovery slices (`S_j + R_{e_j}`) and apply `A⁻¹`—reading `k` recovery slices instead of
//! all `n` input slices.
//!
//! # What streaming cannot do
//!
//! PAR2 is one code over the whole set: every block that is neither verified nor covered by a
//! recovery block is an unknown. Blocks that have not been downloaded yet count as missing, so
//! an archive part can only be reconstructed early when `damaged + pending <= recovery`.
//! [`StreamingStatus::repair_possible_now`] reports exactly that condition.
//!
//! Recovery volumes often arrive *after* the data files. Syndromes do not need the recovery
//! packets themselves, only their exponents, so tracking can start from the expected exponents
//! (for example, `0..N` from the `.volXX+YY` names) before any volume is loaded.
//!
//! # Repair-while-downloading session
//!
//! [`StreamingParSession`] is the thread-safe (`Send + Sync`, cloneable) integration point for
//! NZBGet's `ArticleWriter` / `DirectRenamer` / `DirectUnpack` / `StreamRepairController`:
//!
//! 1. **Live slice state machine + `.vol` unpause scheduler**—every slice is `Unarrived`,
//!    `PartiallyArrived`, `VerifiedGood` or `Damaged`; permanent article failures mark slices
//!    damaged and immediately run the two-stage greedy volume selector over the paused
//!    `.volXX+YY.par2` files so the exact recovery volumes download concurrently.
//! 2. **In-flight syndrome accumulator**—completed slices (from the `ArticleCache` bytes or
//!    the target file) are hashed lock-free on the calling thread (with a `crc32_combine`
//!    pre-check over the article CRCs) and folded into pre-allocated syndrome slots; each slot
//!    carries a `folded_mask` bitset so slots created when a late volume arrives can be
//!    back-filled from disk for exactly the slices they lack.
//! 3. **Mid-download volume repair**—Mode A splices donor/twin bytes into holes slice by slice
//!    (works even when `D + U > R`); Mode B performs an early Reed-Solomon cutover computing only
//!    the `A⁻¹` rows of the requested files once `D + U <= R`.
//! 4. **Concurrency**—bounded admission for payload work, one bookkeeping mutex
//!    (never held during hashing or I/O), one mutex per
//!    syndrome slot (striped folding) and an optional bounded folder pool that never blocks the
//!    article writers (full queue → inline fold).

use crate::crc::{crc32_combine, crc32_zeros};
use crate::damage::{ByteRange, normalize_ranges, range_covered};
use crate::gf16::simd::{Kernel, MAX_MULTI, Plane, PlaneMut};
use crate::gf16::{input_constant_logs, rs_coefficient};
use crate::hasher::slice_checksums;
use crate::packet::{FileSource, read_exact_at};
use crate::repairer::{
    BlockLocation, FileStatus, Level, Par2Repairer, RepairError, RepairObserver, io_ctx,
    write_all_at,
};
use crate::scanner::{BlockRef, ChecksumEntry, entries_for_file};
use std::collections::{BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Options for [`Par2Repairer::enable_streaming`].
#[derive(Clone, Debug)]
pub struct StreamingOptions {
    /// Recovery exponents to track. `None`: the exponents of the recovery slices loaded so
    /// far, or `0..expected_recovery_blocks` when none are loaded yet.
    pub exponents: Option<Vec<u32>>,
    /// Number of recovery blocks expected to arrive (used when `exponents` is `None` and no
    /// recovery packet has been loaded).
    pub expected_recovery_blocks: u32,
    /// Memory budget for syndromes; tracking is capped at `max_memory_bytes / slice_size`
    /// exponents (lowest first).
    pub max_memory_bytes: u64,
    /// Threads for folding a block into the syndromes (0 = all cores).
    pub threads: usize,
}

impl Default for StreamingOptions {
    fn default() -> Self {
        Self {
            exponents: None,
            expected_recovery_blocks: 0,
            max_memory_bytes: 512 << 20,
            threads: 0,
        }
    }
}

/// State of one input block during streaming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockState {
    /// Not (fully) arrived yet.
    Pending,
    /// Verified and folded into the syndromes.
    Verified,
    /// Arrived but failed verification, or its article failed.
    Damaged,
}

/// A block whose state changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockEvent {
    /// File index (Main-packet order).
    pub file_index: usize,
    /// Block index within the file.
    pub block_index: u32,
    /// New state.
    pub state: BlockState,
}

/// Streaming progress summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamingStatus {
    /// Exponents with a syndrome buffer.
    pub tracked_exponents: usize,
    /// Tracked exponents whose recovery slice is loaded (usable right now).
    pub usable_recovery: usize,
    /// Recovery slices loaded (tracked or not).
    pub recovery_loaded: usize,
    /// Blocks verified and folded.
    pub verified_blocks: u64,
    /// Blocks known to be bad.
    pub damaged_blocks: u64,
    /// Blocks not yet arrived.
    pub pending_blocks: u64,
    /// Total input blocks.
    pub total_blocks: u64,
    /// `damaged + pending <= usable_recovery`: a repair started now would succeed, even for
    /// files that have not finished downloading.
    pub repair_possible_now: bool,
    /// Recovery blocks still needed to repair right now (0 when possible).
    pub blocks_needed_now: u64,
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamingStats {
    /// Blocks folded into the syndromes.
    pub blocks_folded: u64,
    /// Blocks that failed CRC/MD5 verification on arrival.
    pub blocks_rejected: u64,
    /// Bytes of block data multiplied into syndromes.
    pub bytes_folded: u64,
}

struct Staged {
    buf: Vec<u8>,
    ranges: Vec<ByteRange>,
}

/// Incremental syndrome accumulator (crate-internal; exposed through `Par2Repairer`).
pub(crate) struct SyndromeState {
    pub(crate) exponents: Vec<u32>,
    pub(crate) syndromes: Vec<Vec<u8>>,
    pub(crate) accumulated: Vec<bool>,
    pub(crate) damaged: Vec<bool>,
    /// Successful segment coverage per file (absolute offsets).
    coverage: Vec<Vec<ByteRange>>,
    staged: HashMap<usize, Staged>,
    logs: Vec<u16>,
    threads: usize,
    max_memory: u64,
    pub(crate) stats: StreamingStats,
}

impl SyndromeState {
    /// Fold `data` (natural layout, zero padded to the slice size) of global block `g` into
    /// the syndromes `range`.
    fn accumulate_into(
        &mut self,
        kernel: &crate::gf16::simd::Kernel,
        g: usize,
        data: &[u8],
        range: std::ops::Range<usize>,
        ss: usize,
    ) {
        if range.is_empty() {
            return;
        }
        let words = ss / 2;
        let mut src = vec![0u8; ss];
        {
            let (lo, hi) = src.split_at_mut(words);
            let n = data.len().min(ss) / 2;
            kernel.deinterleave(&data[..2 * n], &mut lo[..n], &mut hi[..n]);
            if data.len().min(ss) % 2 == 1 {
                lo[n] = data[2 * n];
            }
        }
        let logbase = self.logs[g];
        let exps = &self.exponents;
        let syn = &mut self.syndromes[range.clone()];
        let exps = &exps[range];
        let k = syn.len();
        let threads = if self.threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            self.threads
        };
        let threads = threads.clamp(1, k.div_ceil(MAX_MULTI).max(1));
        let per = k.div_ceil(threads);
        let src_plane = Plane::from_halves(&src);
        std::thread::scope(|s| {
            for (syn_chunk, exp_chunk) in syn.chunks_mut(per).zip(exps.chunks(per)) {
                s.spawn(move || {
                    let mut coeffs = [0u16; MAX_MULTI];
                    for (group, egroup) in syn_chunk
                        .chunks_mut(MAX_MULTI)
                        .zip(exp_chunk.chunks(MAX_MULTI))
                    {
                        for (c, &e) in coeffs.iter_mut().zip(egroup) {
                            *c = rs_coefficient(logbase, e);
                        }
                        let mut planes: Vec<PlaneMut> =
                            group.iter_mut().map(|b| PlaneMut::from_halves(b)).collect();
                        kernel.mul_acc_multi_split(&mut planes, src_plane, &coeffs[..egroup.len()]);
                    }
                });
            }
        });
        self.stats.bytes_folded += ss as u64;
    }
}

impl Par2Repairer {
    /// Turn on streaming mode (after [`finalize`](Self::finalize)). Allocates one
    /// `slice_size` buffer per tracked exponent.
    pub fn enable_streaming(
        &mut self,
        opts: &StreamingOptions,
    ) -> Result<StreamingStatus, RepairError> {
        if !self.finalized {
            return Err(RepairError::NotFinalized);
        }
        let ss = self.block_size() as usize;
        let total = self.locations.len();
        let mut exps: Vec<u32> = match &opts.exponents {
            Some(e) => e.clone(),
            None if !self.packets.recovery.is_empty() => {
                self.packets.recovery.keys().copied().collect()
            }
            None => (0..opts.expected_recovery_blocks).collect(),
        };
        exps.sort_unstable();
        exps.dedup();
        let cap = if ss == 0 {
            0
        } else {
            (opts.max_memory_bytes / ss as u64) as usize
        };
        exps.truncate(cap.min(exps.len()));
        let logs = input_constant_logs(total).map_err(|_| RepairError::Singular)?;
        let mut st = SyndromeState {
            syndromes: exps.iter().map(|_| vec![0u8; ss]).collect(),
            exponents: exps,
            accumulated: vec![false; total],
            damaged: vec![false; total],
            coverage: self.files.iter().map(|_| Vec::new()).collect(),
            staged: HashMap::new(),
            logs,
            threads: opts.threads,
            max_memory: opts.max_memory_bytes,
            stats: StreamingStats::default(),
        };
        // Blocks already located (for example, by a `verify()` before enabling) are folded now.
        let located: Vec<usize> = (0..total)
            .filter(|&g| self.locations[g].is_some())
            .collect();
        for g in located {
            let data = self.read_located_block(g)?;
            st.accumulate_into(&self.options.kernel, g, &data, 0..st.syndromes.len(), ss);
            st.accumulated[g] = true;
            st.stats.blocks_folded += 1;
        }
        self.streaming = Some(st);
        Ok(self.streaming_status().expect("just enabled"))
    }

    /// Whether streaming mode is enabled.
    pub fn streaming_enabled(&self) -> bool {
        self.streaming.is_some()
    }

    /// Streaming counters.
    pub fn streaming_stats(&self) -> Option<StreamingStats> {
        self.streaming.as_ref().map(|s| s.stats)
    }

    /// Current streaming summary.
    pub fn streaming_status(&self) -> Option<StreamingStatus> {
        let st = self.streaming.as_ref()?;
        let total = self.locations.len() as u64;
        let verified = self.locations.iter().filter(|l| l.is_some()).count() as u64;
        let damaged = (0..self.locations.len())
            .filter(|&g| self.locations[g].is_none() && st.damaged[g])
            .count() as u64;
        let pending = total - verified - damaged;
        let usable = st
            .exponents
            .iter()
            .filter(|e| self.packets.recovery.contains_key(e))
            .count();
        let missing = damaged + pending;
        Some(StreamingStatus {
            tracked_exponents: st.exponents.len(),
            usable_recovery: usable,
            recovery_loaded: self.packets.recovery.len(),
            verified_blocks: verified,
            damaged_blocks: damaged,
            pending_blocks: pending,
            total_blocks: total,
            repair_possible_now: missing <= usable as u64,
            blocks_needed_now: missing.saturating_sub(usable as u64),
        })
    }

    /// State of one block.
    pub fn block_state(&self, file_index: usize, block_index: u32) -> Option<BlockState> {
        let st = self.streaming.as_ref()?;
        let f = self.files.get(file_index)?;
        if block_index >= f.block_count {
            return None;
        }
        let g = f.first_block + block_index as usize;
        Some(if self.locations[g].is_some() {
            BlockState::Verified
        } else if st.damaged[g] {
            BlockState::Damaged
        } else {
            BlockState::Pending
        })
    }

    /// Track additional recovery exponents (for example, when more volumes are queued). Already
    /// verified blocks are re-read from disk and folded into the new syndromes. Returns the
    /// number of exponents now tracked.
    pub fn streaming_track_exponents(&mut self, more: &[u32]) -> Result<usize, RepairError> {
        let ss = self.block_size() as usize;
        let Some(st) = self.streaming.as_mut() else {
            return Err(RepairError::NotFinalized);
        };
        let cap = if ss == 0 {
            0
        } else {
            (st.max_memory / ss as u64) as usize
        };
        let mut new: Vec<u32> = more
            .iter()
            .copied()
            .filter(|e| !st.exponents.contains(e))
            .collect();
        new.sort_unstable();
        new.dedup();
        let room = cap.saturating_sub(st.exponents.len());
        new.truncate(room);
        if new.is_empty() {
            return Ok(st.exponents.len());
        }
        let first_new = st.exponents.len();
        for e in &new {
            st.exponents.push(*e);
            st.syndromes.push(vec![0u8; ss]);
        }
        let range = first_new..st.exponents.len();
        let accumulated: Vec<usize> = (0..st.accumulated.len())
            .filter(|&g| st.accumulated[g])
            .collect();
        for g in accumulated {
            let data = self.read_located_block(g)?;
            let st = self.streaming.as_mut().expect("streaming");
            st.accumulate_into(&self.options.kernel, g, &data, range.clone(), ss);
        }
        Ok(self.streaming.as_ref().expect("streaming").exponents.len())
    }

    /// Report an article written to the target file of `file_index` at `offset`
    /// (`success == false` for a failed article). Blocks that became complete are read from
    /// the target file, verified, and folded. Returns the blocks whose state changed.
    pub fn streaming_segment_written(
        &mut self,
        file_index: usize,
        offset: u64,
        len: u64,
        success: bool,
    ) -> Result<Vec<BlockEvent>, RepairError> {
        self.streaming_segment(file_index, offset, len, success, None)
    }

    /// Report a decoded article held in memory (also assumed to be written to the target file
    /// at the same offset). Blocks completed purely from staged data undergo verification
    /// without touching the disk.
    pub fn streaming_segment_data(
        &mut self,
        file_index: usize,
        offset: u64,
        data: &[u8],
    ) -> Result<Vec<BlockEvent>, RepairError> {
        self.streaming_segment(file_index, offset, data.len() as u64, true, Some(data))
    }

    /// Report that a failed article's byte range cannot arrive.
    pub fn streaming_segment_failed(
        &mut self,
        file_index: usize,
        offset: u64,
        len: u64,
    ) -> Result<Vec<BlockEvent>, RepairError> {
        self.streaming_segment(file_index, offset, len, false, None)
    }

    fn streaming_segment(
        &mut self,
        file_index: usize,
        offset: u64,
        len: u64,
        success: bool,
        data: Option<&[u8]>,
    ) -> Result<Vec<BlockEvent>, RepairError> {
        if self.streaming.is_none() {
            return Err(RepairError::NotFinalized);
        }
        let Some(f) = self.files.get(file_index) else {
            return Ok(Vec::new());
        };
        let ss = self.block_size();
        let file_len = f.file_length;
        let first_block = f.first_block;
        let block_count = f.block_count as u64;
        let target = f.target_path.clone();
        let mut events = Vec::new();
        if len == 0 || ss == 0 || offset >= file_len {
            return Ok(events);
        }
        let end = (offset + len).min(file_len);
        let b0 = offset / ss;
        let b1 = ((end - 1) / ss).min(block_count.saturating_sub(1));
        if !success {
            let st = self.streaming.as_mut().expect("streaming");
            for b in b0..=b1 {
                let g = first_block + b as usize;
                if self.locations[g].is_none() && !st.damaged[g] {
                    st.damaged[g] = true;
                    st.staged.remove(&g);
                    events.push(BlockEvent {
                        file_index,
                        block_index: b as u32,
                        state: BlockState::Damaged,
                    });
                }
            }
            return Ok(events);
        }
        // Record coverage.
        {
            let st = self.streaming.as_mut().expect("streaming");
            let cov = &mut st.coverage[file_index];
            cov.push(ByteRange::new(offset as i64, (end - offset) as i64));
            if cov.len() > 64 {
                *cov = normalize_ranges(cov);
            }
            // Stage in-memory bytes per block.
            if let Some(d) = data {
                for b in b0..=b1 {
                    let g = first_block + b as usize;
                    if self.locations[g].is_some() {
                        continue;
                    }
                    let bstart = b * ss;
                    let bend = (bstart + ss).min(file_len);
                    let s = offset.max(bstart);
                    let e = end.min(bend);
                    if s >= e {
                        continue;
                    }
                    let staged = st.staged.entry(g).or_insert_with(|| Staged {
                        buf: vec![0u8; (bend - bstart) as usize],
                        ranges: Vec::new(),
                    });
                    let rel = (s - bstart) as usize;
                    staged.buf[rel..rel + (e - s) as usize]
                        .copy_from_slice(&d[(s - offset) as usize..(e - offset) as usize]);
                    staged
                        .ranges
                        .push(ByteRange::new((s - bstart) as i64, (e - s) as i64));
                }
            }
        }
        let verifiable = self.checksums[file_index].is_some();
        for b in b0..=b1 {
            let g = first_block + b as usize;
            if self.locations[g].is_some() {
                continue;
            }
            let bstart = b * ss;
            let bend = (bstart + ss).min(file_len);
            let covered = {
                let st = self.streaming.as_mut().expect("streaming");
                let cov = &mut st.coverage[file_index];
                *cov = normalize_ranges(cov);
                range_covered(cov, bstart as i64, bend as i64)
            };
            if !covered {
                continue;
            }
            if !verifiable {
                // Without IFSC only the whole file can be checked.
                continue;
            }
            // Obtain the block bytes: staged if complete, else from the target file.
            let block: Vec<u8> = {
                let st = self.streaming.as_mut().expect("streaming");
                match st.staged.remove(&g) {
                    Some(staged)
                        if range_covered(
                            &normalize_ranges(&staged.ranges),
                            0,
                            (bend - bstart) as i64,
                        ) =>
                    {
                        staged.buf
                    }
                    _ => {
                        let f = File::open(&target)
                            .map_err(io_ctx(format!("opening {}", target.display())))?;
                        let mut buf = vec![0u8; (bend - bstart) as usize];
                        read_exact_at(&f, bstart, &mut buf)
                            .map_err(io_ctx(format!("reading {}", target.display())))?;
                        buf
                    }
                }
            };
            let ok = self.streaming_verify_and_fold(file_index, b as u32, &block, &target)?;
            events.push(BlockEvent {
                file_index,
                block_index: b as u32,
                state: if ok {
                    BlockState::Verified
                } else {
                    BlockState::Damaged
                },
            });
        }
        if !verifiable
            && range_covered(
                &self.streaming.as_ref().expect("streaming").coverage[file_index],
                0,
                file_len as i64,
            )
        {
            events.extend(self.streaming_file_complete(file_index)?);
        }
        Ok(events)
    }

    /// Verify a complete block against its checksums; fold it when correct.
    fn streaming_verify_and_fold(
        &mut self,
        file_index: usize,
        b: u32,
        block: &[u8],
        target: &std::path::Path,
    ) -> Result<bool, RepairError> {
        let ss = self.block_size() as usize;
        let g = self.files[file_index].first_block + b as usize;
        let entry = self.checksums[file_index].as_ref().map(|cs| cs[b as usize]);
        let ok = match entry {
            Some(e) => {
                let mut padded = block.to_vec();
                padded.resize(ss, 0);
                let (crc, m) = slice_checksums(&padded);
                crc == e.crc32 && m == e.md5
            }
            None => false,
        };
        let st = self.streaming.as_mut().expect("streaming");
        if !ok {
            st.damaged[g] = true;
            st.stats.blocks_rejected += 1;
            return Ok(false);
        }
        st.damaged[g] = false;
        let n = st.syndromes.len();
        st.accumulate_into(&self.options.kernel, g, block, 0..n, ss);
        st.accumulated[g] = true;
        st.stats.blocks_folded += 1;
        let di = self.disk_file_index_pub(target);
        self.set_location_pub(
            BlockRef {
                file_index: file_index as u32,
                block_index: b,
            },
            BlockLocation {
                file: di,
                offset: b as u64 * ss as u64,
            },
        );
        let f = &mut self.files[file_index];
        if f.available_blocks == f.block_count {
            f.status = FileStatus::Complete;
            f.complete_file = Some(f.target_path.clone());
            f.target_exists = true;
        }
        Ok(true)
    }

    /// Declare a file fully written. Needed for files without IFSC packets (verified by whole
    /// file MD5 only); harmless otherwise. Returns the blocks whose state changed.
    pub fn streaming_file_complete(
        &mut self,
        file_index: usize,
    ) -> Result<Vec<BlockEvent>, RepairError> {
        if self.streaming.is_none() {
            return Err(RepairError::NotFinalized);
        }
        let Some(f) = self.files.get(file_index) else {
            return Ok(Vec::new());
        };
        let mut events = Vec::new();
        if self.checksums[file_index].is_some() || f.status == FileStatus::Complete {
            return Ok(events);
        }
        let target = f.target_path.clone();
        let (first, count, expected_len, expected_md5) =
            (f.first_block, f.block_count, f.file_length, f.hash_full);
        let h = crate::hasher::hash_file(&target)
            .map_err(io_ctx(format!("hashing {}", target.display())))?;
        let ok = h.len == expected_len && h.md5_full == expected_md5;
        if count == 0 {
            if ok {
                self.files[file_index].status = FileStatus::Complete;
                self.files[file_index].complete_file = Some(target);
            }
            return Ok(events);
        }
        let ss = self.block_size();
        if ok {
            let di = self.disk_file_index_pub(&target);
            let fh =
                File::open(&target).map_err(io_ctx(format!("opening {}", target.display())))?;
            for b in 0..count {
                let g = first + b as usize;
                if self.locations[g].is_some() {
                    continue;
                }
                let off = b as u64 * ss;
                let len = (expected_len - off).min(ss) as usize;
                let mut buf = vec![0u8; len];
                read_exact_at(&fh, off, &mut buf)
                    .map_err(io_ctx(format!("reading {}", target.display())))?;
                let st = self.streaming.as_mut().expect("streaming");
                let n = st.syndromes.len();
                st.accumulate_into(&self.options.kernel, g, &buf, 0..n, ss as usize);
                st.accumulated[g] = true;
                st.damaged[g] = false;
                st.stats.blocks_folded += 1;
                self.set_location_pub(
                    BlockRef {
                        file_index: file_index as u32,
                        block_index: b,
                    },
                    BlockLocation {
                        file: di,
                        offset: off,
                    },
                );
                events.push(BlockEvent {
                    file_index,
                    block_index: b,
                    state: BlockState::Verified,
                });
            }
            let f = &mut self.files[file_index];
            f.status = FileStatus::Complete;
            f.complete_file = Some(target);
            f.target_exists = true;
        } else {
            let st = self.streaming.as_mut().expect("streaming");
            for b in 0..count {
                let g = first + b as usize;
                if self.locations[g].is_none() && !st.damaged[g] {
                    st.damaged[g] = true;
                    events.push(BlockEvent {
                        file_index,
                        block_index: b,
                        state: BlockState::Damaged,
                    });
                }
            }
            self.files[file_index].status = FileStatus::Damaged;
        }
        Ok(events)
    }

    /// Fold every located but not yet accumulated block (used before a streaming repair).
    pub(crate) fn streaming_backfill(
        &mut self,
        observer: &mut dyn RepairObserver,
    ) -> Result<(), RepairError> {
        let ss = self.block_size() as usize;
        let Some(st) = self.streaming.as_ref() else {
            return Ok(());
        };
        let todo: Vec<usize> = (0..self.locations.len())
            .filter(|&g| self.locations[g].is_some() && !st.accumulated[g])
            .collect();
        if todo.is_empty() {
            return Ok(());
        }
        observer.message(
            Level::Detail,
            &format!(
                "Folding {} late blocks into the streamed syndromes",
                todo.len()
            ),
        );
        for g in todo {
            let data = self.read_located_block(g)?;
            let st = self.streaming.as_mut().expect("streaming");
            let n = st.syndromes.len();
            st.accumulate_into(&self.options.kernel, g, &data, 0..n, ss);
            st.accumulated[g] = true;
            st.damaged[g] = false;
            st.stats.blocks_folded += 1;
        }
        Ok(())
    }

    /// In streaming mode, probe the not-yet-verified blocks of a target file at their natural
    /// offsets (the downloader writes articles in place, so a sliding scan is unnecessary).
    pub(crate) fn streaming_probe_remaining(
        &mut self,
        file_index: usize,
    ) -> Result<(), RepairError> {
        let ss = self.block_size();
        let f = &self.files[file_index];
        let target = f.target_path.clone();
        let (first, count, file_len) = (f.first_block, f.block_count, f.file_length);
        if self.checksums[file_index].is_none() {
            let _ = self.streaming_file_complete(file_index)?;
            return Ok(());
        }
        let Ok(fh) = File::open(&target) else {
            return Ok(());
        };
        let disk_len = fh.metadata().map(|m| m.len()).unwrap_or(0);
        for b in 0..count {
            let g = first + b as usize;
            if self.locations[g].is_some() {
                continue;
            }
            let off = b as u64 * ss;
            if off >= disk_len {
                break;
            }
            let len = (file_len - off).min(ss).min(disk_len - off) as usize;
            let mut buf = vec![0u8; len];
            if read_exact_at(&fh, off, &mut buf).is_err() {
                break;
            }
            self.streaming_verify_and_fold(file_index, b, &buf, &target)?;
        }
        if self.files[file_index].status != FileStatus::Complete {
            self.files[file_index].status = FileStatus::Damaged;
        }
        Ok(())
    }

    /// Read the data of a located block from disk (zero padded to the slice size).
    fn read_located_block(&self, g: usize) -> Result<Vec<u8>, RepairError> {
        let ss = self.block_size() as usize;
        let loc = self.locations[g].clone().expect("located block");
        let path = &self.disk_files[loc.file];
        let f = File::open(path).map_err(io_ctx(format!("opening {}", path.display())))?;
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let avail = len.saturating_sub(loc.offset).min(ss as u64) as usize;
        let mut buf = vec![0u8; ss];
        if avail > 0 {
            read_exact_at(&f, loc.offset, &mut buf[..avail])
                .map_err(io_ctx(format!("reading {}", path.display())))?;
        }
        Ok(buf)
    }

    /// Wipe syndromes and coverage (for example, when the host restarts a download).
    pub fn disable_streaming(&mut self) {
        self.streaming = None;
    }

    /// Number of recovery blocks still needed to repair right now in streaming mode (pending
    /// blocks count as missing), or the plain estimate otherwise.
    pub fn blocks_needed_now(&self) -> u64 {
        self.streaming_status()
            .map(|s| s.blocks_needed_now)
            .unwrap_or_else(|| self.blocks_needed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{CreateOptions, SourceFile, VolumeScheme, create};
    use crate::repairer::{NullObserver, RepairOptions, RepairResult};
    use std::path::{Path, PathBuf};

    fn rnd(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 43) as u8
            })
            .collect()
    }

    struct Fx {
        dir: PathBuf,
        files: Vec<(String, Vec<u8>)>,
        main: PathBuf,
    }

    fn fixture(tag: &str, sizes: &[usize], slice: u64, recovery: u32) -> Fx {
        let dir = std::env::temp_dir().join(format!("par-rs-stream-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut files = Vec::new();
        let mut sources = Vec::new();
        for (i, &n) in sizes.iter().enumerate() {
            let name = format!("part{i}.rar");
            let data = rnd(n, 5000 + i as u64);
            std::fs::write(dir.join(&name), &data).unwrap();
            sources.push(SourceFile::new(dir.join(&name)));
            files.push((name, data));
        }
        let opts = CreateOptions {
            slice_size: slice,
            recovery_blocks: recovery,
            volumes: VolumeScheme::Exponential,
            ..CreateOptions::default()
        };
        create(&sources, &dir, "set", &opts, None, &mut |_, _, _| {}).unwrap();
        // Remove the data files: the "download" recreates them.
        for (n, _) in &files {
            std::fs::remove_file(dir.join(n)).unwrap();
        }
        Fx {
            main: dir.join("set.par2"),
            dir,
            files,
        }
    }

    fn check_all(fx: &Fx) {
        for (n, d) in &fx.files {
            assert_eq!(std::fs::read(fx.dir.join(n)).unwrap(), *d, "{n}");
        }
    }

    fn write_at(path: &Path, off: u64, data: &[u8]) {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            f.write_all_at(data, off).unwrap();
        }
        #[cfg(not(unix))]
        {
            use std::io::{Seek, Write};
            let mut f = f;
            f.seek(std::io::SeekFrom::Start(off)).unwrap();
            f.write_all(data).unwrap();
        }
    }

    fn file_index(r: &Par2Repairer, name: &str) -> usize {
        r.source_files()
            .iter()
            .position(|f| f.target_filename == name)
            .unwrap()
    }

    /// Simulated article order: a deterministic shuffle of segment indices.
    fn shuffled(n: usize, seed: u64) -> Vec<usize> {
        let mut v: Vec<usize> = (0..n).collect();
        let mut s = seed | 1;
        for i in (1..n).rev() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            v.swap(i, (s % (i as u64 + 1)) as usize);
        }
        v
    }

    #[derive(Default)]
    struct Msgs(Vec<String>);
    impl RepairObserver for Msgs {
        fn message(&mut self, _l: Level, t: &str) {
            self.0.push(t.to_string());
        }
    }

    #[test]
    fn download_simulation_with_failed_articles_on_disk() {
        let fx = fixture("disk", &[50_000, 20_000, 7_777], 1000, 12);
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        let st = r.enable_streaming(&StreamingOptions::default()).unwrap();
        assert_eq!(st.tracked_exponents, 12);
        assert_eq!(st.pending_blocks, 50 + 20 + 8);
        assert!(!st.repair_possible_now);
        assert!(r.streaming_enabled());

        let article = 700usize;
        let mut events = Vec::new();
        let mut failed_total = 0;
        for (name, data) in &fx.files {
            let fi = file_index(&r, name);
            let path = fx.dir.join(name);
            std::fs::File::create(&path)
                .unwrap()
                .set_len(data.len() as u64)
                .unwrap();
            let n = data.len().div_ceil(article);
            for si in shuffled(n, 99) {
                let off = si * article;
                let end = (off + article).min(data.len());
                // Every eleventh article of part0 fails.
                let fail = name == "part0.rar" && si % 11 == 3;
                if fail {
                    failed_total += 1;
                    events.extend(
                        r.streaming_segment_failed(fi, off as u64, (end - off) as u64)
                            .unwrap(),
                    );
                } else {
                    write_at(&path, off as u64, &data[off..end]);
                    events.extend(
                        r.streaming_segment_written(fi, off as u64, (end - off) as u64, true)
                            .unwrap(),
                    );
                }
            }
        }
        assert!(failed_total > 0);
        let st = r.streaming_status().unwrap();
        assert_eq!(st.pending_blocks, 0);
        assert!(st.damaged_blocks > 0 && st.damaged_blocks <= 12, "{st:?}");
        assert_eq!(st.verified_blocks + st.damaged_blocks, 78);
        assert!(st.repair_possible_now);
        assert_eq!(st.blocks_needed_now, 0);
        assert_eq!(r.blocks_needed_now(), 0);
        let verified_events = events
            .iter()
            .filter(|e| e.state == BlockState::Verified)
            .count() as u64;
        assert_eq!(verified_events, st.verified_blocks);
        assert_eq!(
            r.block_state(file_index(&r, "part1.rar"), 0),
            Some(BlockState::Verified)
        );
        assert_eq!(r.block_state(0, 9999), None);
        let stats = r.streaming_stats().unwrap();
        assert_eq!(stats.blocks_folded, st.verified_blocks);
        assert_eq!(stats.blocks_rejected, 0);
        // part1 and part2 are complete already; part0 is damaged.
        assert_eq!(
            r.source_files()[file_index(&r, "part1.rar")].status,
            FileStatus::Complete
        );
        assert_ne!(
            r.source_files()[file_index(&r, "part0.rar")].status,
            FileStatus::Complete
        );

        // verify() must not rescan: only probes remaining blocks, which are the failed ones.
        let mut obs = Msgs::default();
        let v = r.verify(None, &mut obs).unwrap();
        assert_eq!(v.missing_blocks, st.damaged_blocks);
        assert!(v.repair_possible);
        assert_eq!(
            r.source_files()[file_index(&r, "part0.rar")].status,
            FileStatus::Damaged
        );
        // The probe re-read only the unverified blocks; nothing new was folded.
        assert_eq!(
            r.streaming_stats().unwrap().blocks_folded,
            st.verified_blocks
        );
        let res = r.repair(&mut obs).unwrap();
        assert!(matches!(res, RepairResult::Repaired { .. }));
        assert!(
            obs.0.iter().any(|m| m.contains("using streamed syndromes")),
            "{:?}",
            obs.0
        );
        check_all(&fx);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn in_memory_articles_corrupt_data_and_retries() {
        let fx = fixture("mem", &[30_000, 12_345], 1024, 10);
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        r.enable_streaming(&StreamingOptions {
            threads: 2,
            ..StreamingOptions::default()
        })
        .unwrap();
        let article = 500usize;
        let mut rejected = 0;
        for (name, data) in &fx.files {
            let fi = file_index(&r, name);
            let path = fx.dir.join(name);
            std::fs::File::create(&path)
                .unwrap()
                .set_len(data.len() as u64)
                .unwrap();
            let n = data.len().div_ceil(article);
            for si in shuffled(n, 7) {
                let off = si * article;
                let end = (off + article).min(data.len());
                let mut chunk = data[off..end].to_vec();
                // Article 4 of part1 arrives corrupted (bad decode) but is written anyway.
                let corrupt = name == "part1.rar" && si == 4;
                if corrupt {
                    chunk[10] ^= 0xFF;
                }
                write_at(&path, off as u64, &chunk);
                let ev = r.streaming_segment_data(fi, off as u64, &chunk).unwrap();
                rejected += ev.iter().filter(|e| e.state == BlockState::Damaged).count();
            }
        }
        assert!(rejected >= 1);
        assert_eq!(
            r.streaming_stats().unwrap().blocks_rejected as usize,
            rejected
        );
        let st = r.streaming_status().unwrap();
        assert_eq!(st.pending_blocks, 0);
        assert_eq!(st.damaged_blocks as usize, rejected);
        // Retry: the corrupt article arrives correctly → block re-verified, damage cleared.
        let fi1 = file_index(&r, "part1.rar");
        let d1 = &fx.files[1].1;
        let (off, end) = (4 * article, (5 * article).min(d1.len()));
        write_at(&fx.dir.join("part1.rar"), off as u64, &d1[off..end]);
        let ev = r
            .streaming_segment_data(fi1, off as u64, &d1[off..end])
            .unwrap();
        assert!(ev.iter().all(|e| e.state == BlockState::Verified));
        let st = r.streaming_status().unwrap();
        assert_eq!(st.damaged_blocks, 0);
        assert_eq!(st.verified_blocks, st.total_blocks);
        assert!(
            r.source_files()
                .iter()
                .all(|f| f.status == FileStatus::Complete)
        );
        assert_eq!(
            r.repair(&mut NullObserver).unwrap(),
            RepairResult::NotNeeded
        );
        check_all(&fx);
        // Out-of-range / empty segments are ignored.
        assert!(
            r.streaming_segment_written(fi1, 10_000_000, 10, true)
                .unwrap()
                .is_empty()
        );
        assert!(
            r.streaming_segment_written(fi1, 0, 0, true)
                .unwrap()
                .is_empty()
        );
        assert!(
            r.streaming_segment_written(99, 0, 10, true)
                .unwrap()
                .is_empty()
        );
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn early_repair_before_download_finishes() {
        // Three parts; the last one (6 blocks) never arrives, 8 recovery blocks tracked.
        let fx = fixture("early", &[40_000, 25_000, 6_000], 1000, 8);
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        r.enable_streaming(&StreamingOptions::default()).unwrap();
        for (name, data) in fx.files.iter().take(2) {
            let fi = file_index(&r, name);
            let path = fx.dir.join(name);
            std::fs::write(&path, data).unwrap();
            r.streaming_segment_written(fi, 0, data.len() as u64, true)
                .unwrap();
        }
        // Damage one block of part0 after the fact: report its article as failed.
        let fi0 = file_index(&r, "part0.rar");
        let p0 = fx.dir.join("part0.rar");
        let mut d0 = std::fs::read(&p0).unwrap();
        d0[3000] ^= 1;
        std::fs::write(&p0, &d0).unwrap();
        // The block was already verified before the corruption → still counted verified; the
        // host would not have reported success for a corrupt article. Instead simulate a block
        // that was never reported: part2 pending (6 blocks) ≤ 8 recovery → possible now.
        let st = r.streaming_status().unwrap();
        assert_eq!(st.pending_blocks, 6);
        assert!(st.repair_possible_now);
        // Restore part0 after the preceding host contract demonstration.
        std::fs::write(&p0, &fx.files[0].1).unwrap();
        let _ = fi0;
        let mut obs = Msgs::default();
        let res = r.repair(&mut obs).unwrap();
        assert!(
            matches!(
                res,
                RepairResult::Repaired {
                    blocks_recovered: 6,
                    ..
                }
            ),
            "{res:?}"
        );
        check_all(&fx); // part2 reconstructed without ever being downloaded
        assert!(obs.0.iter().any(|m| m.contains("streamed")));
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn track_exponents_before_volumes_arrive_and_memory_cap() {
        let fx = fixture("late", &[20_000, 10_000], 1000, 6);
        // Load only the index: no recovery packets known yet.
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        r.load_par2_file(&fx.main).unwrap();
        r.finalize().unwrap();
        // Expect 6 recovery blocks (from .vol names), but cap memory to 4 syndromes.
        let st = r
            .enable_streaming(&StreamingOptions {
                expected_recovery_blocks: 6,
                max_memory_bytes: 4 * 1000,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(st.tracked_exponents, 4);
        assert_eq!(st.usable_recovery, 0);
        // Download everything except 3 blocks of part0 (articles 1000 bytes, aligned).
        for (name, data) in &fx.files {
            let fi = file_index(&r, name);
            let path = fx.dir.join(name);
            std::fs::File::create(&path)
                .unwrap()
                .set_len(data.len() as u64)
                .unwrap();
            for (si, chunk) in data.chunks(1000).enumerate() {
                if name == "part0.rar" && matches!(si, 2 | 9 | 15) {
                    r.streaming_segment_failed(fi, (si * 1000) as u64, 1000)
                        .unwrap();
                    continue;
                }
                write_at(&path, (si * 1000) as u64, chunk);
                r.streaming_segment_written(fi, (si * 1000) as u64, chunk.len() as u64, true)
                    .unwrap();
            }
        }
        let st = r.streaming_status().unwrap();
        assert_eq!(st.damaged_blocks, 3);
        assert!(!st.repair_possible_now); // no recovery packets loaded yet
        assert_eq!(st.blocks_needed_now, 3);
        // Volumes arrive now (as in a download queue with par2 files last).
        for v in [
            "set.vol00+01.par2",
            "set.vol01+02.par2",
            "set.vol03+03.par2",
        ] {
            r.load_par2_file(&fx.dir.join(v)).unwrap();
        }
        let st = r.streaming_status().unwrap();
        assert_eq!(st.recovery_loaded, 6);
        assert_eq!(st.usable_recovery, 4);
        assert!(st.repair_possible_now);
        // Track the remaining exponents too (raises the cap first): backfill from disk.
        let mut r2 = r; // same repairer; the cap is part of the state, so rebuild tracking
        assert_eq!(r2.streaming_track_exponents(&[4, 5]).unwrap(), 4); // cap reached → unchanged
        r2.disable_streaming();
        assert!(!r2.streaming_enabled());
        let st = r2
            .enable_streaming(&StreamingOptions {
                max_memory_bytes: 1 << 20,
                ..Default::default()
            })
            .unwrap();
        // Re-enabling folds the already located blocks immediately.
        assert_eq!(st.tracked_exponents, 6);
        assert_eq!(st.verified_blocks, 27);
        assert_eq!(r2.streaming_track_exponents(&[7, 8]).unwrap(), 8); // untracked exponents: syndromes computed by backfill
        assert_eq!(r2.streaming_track_exponents(&[7]).unwrap(), 8);
        let res = r2.repair(&mut NullObserver).unwrap();
        assert!(matches!(
            res,
            RepairResult::Repaired {
                blocks_recovered: 3,
                ..
            }
        ));
        check_all(&fx);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn unverifiable_file_and_errors() {
        let fx = fixture("noifsc", &[3000, 2000], 1000, 4);
        // Strip part0's IFSC from every par2 file.
        let id0 = {
            let set =
                crate::packet::load_par2_file(&fx.main, crate::packet::ScanOptions::FULL).unwrap();
            set.file_descs
                .values()
                .find(|d| d.name == b"part0.rar")
                .unwrap()
                .file_id
        };
        for entry in std::fs::read_dir(&fx.dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().is_some_and(|e| e == "par2") {
                let bytes = std::fs::read(&p).unwrap();
                let raws: Vec<_> = crate::packet::PacketIter::new(
                    &bytes[..],
                    crate::packet::ScanOptions::UNVERIFIED,
                )
                .map(|x| x.unwrap())
                .collect();
                let mut out = Vec::new();
                for raw in raws {
                    let s = raw.offset as usize;
                    let e = s + raw.header.length as usize;
                    if raw.header.kind() == crate::packet::PacketType::Ifsc
                        && bytes[s + 64..s + 80] == id0.0
                    {
                        continue;
                    }
                    out.extend_from_slice(&bytes[s..e]);
                }
                std::fs::write(&p, &out).unwrap();
            }
        }
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        assert!(matches!(
            r.enable_streaming(&StreamingOptions::default()),
            Err(RepairError::NotFinalized)
        ));
        assert!(matches!(
            r.streaming_segment_written(0, 0, 1, true),
            Err(RepairError::NotFinalized)
        ));
        assert!(matches!(
            r.streaming_file_complete(0),
            Err(RepairError::NotFinalized)
        ));
        assert!(matches!(
            r.streaming_track_exponents(&[1]),
            Err(RepairError::NotFinalized)
        ));
        assert!(r.streaming_status().is_none());
        assert!(r.block_state(0, 0).is_none());
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        r.enable_streaming(&StreamingOptions::default()).unwrap();
        let fi0 = file_index(&r, "part0.rar");
        let fi1 = file_index(&r, "part1.rar");
        let d0 = &fx.files[0].1;
        let d1 = &fx.files[1].1;
        std::fs::write(fx.dir.join("part1.rar"), d1).unwrap();
        r.streaming_segment_written(fi1, 0, d1.len() as u64, true)
            .unwrap();
        // part0 without IFSC: segments alone cannot verify blocks; the whole file does.
        let p0 = fx.dir.join("part0.rar");
        std::fs::File::create(&p0)
            .unwrap()
            .set_len(d0.len() as u64)
            .unwrap();
        write_at(&p0, 0, &d0[..1500]);
        let ev = r.streaming_segment_written(fi0, 0, 1500, true).unwrap();
        assert!(ev.is_empty());
        assert_eq!(r.block_state(fi0, 0), Some(BlockState::Pending));
        write_at(&p0, 1500, &d0[1500..]);
        let ev = r
            .streaming_segment_written(fi0, 1500, (d0.len() - 1500) as u64, true)
            .unwrap();
        assert_eq!(ev.len(), 3);
        assert!(ev.iter().all(|e| e.state == BlockState::Verified));
        assert_eq!(r.streaming_status().unwrap().pending_blocks, 0);
        assert!(r.streaming_file_complete(fi0).unwrap().is_empty()); // already complete
        assert!(r.streaming_file_complete(fi1).unwrap().is_empty()); // verifiable file: no-op
        assert!(r.streaming_file_complete(42).unwrap().is_empty());
        assert_eq!(
            r.repair(&mut NullObserver).unwrap(),
            RepairResult::NotNeeded
        );

        // Damaged unverifiable file: declared complete with wrong content → all blocks damaged.
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        r.enable_streaming(&StreamingOptions::default()).unwrap();
        let fi0 = file_index(&r, "part0.rar");
        let mut bad = d0.clone();
        bad[100] ^= 1;
        std::fs::write(&p0, &bad).unwrap();
        let ev = r.streaming_file_complete(fi0).unwrap();
        assert_eq!(ev.len(), 3);
        assert!(ev.iter().all(|e| e.state == BlockState::Damaged));
        let fi1 = file_index(&r, "part1.rar");
        r.streaming_segment_written(fi1, 0, d1.len() as u64, true)
            .unwrap();
        let st = r.streaming_status().unwrap();
        assert_eq!(st.damaged_blocks, 3);
        assert!(st.repair_possible_now);
        r.verify(None, &mut NullObserver).unwrap();
        assert!(matches!(
            r.repair(&mut NullObserver).unwrap(),
            RepairResult::Repaired {
                blocks_recovered: 3,
                ..
            }
        ));
        check_all(&fx);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn verify_after_partial_streaming_probes_only_remaining_blocks() {
        let fx = fixture("probe", &[40_000], 1000, 5);
        let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
        r.load_par2_set(&fx.main).unwrap();
        r.finalize().unwrap();
        r.enable_streaming(&StreamingOptions::default()).unwrap();
        let d = &fx.files[0].1;
        let p = fx.dir.join("part0.rar");
        std::fs::write(&p, d).unwrap();
        // Host reports only the first half; the second half is on disk but unreported, with
        // two blocks corrupted on disk.
        let fi = file_index(&r, "part0.rar");
        r.streaming_segment_written(fi, 0, 20_000, true).unwrap();
        let mut dmg = d.clone();
        dmg[25_000] ^= 1;
        dmg[39_999] ^= 1;
        std::fs::write(&p, &dmg).unwrap();
        let st = r.streaming_status().unwrap();
        assert_eq!(st.verified_blocks, 20);
        assert_eq!(st.pending_blocks, 20);
        let v = r.verify(None, &mut NullObserver).unwrap();
        assert_eq!(v.missing_blocks, 2);
        // The probe verified and folded the 18 good unreported blocks directly.
        assert_eq!(r.streaming_stats().unwrap().blocks_folded, 38);
        let mut obs = Msgs::default();
        assert!(matches!(
            r.repair(&mut obs).unwrap(),
            RepairResult::Repaired {
                blocks_recovered: 2,
                ..
            }
        ));
        assert_eq!(r.streaming_stats().unwrap().blocks_folded, 38);
        check_all(&fx);

        // Blocks located by an extra-file scan (not by the probe) are folded lazily at repair.
        let fx2 = fixture("probe2", &[20_000], 1000, 5);
        let mut r = Par2Repairer::new(&fx2.dir, RepairOptions::default());
        r.load_par2_set(&fx2.main).unwrap();
        r.finalize().unwrap();
        r.enable_streaming(&StreamingOptions::default()).unwrap();
        let d = &fx2.files[0].1;
        // Target never arrives; a renamed complete copy exists elsewhere in the directory.
        std::fs::write(fx2.dir.join("renamed.bin"), d).unwrap();
        r.verify(None, &mut NullObserver).unwrap();
        assert_eq!(
            r.add_extra_files_from_dir(&fx2.dir, &mut NullObserver)
                .unwrap(),
            20
        );
        let mut obs = Msgs::default();
        assert!(matches!(
            r.repair(&mut obs).unwrap(),
            RepairResult::Repaired {
                blocks_recovered: 0,
                ..
            }
        ));
        check_all(&fx2);
        // Now damage: delete one block's worth and let the repairer fold late blocks.
        let mut dmg = d.clone();
        dmg[5000] ^= 1;
        std::fs::write(fx2.dir.join("part0.rar"), &dmg).unwrap();
        let mut r = Par2Repairer::new(&fx2.dir, RepairOptions::default());
        r.load_par2_set(&fx2.main).unwrap();
        r.finalize().unwrap();
        r.verify(None, &mut NullObserver).unwrap(); // locates 19 blocks before streaming is on
        r.enable_streaming(&StreamingOptions::default()).unwrap(); // folds them
        assert_eq!(r.streaming_stats().unwrap().blocks_folded, 19);
        assert!(matches!(
            r.repair(&mut NullObserver).unwrap(),
            RepairResult::Repaired {
                blocks_recovered: 1,
                ..
            }
        ));
        check_all(&fx2);
        std::fs::remove_dir_all(&fx2.dir).unwrap();
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }
}

// =============================================================================================
// Repair-while-downloading: live slice tracker, in-flight syndrome accumulator, mid-download
// volume repair and the thread-safe session that ties them to NZBGet's `ArticleWriter`,
// `DirectRenamer`, `DirectUnpack` and `StreamRepairController::StartLive`.
// =============================================================================================

use crate::filenames::select_more_pars;
use crate::packet::{FileId, PacketSet, ScanOptions, SetId};
use crate::reed_solomon::{
    Engine, EngineConfig, InputKind, InputSpec, Matrix, OutputSink, plan_recovery,
};
use crate::repairer::{RepairReader, SliceSrc};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, mpsc};

/// State of one PAR2 slice during a live download.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SliceState {
    /// No article covering it has arrived (`U`).
    Unarrived,
    /// Some bytes arrived; `covered` holds slice-relative byte ranges of successful articles.
    PartiallyArrived {
        /// Slice-relative byte ranges that arrived.
        covered: Vec<ByteRange>,
    },
    /// Verified against IFSC and folded into the active syndromes (`V`).
    VerifiedGood,
    /// An article failed permanently or the slice failed verification (`D`).
    Damaged,
}

impl SliceState {
    fn tag(&self) -> u8 {
        match self {
            SliceState::Unarrived => 0,
            SliceState::PartiallyArrived { .. } => 1,
            SliceState::VerifiedGood => 2,
            SliceState::Damaged => 3,
        }
    }
}

/// A slice whose state changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SliceEvent {
    /// File.
    pub file_id: FileId,
    /// Slice index within the file.
    pub slice_idx: usize,
    /// New state.
    pub state: SliceState,
}

/// Instruction for the download queue: which paused recovery volumes to unpause now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnpauseAction {
    /// Host-defined ids of the queued `.volXX+YY.par2` files to unpause.
    pub volume_ids_to_unpause: Vec<u64>,
    /// Recovery blocks those volumes carry.
    pub blocks_requested: i64,
    /// Blocks still uncovered after unpausing everything selected (0 when enough are queued).
    pub shortfall: i64,
}

/// A queued recovery volume known to the scheduler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedVolume {
    /// Host-defined id (for example, NZBGet `FileInfo::GetId()`).
    pub id: u64,
    /// Recovery blocks it carries (from the `+YY` name part or an estimate).
    pub blocks: i32,
    /// Whether it is currently paused.
    pub paused: bool,
}

/// Completion state of one archive volume (source file).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VolumeStatus {
    /// Every slice verified (and, when checked, the whole-file MD5 matched).
    CompleteAndVerified,
    /// Still missing data.
    Incomplete {
        /// Verified slices.
        verified: usize,
        /// Damaged slices.
        damaged: usize,
        /// Slices not (fully) arrived.
        unarrived: usize,
    },
}

/// Outcome of an [`StreamingParSession::on_article_finished`] call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArticleOutcome {
    /// Slice transitions caused by the article.
    pub events: Vec<SliceEvent>,
    /// Volumes to unpause if new damage pushed the need beyond the available blocks.
    pub unpause: Option<UnpauseAction>,
}

/// Result of [`StreamingParSession::repair_available_targets_now`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarlyRepairReport {
    /// Erasures (`D + U`) in the whole set at the time of the repair.
    pub erasures: usize,
    /// Recovery syndromes used for the solve.
    pub recovery_used: usize,
    /// Slices written: `(file id, slice index)`.
    pub repaired_slices: Vec<(FileId, usize)>,
    /// Per target file: status after patching and whether the whole-file MD5 matched.
    pub files: Vec<(FileId, VolumeStatus, bool)>,
}

/// Live counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveStatus {
    /// Slices in each state.
    pub unarrived: usize,
    /// Partially arrived slices.
    pub partially_arrived: usize,
    /// Verified slices.
    pub verified: usize,
    /// Damaged slices.
    pub damaged: usize,
    /// Total slices.
    pub total: usize,
    /// Syndrome slots allocated.
    pub syndrome_slots: usize,
    /// Slots whose recovery slice has arrived (usable for a solve).
    pub ready_recovery: usize,
    /// Blocks of unpaused volumes still in flight.
    pub unpaused_in_flight: i64,
    /// `D - (ready + in flight)`, clamped at 0.
    pub needed_recovery_blocks: i64,
    /// `D + U <= ready`: an early Reed-Solomon cutover would succeed right now.
    pub early_cutover_possible: bool,
    /// Folding jobs not yet applied to the syndromes.
    pub pending_folds: usize,
}

/// Session options.
#[derive(Clone, Debug)]
pub struct SessionOptions {
    /// Syndrome slots allocated up front (exponents from the loaded set or canonical `0..n`).
    pub preallocated_syndrome_slots: usize,
    /// Byte cap for resident syndrome payloads and reconstructed output payloads separately.
    pub max_syndrome_bytes: u64,
    /// Byte cap applied separately to staging, folding payloads, and per-call scratch.
    /// Concurrent calls and queued jobs share bounded admission; metadata and engine buffers are additional.
    pub max_working_bytes: u64,
    /// Hard cap on slots, also limited by `max_syndrome_bytes / slice_size`.
    pub max_syndrome_slots: usize,
    /// Memory for in-RAM slice reassembly before falling back to reading the target file.
    pub max_staging_bytes: u64,
    /// Dedicated folding threads (0 = fold inline on the calling thread).
    pub fold_threads: usize,
    /// Bounded folding queue depth per folder; when full the caller folds inline.
    pub fold_queue_depth: usize,
    /// Threads for the Reed-Solomon solve.
    pub solve_threads: usize,
    /// Buffer budget for the solve and separate cap for recovery-matrix planning
    /// (minimum 16 MiB each). Resident syndromes and reconstructed slices are additional.
    pub solve_mem_limit_bytes: u64,
    /// SIMD kernel.
    pub kernel: Kernel,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            preallocated_syndrome_slots: 32,
            max_syndrome_bytes: 64 << 20,
            max_working_bytes: 64 << 20,
            max_syndrome_slots: 512,
            max_staging_bytes: 256 << 20,
            fold_threads: 0,
            fold_queue_depth: 64,
            solve_threads: 0,
            solve_mem_limit_bytes: 256 << 20,
            kernel: Kernel::detect(),
        }
    }
}

impl SessionOptions {
    fn bounded(mut self, slice_size: u64) -> Result<Self, RepairError> {
        if slice_size == 0 || !slice_size.is_multiple_of(4) || usize::try_from(slice_size).is_err()
        {
            return Err(io_ctx("streaming slice size")(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid slice size",
            )));
        }
        let scratch = slice_size
            .checked_mul(2)
            .map(|bytes| bytes.max(crate::hasher::READ_CHUNK as u64));
        if scratch.is_none_or(|bytes| bytes > self.max_working_bytes) {
            return Err(RepairError::StreamingMemoryLimit {
                context: "slice scratch",
                required_bytes: scratch.unwrap_or(u64::MAX),
                limit_bytes: self.max_working_bytes,
            });
        }
        if self.max_syndrome_slots > 0 && slice_size > self.max_syndrome_bytes {
            return Err(RepairError::StreamingMemoryLimit {
                context: "syndrome slice",
                required_bytes: slice_size,
                limit_bytes: self.max_syndrome_bytes,
            });
        }
        let capacity = usize::try_from(self.max_syndrome_bytes / slice_size).unwrap_or(usize::MAX);
        self.max_syndrome_slots = self.max_syndrome_slots.min(capacity);
        self.preallocated_syndrome_slots = self
            .preallocated_syndrome_slots
            .min(self.max_syndrome_slots);
        self.max_staging_bytes = self.max_staging_bytes.min(self.max_working_bytes);
        // Bound every lane's queued and active jobs plus one payload per admitted
        // producer. Arcs shared by lanes only reduce the actual live bytes.
        let jobs = usize::try_from(self.max_working_bytes / slice_size).unwrap_or(usize::MAX);
        let queue_jobs = jobs - jobs / 2;
        self.fold_threads = self.fold_threads.min(queue_jobs / 2);
        if let Some(per_lane) = queue_jobs.checked_div(self.fold_threads) {
            self.fold_queue_depth = self.fold_queue_depth.max(1).min(per_lane - 1);
        }
        Ok(self)
    }
}

/// Simple growable bitset.
#[derive(Clone, Debug, Default)]
pub struct BitVec {
    words: Vec<u64>,
    ones: usize,
}

impl BitVec {
    /// Bitset with `n` cleared bits.
    pub fn new(n: usize) -> Self {
        Self {
            words: vec![0; n.div_ceil(64)],
            ones: 0,
        }
    }
    /// Bit `i`.
    #[inline]
    pub fn get(&self, i: usize) -> bool {
        self.words
            .get(i / 64)
            .is_some_and(|w| (w >> (i % 64)) & 1 == 1)
    }
    /// Set bit `i`; returns whether it was previously clear.
    #[inline]
    pub fn set(&mut self, i: usize) -> bool {
        let w = &mut self.words[i / 64];
        let m = 1u64 << (i % 64);
        if *w & m == 0 {
            *w |= m;
            self.ones += 1;
            true
        } else {
            false
        }
    }
    /// Number of set bits.
    pub fn count_ones(&self) -> usize {
        self.ones
    }
}

struct LiveFile {
    file_id: FileId,
    target_path: PathBuf,
    local_name: String,
    raw_name: Vec<u8>,
    hash_16k: [u8; 16],
    length: u64,
    first_slice: usize,
    slice_count: usize,
    checksums: Option<Vec<ChecksumEntry>>,
    hash_full: [u8; 16],
}

struct LiveStaged {
    buf: Vec<u8>,
    ranges: Vec<ByteRange>,
}

/// Mutable tracker state (one lock, held only for bookkeeping—never during hashing or I/O).
struct Tracker {
    states: Vec<SliceState>,
    counts: [usize; 4],
    /// Slice-relative coverage by successful articles (kept across the `Damaged` state so a
    /// damaged slice that later becomes fully covered by retries is re-verified).
    covered: Vec<Vec<ByteRange>>,
    /// Article CRCs per slice for the ParQuick pre-check: `(slice-relative offset, len, crc)`.
    article_crcs: Vec<Vec<(u64, u64, u32)>>,
    staging: HashMap<usize, LiveStaged>,
    staging_bytes: u64,
    queued_volumes: Vec<QueuedVolume>,
    /// Volume ids unpaused by the scheduler that have not arrived yet, with their blocks.
    unpaused_in_flight: HashMap<u64, i32>,
    /// Exponents whose recovery slice has been XOR-ed into a slot.
    ready_exponents: BTreeSet<u32>,
    par_files: Vec<PathBuf>,
}

/// One syndrome accumulator `S_r = R_{e_r} ⊕ Σ_{m folded} g_m^{e_r} · D_m` (split-plane layout).
struct SyndromeSlot {
    exponent: u32,
    data: Vec<u8>,
    folded_mask: BitVec,
    recovery_added: bool,
}

type SlotList = Arc<RwLock<Vec<Arc<Mutex<SyndromeSlot>>>>>;

struct StagingCharges<'a> {
    tracker: &'a Mutex<Tracker>,
    bytes: u64,
}

impl Drop for StagingCharges<'_> {
    fn drop(&mut self) {
        self.tracker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .staging_bytes -= self.bytes;
    }
}

struct TakenSyndromes {
    slots: Vec<Arc<Mutex<SyndromeSlot>>>,
    data: Vec<Vec<u8>>,
}

impl Drop for TakenSyndromes {
    fn drop(&mut self) {
        for (slot, data) in self.slots.iter().zip(self.data.drain(..)) {
            slot.lock().unwrap_or_else(|e| e.into_inner()).data = data;
        }
    }
}

struct FoldJob {
    slice: usize,
    logbase: u16,
    /// Split-plane slice data (`slice_size` bytes).
    split: Arc<Vec<u8>>,
}

struct FoldPool {
    txs: Vec<mpsc::SyncSender<Arc<FoldJob>>>,
    pending: Arc<(Mutex<usize>, Condvar)>,
}

/// Fold `job` into every slot whose index satisfies `index % stride == lane`.
fn fold_lane(kernel: &Kernel, slots: &SlotList, job: &FoldJob, lane: usize, stride: usize) {
    let list = slots.read().unwrap_or_else(|e| e.into_inner());
    let src = Plane::from_halves(&job.split);
    for (i, slot) in list.iter().enumerate() {
        if i % stride != lane {
            continue;
        }
        let mut s = slot.lock().unwrap_or_else(|e| e.into_inner());
        if !s.folded_mask.set(job.slice) {
            continue;
        }
        let c = rs_coefficient(job.logbase, s.exponent);
        let mut dst = PlaneMut::from_halves(&mut s.data);
        kernel.mul_acc_split(&mut dst, src, c);
    }
}

struct SessionInner {
    payload_gate: RwLock<()>,
    active_payloads: Mutex<usize>,
    payload_available: Condvar,
    opts: SessionOptions,
    set_id: SetId,
    slice_size: usize,
    files: Vec<LiveFile>,
    file_index: HashMap<FileId, usize>,
    logs: Vec<u16>,
    tracker: Mutex<Tracker>,
    slots: SlotList,
    pool: Option<FoldPool>,
    /// Slices folded (counter for statistics).
    folds: AtomicU64,
    inline_folds: AtomicUsize,
}

struct PayloadPermit<'a>(&'a SessionInner);

impl Drop for PayloadPermit<'_> {
    fn drop(&mut self) {
        let mut active = self
            .0
            .active_payloads
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *active -= 1;
        self.0.payload_available.notify_one();
    }
}

impl SessionInner {
    fn admit_payload(&self) -> PayloadPermit<'_> {
        let cap = self.opts.max_working_bytes / (2 * self.slice_size as u64);
        let mut active = self
            .active_payloads
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        while *active as u64 >= cap {
            active = self
                .payload_available
                .wait(active)
                .unwrap_or_else(|e| e.into_inner());
        }
        *active += 1;
        PayloadPermit(self)
    }
}

/// Thread-safe repair-while-downloading session (`Send + Sync`; clone freely).
#[derive(Clone)]
pub struct StreamingParSession {
    inner: Arc<SessionInner>,
}

impl StreamingParSession {
    /// Create a session from the metadata packets of a set (Main + FileDesc + IFSC; recovery
    /// packets, if any are loaded already, seed the syndrome exponents). Target files live in
    /// `base_dir`.
    pub fn new(
        set: &PacketSet,
        base_dir: &Path,
        opts: SessionOptions,
    ) -> Result<Self, RepairError> {
        let main = set.main.as_ref().ok_or(RepairError::NoMainPacket)?;
        let missing: Vec<FileId> = main
            .recoverable_file_ids
            .iter()
            .filter(|id| !set.file_descs.contains_key(id))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(RepairError::IncompleteMetadata {
                missing_descriptions: missing,
            });
        }
        let opts = opts.bounded(main.slice_size)?;
        let ss = main.slice_size as usize;
        let mut files = Vec::new();
        let mut file_index = HashMap::new();
        let mut first = 0usize;
        for (fi, id) in main.recoverable_file_ids.iter().enumerate() {
            let fd = &set.file_descs[id];
            let count = main.slice_count_for(fd.file_length) as usize;
            let checksums = set
                .ifscs
                .get(id)
                .filter(|p| p.slices.len() == count && count > 0)
                .map(|p| entries_for_file(fi as u32, &p.slices));
            files.push(LiveFile {
                file_id: *id,
                target_path: base_dir.join(fd.local_name()),
                local_name: fd.local_name(),
                raw_name: fd.name.clone(),
                hash_16k: fd.hash_16k,
                length: fd.file_length,
                first_slice: first,
                slice_count: count,
                checksums,
                hash_full: fd.hash_full,
            });
            file_index.insert(*id, fi);
            first += count;
        }
        let total = first;
        let logs = input_constant_logs(total).map_err(|_| RepairError::Singular)?;
        // Exponents for the pre-allocated slots: loaded recovery exponents first, then the
        // canonical sequence of nonnegative integers.
        let mut exps: Vec<u32> = set.recovery.keys().copied().collect();
        let mut e = 0u32;
        while exps.len()
            < opts
                .preallocated_syndrome_slots
                .min(opts.max_syndrome_slots)
        {
            if !exps.contains(&e) {
                exps.push(e);
            }
            e += 1;
        }
        exps.truncate(
            opts.preallocated_syndrome_slots
                .min(opts.max_syndrome_slots),
        );
        let slots: Vec<Arc<Mutex<SyndromeSlot>>> = exps
            .iter()
            .map(|&exponent| {
                Arc::new(Mutex::new(SyndromeSlot {
                    exponent,
                    data: vec![0u8; ss],
                    folded_mask: BitVec::new(total),
                    recovery_added: false,
                }))
            })
            .collect();
        let slots: SlotList = Arc::new(RwLock::new(slots));
        let pool = (opts.fold_threads > 0).then(|| {
            let pending = Arc::new((Mutex::new(0usize), Condvar::new()));
            let mut txs = Vec::new();
            for lane in 0..opts.fold_threads {
                let (tx, rx) = mpsc::sync_channel::<Arc<FoldJob>>(opts.fold_queue_depth.max(1));
                txs.push(tx);
                let slots = Arc::clone(&slots);
                let pending = Arc::clone(&pending);
                let kernel = opts.kernel;
                let stride = opts.fold_threads;
                std::thread::Builder::new()
                    .name(format!("par2-fold-{lane}"))
                    .spawn(move || {
                        while let Ok(job) = rx.recv() {
                            fold_lane(&kernel, &slots, &job, lane, stride);
                            let (m, cv) = &*pending;
                            let mut p = m.lock().unwrap_or_else(|e| e.into_inner());
                            *p -= 1;
                            cv.notify_all();
                        }
                    })
                    .expect("spawn folder thread");
            }
            FoldPool { txs, pending }
        });
        let inner = SessionInner {
            payload_gate: RwLock::new(()),
            active_payloads: Mutex::new(0),
            payload_available: Condvar::new(),
            set_id: set.set_id.unwrap_or(SetId([0; 16])),
            slice_size: ss,
            tracker: Mutex::new(Tracker {
                states: vec![SliceState::Unarrived; total],
                counts: [total, 0, 0, 0],
                covered: vec![Vec::new(); total],
                article_crcs: vec![Vec::new(); total],
                staging: HashMap::new(),
                staging_bytes: 0,
                queued_volumes: Vec::new(),
                unpaused_in_flight: HashMap::new(),
                ready_exponents: BTreeSet::new(),
                par_files: Vec::new(),
            }),
            files,
            file_index,
            logs,
            slots,
            pool,
            folds: AtomicU64::new(0),
            inline_folds: AtomicUsize::new(0),
            opts,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Set id.
    pub fn set_id(&self) -> SetId {
        self.inner.set_id
    }

    /// Slice size.
    pub fn slice_size(&self) -> u64 {
        self.inner.slice_size as u64
    }

    fn file(&self, id: &FileId) -> Result<usize, RepairError> {
        self.inner
            .file_index
            .get(id)
            .copied()
            .ok_or(RepairError::UnknownFile(*id))
    }

    fn set_state(t: &mut Tracker, g: usize, new: SliceState) -> bool {
        let old = t.states[g].tag();
        if t.states[g] == new {
            return false;
        }
        t.counts[old as usize] -= 1;
        t.counts[new.tag() as usize] += 1;
        t.states[g] = new;
        true
    }

    // -----------------------------------------------------------------------------------------
    // 1. LiveParTracker
    // -----------------------------------------------------------------------------------------

    /// File id for a filename (raw PAR2 bytes or local name; exact, then ASCII case-insensitive),
    /// in `libpar2` order for ties.
    pub fn file_id_by_name(&self, name: &[u8]) -> Option<FileId> {
        let files = &self.inner.files;
        if let Some(f) = files
            .iter()
            .find(|f| f.raw_name.as_slice() == name || f.local_name.as_bytes() == name)
        {
            return Some(f.file_id);
        }
        let lower: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
        files
            .iter()
            .find(|f| {
                f.raw_name
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .eq(lower.iter().copied())
                    || f.local_name.to_ascii_lowercase().as_bytes() == lower.as_slice()
            })
            .map(|f| f.file_id)
    }

    /// File id of the first file (in `libpar2` order) whose 16k hash matches: the key a
    /// downloader has after article 1 of an obfuscated file.
    pub fn file_id_by_hash16k(&self, hash_16k: &[u8; 16]) -> Option<FileId> {
        self.inner
            .files
            .iter()
            .find(|f| f.hash_16k == *hash_16k)
            .map(|f| f.file_id)
    }

    /// [`on_article_finished`](Self::on_article_finished) keyed by filename.
    pub fn on_article_finished_by_name(
        &self,
        name: &[u8],
        offset: u64,
        size: u64,
        crc32: u32,
        bytes: Option<&[u8]>,
    ) -> Result<ArticleOutcome, RepairError> {
        let id = self
            .file_id_by_name(name)
            .ok_or(RepairError::UnknownFile(FileId([0; 16])))?;
        self.on_article_finished(&id, offset, size, crc32, bytes)
    }

    /// [`on_article_failed_permanently`](Self::on_article_failed_permanently) keyed by filename.
    pub fn on_article_failed_permanently_by_name(
        &self,
        name: &[u8],
        offset: u64,
        size: u64,
    ) -> Result<(Vec<SliceEvent>, Option<UnpauseAction>), RepairError> {
        let id = self
            .file_id_by_name(name)
            .ok_or(RepairError::UnknownFile(FileId([0; 16])))?;
        self.on_article_failed_permanently(&id, offset, size)
    }

    /// Register a `.volXX+YY.par2` file in the download queue (call for every recovery volume
    /// of the NZB, paused or not).
    pub fn register_queued_volume(&self, volume: QueuedVolume) {
        let mut t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = t.queued_volumes.iter_mut().find(|v| v.id == volume.id) {
            *v = volume;
        } else {
            t.queued_volumes.push(volume);
        }
    }

    /// Current state of a slice.
    pub fn slice_state(
        &self,
        file_id: &FileId,
        slice_idx: usize,
    ) -> Result<SliceState, RepairError> {
        let fi = self.file(file_id)?;
        let f = &self.inner.files[fi];
        if slice_idx >= f.slice_count {
            return Err(RepairError::UnknownFile(*file_id));
        }
        let t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
        Ok(t.states[f.first_slice + slice_idx].clone())
    }

    /// Completion status of one volume (source file).
    pub fn volume_status(&self, file_id: &FileId) -> Result<VolumeStatus, RepairError> {
        let fi = self.file(file_id)?;
        let t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
        Ok(Self::volume_status_locked(&t, &self.inner.files[fi]))
    }

    fn volume_status_locked(t: &Tracker, f: &LiveFile) -> VolumeStatus {
        let (mut v, mut d, mut u) = (0, 0, 0);
        for g in f.first_slice..f.first_slice + f.slice_count {
            match t.states[g] {
                SliceState::VerifiedGood => v += 1,
                SliceState::Damaged => d += 1,
                _ => u += 1,
            }
        }
        if d == 0 && u == 0 {
            VolumeStatus::CompleteAndVerified
        } else {
            VolumeStatus::Incomplete {
                verified: v,
                damaged: d,
                unarrived: u,
            }
        }
    }

    /// Live counters.
    pub fn status(&self) -> LiveStatus {
        let t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
        let ready = t.ready_exponents.len();
        let in_flight: i64 = t.unpaused_in_flight.values().map(|&b| b as i64).sum();
        let damaged = t.counts[3] as i64;
        let unarrived = t.counts[0] + t.counts[1];
        let slots = self
            .inner
            .slots
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let pending = self
            .inner
            .pool
            .as_ref()
            .map(|p| *p.pending.0.lock().unwrap_or_else(|e| e.into_inner()))
            .unwrap_or(0);
        LiveStatus {
            unarrived: t.counts[0],
            partially_arrived: t.counts[1],
            verified: t.counts[2],
            damaged: t.counts[3],
            total: t.states.len(),
            syndrome_slots: slots,
            ready_recovery: ready,
            unpaused_in_flight: in_flight,
            needed_recovery_blocks: (damaged - ready as i64 - in_flight).max(0),
            early_cutover_possible: damaged as usize + unarrived <= ready,
            pending_folds: pending,
        }
    }

    /// Run the volume selector if damage exceeds what is loaded or already in flight.
    fn schedule_unpause(t: &mut Tracker) -> Option<UnpauseAction> {
        let damaged = t.counts[3] as i64;
        let ready = t.ready_exponents.len() as i64;
        let in_flight: i64 = t.unpaused_in_flight.values().map(|&b| b as i64).sum();
        let needed = damaged - ready - in_flight;
        if needed <= 0 {
            return None;
        }
        let mut paused: Vec<(i32, u64)> = t
            .queued_volumes
            .iter()
            .filter(|v| v.paused)
            .map(|v| (v.blocks.max(0), v.id))
            .collect();
        paused.sort_unstable();
        let counts: Vec<i32> = paused.iter().map(|(b, _)| *b).collect();
        let (selected, _available) = select_more_pars(&counts, needed.min(i32::MAX as i64) as i32);
        let mut ids = Vec::new();
        let mut blocks = 0i64;
        for i in selected {
            let (b, id) = paused[i];
            ids.push(id);
            blocks += b as i64;
            t.unpaused_in_flight.insert(id, b);
            if let Some(v) = t.queued_volumes.iter_mut().find(|v| v.id == id) {
                v.paused = false;
            }
        }
        Some(UnpauseAction {
            volume_ids_to_unpause: ids,
            blocks_requested: blocks,
            shortfall: (needed - blocks).max(0),
        })
    }

    /// An article failed on every server and fallback round: its slices are damaged now.
    /// Returns an unpause instruction when more recovery blocks must be fetched.
    pub fn on_article_failed_permanently(
        &self,
        file_id: &FileId,
        offset: u64,
        size: u64,
    ) -> Result<(Vec<SliceEvent>, Option<UnpauseAction>), RepairError> {
        let fi = self.file(file_id)?;
        let f = &self.inner.files[fi];
        let ss = self.inner.slice_size as u64;
        let mut events = Vec::new();
        if size == 0 || offset >= f.length || f.slice_count == 0 {
            return Ok((events, None));
        }
        let end = (offset + size).min(f.length);
        let (b0, b1) = ((offset / ss) as usize, ((end - 1) / ss) as usize);
        let mut t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
        for b in b0..=b1.min(f.slice_count - 1) {
            let g = f.first_slice + b;
            if t.states[g] == SliceState::VerifiedGood {
                continue;
            }
            if let Some(st) = t.staging.remove(&g) {
                t.staging_bytes -= st.buf.len() as u64;
            }
            if Self::set_state(&mut t, g, SliceState::Damaged) {
                events.push(SliceEvent {
                    file_id: *file_id,
                    slice_idx: b,
                    state: SliceState::Damaged,
                });
            }
        }
        let action = Self::schedule_unpause(&mut t);
        Ok((events, action))
    }

    /// An article finished downloading and was written to the target file at `offset`.
    /// `crc32` is the decoded article CRC (yEnc); `bytes` the decoded data when still in RAM
    /// (`ArticleCache`). Completed slices are verified on the calling thread without holding
    /// any lock and folded into the syndromes.
    pub fn on_article_finished(
        &self,
        file_id: &FileId,
        offset: u64,
        size: u64,
        crc32: u32,
        bytes: Option<&[u8]>,
    ) -> Result<ArticleOutcome, RepairError> {
        let _payload = self
            .inner
            .payload_gate
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let _permit = self.inner.admit_payload();
        let fi = self.file(file_id)?;
        let f = &self.inner.files[fi];
        let ss = self.inner.slice_size as u64;
        let mut out = ArticleOutcome::default();
        if size == 0 || offset >= f.length || f.slice_count == 0 {
            return Ok(out);
        }
        let end = (offset + size).min(f.length);
        let (b0, b1) = ((offset / ss) as usize, ((end - 1) / ss) as usize);
        // Phase 1 (locked): coverage, staging, ParQuick CRC bookkeeping; collect completed slices.
        let mut completed_charges = StagingCharges {
            tracker: &self.inner.tracker,
            bytes: 0,
        };
        let mut completed: Vec<(usize, Option<Vec<u8>>, Option<u32>)> = Vec::new();
        {
            let mut t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
            for b in b0..=b1.min(f.slice_count - 1) {
                let g = f.first_slice + b;
                if t.states[g] == SliceState::VerifiedGood {
                    continue;
                }
                let sstart = b as u64 * ss;
                let send = (sstart + ss).min(f.length);
                let s = offset.max(sstart);
                let e = end.min(send);
                if s >= e {
                    continue;
                }
                let slen = (send - sstart) as usize;
                // Coverage.
                t.covered[g].push(ByteRange::new((s - sstart) as i64, (e - s) as i64));
                let covered = normalize_ranges(&t.covered[g]);
                t.covered[g] = covered.clone();
                // Article CRC for the quick path (only exact per-article pieces are usable).
                if s == offset && e == end {
                    t.article_crcs[g].push((s - sstart, e - s, crc32));
                }
                // Staging.
                if let Some(d) = bytes {
                    let have = t.staging.contains_key(&g);
                    if have || t.staging_bytes + slen as u64 <= self.inner.opts.max_staging_bytes {
                        if !have {
                            t.staging_bytes += slen as u64;
                        }
                        let st = t.staging.entry(g).or_insert_with(|| LiveStaged {
                            buf: vec![0u8; slen],
                            ranges: Vec::new(),
                        });
                        let rel = (s - sstart) as usize;
                        st.buf[rel..rel + (e - s) as usize]
                            .copy_from_slice(&d[(s - offset) as usize..(e - offset) as usize]);
                        st.ranges.push(ByteRange::new(rel as i64, (e - s) as i64));
                    }
                }
                if range_covered(&covered, 0, slen as i64) {
                    // Complete: hand the bytes (if fully staged) to the unlocked phase.
                    let staged = match t.staging.remove(&g) {
                        Some(st) => {
                            if range_covered(&normalize_ranges(&st.ranges), 0, slen as i64) {
                                completed_charges.bytes += st.buf.len() as u64;
                                Some(st.buf)
                            } else {
                                t.staging_bytes -= st.buf.len() as u64;
                                None
                            }
                        }
                        None => None,
                    };
                    // ParQuick: combined CRC when the articles tile the slice exactly.
                    let mut crcs = std::mem::take(&mut t.article_crcs[g]);
                    crcs.sort_unstable();
                    let mut quick: Option<u32> = None;
                    if !crcs.is_empty() && crcs[0].0 == 0 {
                        let mut pos = 0u64;
                        let mut acc = 0u32;
                        let mut ok = true;
                        for (i, (o, l, c)) in crcs.iter().enumerate() {
                            if *o != pos {
                                ok = false;
                                break;
                            }
                            acc = if i == 0 {
                                *c
                            } else {
                                crc32_combine(acc, *c, *l)
                            };
                            pos += l;
                        }
                        if ok && pos == slen as u64 {
                            quick = Some(if (slen as u64) < ss {
                                crc32_zeros(acc, ss - slen as u64)
                            } else {
                                acc
                            });
                        }
                    }
                    completed.push((g, staged, quick));
                } else if t.states[g] != SliceState::Damaged {
                    // A damaged slice stays damaged until it is fully covered and re-verified.
                    Self::set_state(&mut t, g, SliceState::PartiallyArrived { covered });
                }
            }
        }
        if completed.is_empty() {
            return Ok(out);
        }
        // Phase 2 (unlocked): obtain bytes, hash, fold.
        let mut damaged_any = false;
        for (g, staged, quick) in completed {
            let b = g - f.first_slice;
            // A large article can supply whole slices without retaining copies of
            // all of them in staging or rereading bytes that the caller supplied.
            let staged = staged.or_else(|| {
                let start = b as u64 * ss;
                let stop = (start + ss).min(f.length);
                if offset <= start && end >= stop {
                    bytes.map(|data| {
                        data[(start - offset) as usize..(stop - offset) as usize].to_vec()
                    })
                } else {
                    None
                }
            });
            let verdict = self.verify_slice_bytes(fi, b, staged, quick)?;
            let mut t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
            if t.states[g] == SliceState::VerifiedGood {
                continue;
            }
            match verdict {
                Some(data) => {
                    Self::set_state(&mut t, g, SliceState::VerifiedGood);
                    drop(t);
                    self.fold(g, data);
                    out.events.push(SliceEvent {
                        file_id: *file_id,
                        slice_idx: b,
                        state: SliceState::VerifiedGood,
                    });
                }
                None => {
                    Self::set_state(&mut t, g, SliceState::Damaged);
                    damaged_any = true;
                    out.events.push(SliceEvent {
                        file_id: *file_id,
                        slice_idx: b,
                        state: SliceState::Damaged,
                    });
                }
            }
        }
        if damaged_any {
            let mut t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
            out.unpause = Self::schedule_unpause(&mut t);
        }
        Ok(out)
    }

    /// Verify slice `b` of file `fi`: `staged` bytes if available, otherwise read from the
    /// target file. `quick` is the pre-combined article CRC (ParQuick). Returns the slice data
    /// (unpadded) when valid. Does not hold the tracker lock.
    fn verify_slice_bytes(
        &self,
        fi: usize,
        b: usize,
        staged: Option<Vec<u8>>,
        quick: Option<u32>,
    ) -> Result<Option<Vec<u8>>, RepairError> {
        let f = &self.inner.files[fi];
        let ss = self.inner.slice_size as u64;
        let Some(cs) = f.checksums.as_ref() else {
            // Without IFSC a slice cannot be verified individually.
            return Ok(None);
        };
        let entry = cs[b];
        if let Some(q) = quick
            && q != entry.crc32
        {
            return Ok(None);
        }
        let data = match staged {
            Some(d) => d,
            None => {
                let off = b as u64 * ss;
                let len = (f.length - off).min(ss) as usize;
                let fh = File::open(&f.target_path)
                    .map_err(io_ctx(format!("opening {}", f.target_path.display())))?;
                let mut buf = vec![0u8; len];
                read_exact_at(&fh, off, &mut buf)
                    .map_err(io_ctx(format!("reading {}", f.target_path.display())))?;
                buf
            }
        };
        let ok = if data.len() == ss as usize {
            let (c, m) = slice_checksums(&data);
            c == entry.crc32 && m == entry.md5
        } else {
            let mut padded = vec![0; ss as usize];
            padded[..data.len()].copy_from_slice(&data);
            let (c, m) = slice_checksums(&padded);
            c == entry.crc32 && m == entry.md5
        };
        Ok(ok.then_some(data))
    }

    // -----------------------------------------------------------------------------------------
    // 2. InFlightSyndromeAccumulator
    // -----------------------------------------------------------------------------------------

    /// Fold verified slice `g` (natural layout, unpadded) into every syndrome slot.
    fn fold(&self, g: usize, data: Vec<u8>) {
        let ss = self.inner.slice_size;
        let words = ss / 2;
        let mut split = vec![0u8; ss];
        {
            let (lo, hi) = split.split_at_mut(words);
            let n = data.len().min(ss) / 2;
            self.inner
                .opts
                .kernel
                .deinterleave(&data[..2 * n], &mut lo[..n], &mut hi[..n]);
            if data.len().min(ss) % 2 == 1 {
                lo[n] = data[2 * n];
            }
        }
        let job = Arc::new(FoldJob {
            slice: g,
            logbase: self.inner.logs[g],
            split: Arc::new(split),
        });
        self.inner.folds.fetch_add(1, Ordering::Relaxed);
        match &self.inner.pool {
            None => fold_lane(&self.inner.opts.kernel, &self.inner.slots, &job, 0, 1),
            Some(pool) => {
                let n = pool.txs.len();
                {
                    let mut p = pool.pending.0.lock().unwrap_or_else(|e| e.into_inner());
                    *p += n;
                }
                for (lane, tx) in pool.txs.iter().enumerate() {
                    if tx.try_send(Arc::clone(&job)).is_err() {
                        // Queue full: never block the article writer—fold this lane inline.
                        fold_lane(&self.inner.opts.kernel, &self.inner.slots, &job, lane, n);
                        self.inner.inline_folds.fetch_add(1, Ordering::Relaxed);
                        let (m, cv) = &*pool.pending;
                        let mut p = m.lock().unwrap_or_else(|e| e.into_inner());
                        *p -= 1;
                        cv.notify_all();
                    }
                }
            }
        }
    }

    /// Wait until all queued folds have been applied.
    pub fn flush(&self) {
        if let Some(pool) = &self.inner.pool {
            let (m, cv) = &*pool.pending;
            let mut p = m.lock().unwrap_or_else(|e| e.into_inner());
            while *p > 0 {
                p = cv.wait(p).unwrap_or_else(|e| e.into_inner());
            }
        }
    }

    /// Slices folded so far and folds performed inline because a folder queue was full.
    pub fn fold_stats(&self) -> (u64, usize) {
        (
            self.inner.folds.load(Ordering::Relaxed),
            self.inner.inline_folds.load(Ordering::Relaxed),
        )
    }

    /// Bring every slot's `folded_mask` up to date with the verified slices by re-reading the
    /// missing ones from the target files (needed for slots allocated after slices were
    /// verified and evicted from RAM).
    fn backfill_slots(&self) -> Result<(), RepairError> {
        self.flush();
        let verified: Vec<usize> = {
            let t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
            (0..t.states.len())
                .filter(|&g| t.states[g] == SliceState::VerifiedGood)
                .collect()
        };
        let slots: Vec<Arc<Mutex<SyndromeSlot>>> = self
            .inner
            .slots
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let ss = self.inner.slice_size;
        for g in verified {
            let needs: Vec<Arc<Mutex<SyndromeSlot>>> = slots
                .iter()
                .filter(|s| {
                    !s.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .folded_mask
                        .get(g)
                })
                .cloned()
                .collect();
            if needs.is_empty() {
                continue;
            }
            let data = self.read_slice_from_disk(g)?;
            let mut split = vec![0u8; ss];
            {
                let (lo, hi) = split.split_at_mut(ss / 2);
                let n = data.len() / 2;
                self.inner
                    .opts
                    .kernel
                    .deinterleave(&data[..2 * n], &mut lo[..n], &mut hi[..n]);
                if data.len() % 2 == 1 {
                    lo[n] = data[2 * n];
                }
            }
            let src = Plane::from_halves(&split);
            for slot in needs {
                let mut s = slot.lock().unwrap_or_else(|e| e.into_inner());
                if s.folded_mask.set(g) {
                    let c = rs_coefficient(self.inner.logs[g], s.exponent);
                    let mut dst = PlaneMut::from_halves(&mut s.data);
                    self.inner.opts.kernel.mul_acc_split(&mut dst, src, c);
                }
            }
        }
        Ok(())
    }

    fn read_slice_from_disk(&self, g: usize) -> Result<Vec<u8>, RepairError> {
        let fi = self
            .inner
            .files
            .iter()
            .position(|f| g >= f.first_slice && g < f.first_slice + f.slice_count)
            .expect("slice belongs to a file");
        let f = &self.inner.files[fi];
        let ss = self.inner.slice_size as u64;
        let off = (g - f.first_slice) as u64 * ss;
        let len = (f.length - off).min(ss) as usize;
        let fh = File::open(&f.target_path)
            .map_err(io_ctx(format!("opening {}", f.target_path.display())))?;
        let mut buf = vec![0u8; len];
        read_exact_at(&fh, off, &mut buf)
            .map_err(io_ctx(format!("reading {}", f.target_path.display())))?;
        Ok(buf)
    }

    /// A recovery volume finished downloading: verify its recovery packets and XOR each
    /// recovery slice into the syndrome of its exponent (allocating a slot and back-filling it
    /// from disk when the exponent was not pre-allocated). `queued_id` clears the in-flight
    /// accounting of the scheduler. Returns the number of recovery slices absorbed.
    pub fn on_recovery_volume_arrived(
        &self,
        path: &Path,
        queued_id: Option<u64>,
    ) -> Result<usize, RepairError> {
        let _payload = self
            .inner
            .payload_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let src = FileSource::open(path).map_err(io_ctx(format!("opening {}", path.display())))?;
        let ss = self.inner.slice_size;
        let mut absorbed = 0usize;
        let mut need_backfill = false;
        // Keep every framed candidate until its hash is known. PacketSet would
        // deduplicate exponents before a corrupt candidate can be rejected.
        for raw in crate::packet::PacketIter::new(&src, ScanOptions::METADATA) {
            let raw = raw.map_err(io_ctx(format!("loading {}", path.display())))?;
            if raw.header.set_id != self.inner.set_id
                || raw.header.kind() != crate::packet::PacketType::RecoverySlice
            {
                continue;
            }
            let Ok(r) = crate::packet::RecoverySliceRef::from_raw(&src, &raw, 0)
                .map_err(io_ctx("reading recovery packet"))?
            else {
                continue;
            };
            let e = &r.exponent;
            if r.slice_size != ss as u64 {
                continue;
            }
            {
                let t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
                if t.ready_exponents.contains(e) {
                    continue;
                }
            }
            let slot = {
                let list = self.inner.slots.read().unwrap_or_else(|e| e.into_inner());
                list.iter()
                    .find(|s| s.lock().unwrap_or_else(|e| e.into_inner()).exponent == *e)
                    .cloned()
            };
            if slot.is_none()
                && self
                    .inner
                    .slots
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .len()
                    >= self.inner.opts.max_syndrome_slots
            {
                continue;
            }
            // Hash only admitted payloads, and do not spend a slot on corrupt parity.
            if !r.verify(&src).map_err(io_ctx("verifying recovery slice"))? {
                continue;
            }
            let slot = match slot {
                Some(s) => s,
                None => {
                    let mut list = self.inner.slots.write().unwrap_or_else(|e| e.into_inner());
                    if list.len() >= self.inner.opts.max_syndrome_slots {
                        continue;
                    }
                    let total = self.inner.logs.len();
                    let s = Arc::new(Mutex::new(SyndromeSlot {
                        exponent: *e,
                        data: vec![0u8; ss],
                        folded_mask: BitVec::new(total),
                        recovery_added: false,
                    }));
                    list.push(Arc::clone(&s));
                    need_backfill = true;
                    s
                }
            };
            let mut data = vec![0u8; ss];
            r.read_data(&src, 0, &mut data)
                .map_err(io_ctx("reading recovery slice"))?;
            // Split layout for XOR into the slot.
            let mut split = vec![0u8; ss];
            {
                let (lo, hi) = split.split_at_mut(ss / 2);
                self.inner.opts.kernel.deinterleave(&data, lo, hi);
            }
            {
                let mut s = slot.lock().unwrap_or_else(|e| e.into_inner());
                if !s.recovery_added {
                    for (d, x) in s.data.iter_mut().zip(&split) {
                        *d ^= x;
                    }
                    s.recovery_added = true;
                }
            }
            let mut t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
            t.ready_exponents.insert(*e);
            absorbed += 1;
        }
        {
            let mut t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
            t.par_files.push(path.to_path_buf());
            if let Some(id) = queued_id {
                t.unpaused_in_flight.remove(&id);
                if let Some(v) = t.queued_volumes.iter_mut().find(|v| v.id == id) {
                    v.paused = false;
                }
            }
        }
        if need_backfill {
            self.backfill_slots()?;
        }
        Ok(absorbed)
    }

    // -----------------------------------------------------------------------------------------
    // 3. Mid-download volume repair
    // -----------------------------------------------------------------------------------------

    /// Mode A—live donor / twin splicing. `candidate_bytes` cover `hole_range` of the file
    /// (from a duplicate posting or twin set); they are combined in RAM with the on-disk bytes
    /// of every touched slice and verified against IFSC. Matching slices are written to
    /// `disk_file`, marked verified, and folded. Returns the healed slice indices.
    pub fn try_splice_live_slice(
        &self,
        file_id: &FileId,
        hole_range: ByteRange,
        candidate_bytes: &[u8],
        disk_file: &Path,
    ) -> Result<Vec<usize>, RepairError> {
        let _payload = self
            .inner
            .payload_gate
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let _permit = self.inner.admit_payload();
        let fi = self.file(file_id)?;
        let f = &self.inner.files[fi];
        let ss = self.inner.slice_size as u64;
        if hole_range.is_empty()
            || (candidate_bytes.len() as i64) < hole_range.size
            || hole_range.offset < 0
            || f.slice_count == 0
        {
            return Ok(Vec::new());
        }
        let hs = hole_range.offset as u64;
        let he = (hole_range.end() as u64).min(f.length);
        if hs >= he {
            return Ok(Vec::new());
        }
        let (b0, b1) = ((hs / ss) as usize, ((he - 1) / ss) as usize);
        let fh = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(disk_file)
            .map_err(io_ctx(format!("opening {}", disk_file.display())))?;
        let disk_len = fh.metadata().map(|m| m.len()).unwrap_or(0);
        let mut healed = Vec::new();
        for b in b0..=b1.min(f.slice_count - 1) {
            let g = f.first_slice + b;
            {
                let t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
                if t.states[g] == SliceState::VerifiedGood {
                    continue;
                }
            }
            let sstart = b as u64 * ss;
            let send = (sstart + ss).min(f.length);
            let slen = (send - sstart) as usize;
            let mut buf = vec![0u8; slen];
            let avail = disk_len.saturating_sub(sstart).min(slen as u64) as usize;
            if avail > 0 {
                read_exact_at(&fh, sstart, &mut buf[..avail])
                    .map_err(io_ctx(format!("reading {}", disk_file.display())))?;
            }
            let s = hs.max(sstart);
            let e = he.min(send);
            buf[(s - sstart) as usize..(e - sstart) as usize]
                .copy_from_slice(&candidate_bytes[(s - hs) as usize..(e - hs) as usize]);
            let Some(data) = self.verify_slice_bytes_direct(fi, b, buf)? else {
                continue;
            };
            write_all_at(&fh, sstart, &data)
                .map_err(io_ctx(format!("writing {}", disk_file.display())))?;
            let mut t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
            if t.states[g] == SliceState::VerifiedGood {
                continue;
            }
            if let Some(st) = t.staging.remove(&g) {
                t.staging_bytes -= st.buf.len() as u64;
            }
            Self::set_state(&mut t, g, SliceState::VerifiedGood);
            drop(t);
            self.fold(g, data);
            healed.push(b);
        }
        if !healed.is_empty() {
            fh.sync_data().ok();
        }
        Ok(healed)
    }

    fn verify_slice_bytes_direct(
        &self,
        fi: usize,
        b: usize,
        data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, RepairError> {
        self.verify_slice_bytes(fi, b, Some(data), None)
    }

    /// Mode B—early Reed-Solomon cutover. When `D + U <= R`, treat every non-verified slice
    /// as an erasure, invert the `K×K` recovery matrix and compute **only** the rows for the
    /// non-verified slices of `target_file_ids`, patching them into the target files on disk.
    /// Each target's whole-file MD5 is checked afterwards.
    pub fn repair_available_targets_now(
        &self,
        target_file_ids: &[FileId],
    ) -> Result<EarlyRepairReport, RepairError> {
        let _payload = self
            .inner
            .payload_gate
            .write()
            .unwrap_or_else(|e| e.into_inner());
        for id in target_file_ids {
            self.file(id)?;
        }
        self.backfill_slots()?;
        let ss = self.inner.slice_size;
        let (missing, present, ready_exps): (Vec<usize>, Vec<bool>, Vec<u32>) = {
            let t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
            let present: Vec<bool> = t
                .states
                .iter()
                .map(|s| *s == SliceState::VerifiedGood)
                .collect();
            let missing: Vec<usize> = (0..present.len()).filter(|&g| !present[g]).collect();
            (
                missing,
                present,
                t.ready_exponents.iter().copied().collect(),
            )
        };
        let k = missing.len();
        if k > ready_exps.len() {
            return Err(RepairError::NotEnoughRecovery {
                needed: k as u64,
                available: ready_exps.len() as u64,
            });
        }
        // Rows to compute: non-verified slices of the target files.
        let mut rows: Vec<usize> = Vec::new();
        for id in target_file_ids {
            let f = &self.inner.files[self.inner.file_index[id]];
            rows.extend((f.first_slice..f.first_slice + f.slice_count).filter(|&g| !present[g]));
        }
        rows.sort_unstable();
        rows.dedup();
        let mut report = EarlyRepairReport {
            erasures: k,
            recovery_used: 0,
            repaired_slices: Vec::new(),
            files: Vec::new(),
        };
        if rows.is_empty() || k == 0 {
            for id in target_file_ids {
                let (st, ok) = self.check_target(id)?;
                report.files.push((*id, st, ok));
            }
            return Ok(report);
        }
        crate::repairer::check_recovery_matrix_memory(
            k as u64,
            self.inner.opts.solve_mem_limit_bytes,
        )?;
        let plan = plan_recovery(
            &self.inner.logs,
            &present,
            &ready_exps,
            &self.inner.opts.kernel,
        )
        .map_err(|e| match e {
            crate::reed_solomon::RsError::NotEnoughRecovery { needed, available } => {
                RepairError::NotEnoughRecovery {
                    needed: needed as u64,
                    available: available as u64,
                }
            }
            _ => RepairError::Singular,
        })?;
        report.recovery_used = plan.used_exponents.len();
        // Sub-matrix: the rows of A⁻¹ for the requested slices.
        let mut sub = Matrix::zeros(rows.len(), k);
        for (ri, &g) in rows.iter().enumerate() {
            let m = plan
                .missing
                .iter()
                .position(|&x| x == g)
                .expect("row is missing");
            for j in 0..k {
                sub.set(ri, j, plan.inverse.get(m, j));
            }
        }
        // Take the used syndromes out of their slots for the duration of the solve.
        self.flush();
        let slots: Vec<Arc<Mutex<SyndromeSlot>>> = self
            .inner
            .slots
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut taken = TakenSyndromes {
            slots: Vec::with_capacity(k),
            data: Vec::with_capacity(k),
        };
        for &e in &plan.used_exponents {
            let slot = slots
                .iter()
                .find(|s| s.lock().unwrap_or_else(|e| e.into_inner()).exponent == e)
                .expect("ready exponent has a slot")
                .clone();
            let data = std::mem::take(&mut slot.lock().unwrap_or_else(|e| e.into_inner()).data);
            taken.slots.push(slot);
            taken.data.push(data);
        }
        let specs: Vec<InputSpec> = (0..k)
            .map(|j| InputSpec {
                kind: InputKind::Recovery { output: j },
                source: j,
            })
            .collect();
        let reader = RepairReader {
            files: Vec::new(),
            by_path: HashMap::new(),
            slices: (0..k).map(SliceSrc::Mem).collect(),
            mem: &taken.data,
            kernel: self.inner.opts.kernel,
        };
        // Outputs: rows → (file, offset, len); patch directly into the target files.
        let mut out_map: Vec<(usize, u64, u64)> = Vec::with_capacity(rows.len());
        let mut targets: HashMap<usize, File> = HashMap::new();
        for &g in &rows {
            let fi = self
                .inner
                .files
                .iter()
                .position(|f| g >= f.first_slice && g < f.first_slice + f.slice_count)
                .expect("slice belongs to a file");
            let f = &self.inner.files[fi];
            if let std::collections::hash_map::Entry::Vacant(slot) = targets.entry(fi) {
                if let Some(p) = f.target_path.parent() {
                    std::fs::create_dir_all(p)
                        .map_err(io_ctx(format!("creating {}", p.display())))?;
                }
                let fh = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&f.target_path)
                    .map_err(io_ctx(format!("opening {}", f.target_path.display())))?;
                if fh.metadata().map(|m| m.len()).unwrap_or(0) < f.length {
                    fh.set_len(f.length)
                        .map_err(io_ctx(format!("sizing {}", f.target_path.display())))?;
                }
                slot.insert(fh);
            }
            let off = (g - f.first_slice) as u64 * ss as u64;
            out_map.push((fi, off, (f.length - off).min(ss as u64)));
        }
        let mut recon: Vec<Vec<u8>> = rows.iter().map(|_| vec![0; ss]).collect();
        let mut sink = |output: usize, offset: u64, data: &[u8]| -> io::Result<()> {
            let (fi, block_off, block_len) = out_map[output];
            let buf = &mut recon[output];
            buf[offset as usize..offset as usize + data.len()].copy_from_slice(data);
            if offset < block_len {
                let n = ((block_len - offset) as usize).min(data.len());
                write_all_at(&targets[&fi], block_off + offset, &data[..n])?;
            }
            Ok(())
        };
        let config = EngineConfig {
            num_threads: self.inner.opts.solve_threads,
            mem_limit_bytes: self.inner.opts.solve_mem_limit_bytes,
            ..EngineConfig::default()
        };
        let engine = Engine {
            slice_size: ss as u64,
            inputs: &specs,
            output_exponents: &plan.used_exponents,
            post_transform: Some(&sub),
            config,
            kernel: self.inner.opts.kernel,
        };
        let run = engine.run(
            &reader,
            &mut sink as &mut dyn OutputSink,
            None,
            &mut |_, _, _, _| {},
        );
        // Return the syndromes to their slots before handling the result.
        drop(taken);
        run.map_err(|e| match e {
            crate::reed_solomon::RsError::Io(e) => RepairError::Io {
                context: "early repair".into(),
                source: e,
            },
            crate::reed_solomon::RsError::Cancelled => RepairError::Cancelled,
            _ => RepairError::Singular,
        })?;
        for fh in targets.values() {
            fh.sync_data().ok();
        }
        // Mark and fold the reconstructed slices so later solves see them as verified.
        for (ri, &g) in rows.iter().enumerate() {
            let fi = self
                .inner
                .files
                .iter()
                .position(|f| g >= f.first_slice && g < f.first_slice + f.slice_count)
                .expect("file");
            let f = &self.inner.files[fi];
            let b = g - f.first_slice;
            let (_, _, block_len) = out_map[ri];
            let mut data = std::mem::take(&mut recon[ri]);
            data.truncate(block_len as usize);
            {
                let mut t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(st) = t.staging.remove(&g) {
                    t.staging_bytes -= st.buf.len() as u64;
                }
                Self::set_state(&mut t, g, SliceState::VerifiedGood);
            }
            self.fold(g, data);
            report.repaired_slices.push((f.file_id, b));
        }
        for id in target_file_ids {
            let (st, ok) = self.check_target(id)?;
            report.files.push((*id, st, ok));
        }
        Ok(report)
    }

    /// Volume status plus whole-file MD5 check (only performed when all slices are verified).
    fn check_target(&self, id: &FileId) -> Result<(VolumeStatus, bool), RepairError> {
        let fi = self.inner.file_index[id];
        let f = &self.inner.files[fi];
        let st = {
            let t = self.inner.tracker.lock().unwrap_or_else(|e| e.into_inner());
            Self::volume_status_locked(&t, f)
        };
        let ok = if st == VolumeStatus::CompleteAndVerified {
            crate::hasher::hash_file(&f.target_path)
                .map(|h| h.md5_full == f.hash_full && h.len == f.length)
                .unwrap_or(false)
        } else {
            false
        };
        Ok((st, ok))
    }
}

// Session must be usable from any thread.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<StreamingParSession>();
};

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::crc::crc32;
    use crate::create::{CreateOptions, SourceFile, VolumeScheme, create};
    use crate::packet::{PacketIter, PacketType, ScanOptions, load_par2_file};
    use std::path::Path;

    fn rnd(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 47) as u8
            })
            .collect()
    }

    struct Fx {
        dir: PathBuf,
        files: Vec<(String, Vec<u8>)>,
        set: PacketSet,
        vols: Vec<PathBuf>,
    }

    /// Set with one recovery block per volume so the scheduler has many volumes to choose from.
    fn fixture(tag: &str, sizes: &[usize], slice: u64, recovery: u32, scheme: VolumeScheme) -> Fx {
        let dir = std::env::temp_dir().join(format!("par-rs-live-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut files = Vec::new();
        let mut sources = Vec::new();
        for (i, &n) in sizes.iter().enumerate() {
            let name = format!("part{i:02}.rar");
            let data = rnd(n, 9000 + i as u64);
            std::fs::write(dir.join(&name), &data).unwrap();
            sources.push(SourceFile::new(dir.join(&name)));
            files.push((name, data));
        }
        let opts = CreateOptions {
            slice_size: slice,
            recovery_blocks: recovery,
            volumes: scheme,
            ..CreateOptions::default()
        };
        let rep = create(&sources, &dir, "set", &opts, None, &mut |_, _, _| {}).unwrap();
        for (n, _) in &files {
            std::fs::remove_file(dir.join(n)).unwrap();
        }
        let set = load_par2_file(&rep.files[0], ScanOptions::FULL).unwrap();
        Fx {
            dir,
            files,
            set,
            vols: rep.files[1..].to_vec(),
        }
    }

    fn fid(fx: &Fx, name: &str) -> FileId {
        fx.set
            .file_descs
            .values()
            .find(|d| d.name == name.as_bytes())
            .unwrap()
            .file_id
    }

    fn write_at(path: &Path, off: u64, data: &[u8]) {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)
            .unwrap();
        write_all_at(&f, off, data).unwrap();
    }

    fn shuffled(n: usize, seed: u64) -> Vec<usize> {
        let mut v: Vec<usize> = (0..n).collect();
        let mut s = seed | 1;
        for i in (1..n).rev() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            v.swap(i, (s % (i as u64 + 1)) as usize);
        }
        v
    }

    fn vol_blocks(p: &Path) -> i32 {
        crate::filenames::volume_blocks_bytes(&crate::filenames::os_str_bytes(
            p.file_name().unwrap(),
        ))
        .unwrap() as i32
    }

    #[test]
    fn bitvec_basics() {
        let mut b = BitVec::new(130);
        assert!(!b.get(0) && !b.get(129) && !b.get(5000));
        assert!(b.set(129));
        assert!(!b.set(129));
        assert!(b.set(0));
        assert_eq!(b.count_ones(), 2);
        assert!(b.get(129));
    }

    #[test]
    fn tracker_states_scheduler_and_in_flight_accounting() {
        let fx = fixture(
            "sched",
            &[20_000, 10_000],
            1000,
            12,
            VolumeScheme::Uniform(1),
        );
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                preallocated_syndrome_slots: 4,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(s.set_id(), fx.set.set_id.unwrap());
        assert_eq!(s.slice_size(), 1000);
        // Twelve paused one-block volumes in the queue.
        for (i, v) in fx.vols.iter().enumerate() {
            s.register_queued_volume(QueuedVolume {
                id: 100 + i as u64,
                blocks: vol_blocks(v),
                paused: true,
            });
        }
        let f0 = fid(&fx, "part00.rar");
        let f1 = fid(&fx, "part01.rar");
        let d0 = &fx.files[0].1;
        let p0 = fx.dir.join("part00.rar");
        std::fs::File::create(&p0)
            .unwrap()
            .set_len(d0.len() as u64)
            .unwrap();
        // Articles of 700 bytes; first article arrives → slice 0 partially arrived.
        write_at(&p0, 0, &d0[..700]);
        let out = s
            .on_article_finished(&f0, 0, 700, crc32(&d0[..700]), None)
            .unwrap();
        assert!(out.events.is_empty());
        assert_eq!(
            s.slice_state(&f0, 0).unwrap(),
            SliceState::PartiallyArrived {
                covered: vec![ByteRange::new(0, 700)]
            }
        );
        assert_eq!(s.status().partially_arrived, 1);
        // Second article completes slice 0 and partially covers slice 1.
        write_at(&p0, 700, &d0[700..1400]);
        let out = s
            .on_article_finished(&f0, 700, 700, crc32(&d0[700..1400]), Some(&d0[700..1400]))
            .unwrap();
        assert_eq!(
            out.events,
            vec![SliceEvent {
                file_id: f0,
                slice_idx: 0,
                state: SliceState::VerifiedGood
            }]
        );
        assert!(out.unpause.is_none());
        assert_eq!(s.status().verified, 1);
        // Permanent failure of an article spanning slices 2 and 3 → damaged, 2 blocks needed → unpause two 1-block volumes.
        let (ev, action) = s.on_article_failed_permanently(&f0, 2900, 700).unwrap();
        assert_eq!(ev.len(), 2);
        assert!(ev.iter().all(|e| e.state == SliceState::Damaged));
        let action = action.unwrap();
        assert_eq!(action.volume_ids_to_unpause.len(), 2);
        assert_eq!(action.blocks_requested, 2);
        assert_eq!(action.shortfall, 0);
        let st = s.status();
        assert_eq!(st.damaged, 2);
        assert_eq!(st.unpaused_in_flight, 2);
        assert_eq!(st.needed_recovery_blocks, 0);
        // Another failure: one more block needed → one more volume, not the already unpaused ones.
        let (_, action2) = s.on_article_failed_permanently(&f0, 5000, 10).unwrap();
        let action2 = action2.unwrap();
        assert_eq!(action2.volume_ids_to_unpause.len(), 1);
        assert!(
            !action
                .volume_ids_to_unpause
                .contains(&action2.volume_ids_to_unpause[0])
        );
        // Repeated failure on the same slice: no new action.
        let (ev, action3) = s.on_article_failed_permanently(&f0, 5000, 10).unwrap();
        assert!(ev.is_empty() && action3.is_none());
        // Unpaused volumes arrive: in-flight drops, ready rises.
        for id in action
            .volume_ids_to_unpause
            .iter()
            .chain(action2.volume_ids_to_unpause.iter())
        {
            let v = &fx.vols[(*id - 100) as usize];
            assert_eq!(s.on_recovery_volume_arrived(v, Some(*id)).unwrap(), 1);
        }
        let st = s.status();
        assert_eq!(st.unpaused_in_flight, 0);
        assert_eq!(st.ready_recovery, 3);
        assert_eq!(st.needed_recovery_blocks, 0);
        // Unknown file / bad index.
        assert!(matches!(
            s.on_article_finished(&FileId([9; 16]), 0, 1, 0, None),
            Err(RepairError::UnknownFile(_))
        ));
        assert!(matches!(
            s.slice_state(&f1, 999),
            Err(RepairError::UnknownFile(_))
        ));
        assert_eq!(
            s.volume_status(&f1).unwrap(),
            VolumeStatus::Incomplete {
                verified: 0,
                damaged: 0,
                unarrived: 10
            }
        );
        // Out-of-range articles are ignored.
        assert!(
            s.on_article_finished(&f0, 10_000_000, 5, 0, None)
                .unwrap()
                .events
                .is_empty()
        );
        assert!(
            s.on_article_failed_permanently(&f0, 10_000_000, 5)
                .unwrap()
                .0
                .is_empty()
        );
        // Scheduler shortfall when nothing is left to unpause.
        for b in 6..20 {
            let _ = s.on_article_failed_permanently(&f0, b * 1000, 1).unwrap();
        }
        let (_, act) = s.on_article_failed_permanently(&f1, 0, 10_000).unwrap();
        let act = act.unwrap();
        assert!(act.shortfall > 0);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    /// Full download simulation: articles in random order, some lost, volumes paused until the
    /// scheduler asks for them; at the end an early cutover repairs everything without any
    /// re-read of the data files.
    fn simulate(fold_threads: usize, with_bytes: bool) {
        let fx = fixture(
            &format!("sim{fold_threads}{with_bytes}"),
            &[60_000, 35_000, 12_345],
            1000,
            16,
            VolumeScheme::Uniform(2),
        );
        let opts = SessionOptions {
            preallocated_syndrome_slots: 6,
            fold_threads,
            fold_queue_depth: 2,
            ..Default::default()
        };
        let s = StreamingParSession::new(&fx.set, &fx.dir, opts).unwrap();
        for (i, v) in fx.vols.iter().enumerate() {
            s.register_queued_volume(QueuedVolume {
                id: i as u64,
                blocks: vol_blocks(v),
                paused: true,
            });
        }
        let article = 650usize;
        let mut arrived_vols = std::collections::BTreeSet::new();
        let mut lost = 0;
        for (name, data) in &fx.files {
            let id = fid(&fx, name);
            let path = fx.dir.join(name);
            std::fs::File::create(&path)
                .unwrap()
                .set_len(data.len() as u64)
                .unwrap();
            let n = data.len().div_ceil(article);
            for si in shuffled(n, 31) {
                let off = si * article;
                let end = (off + article).min(data.len());
                if name == "part00.rar" && si % 13 == 5 {
                    lost += 1;
                    let (_, act) = s
                        .on_article_failed_permanently(&id, off as u64, (end - off) as u64)
                        .unwrap();
                    if let Some(a) = act {
                        for vid in a.volume_ids_to_unpause {
                            // The unpaused volume "downloads" immediately.
                            s.on_recovery_volume_arrived(&fx.vols[vid as usize], Some(vid))
                                .unwrap();
                            arrived_vols.insert(vid);
                        }
                    }
                    continue;
                }
                write_at(&path, off as u64, &data[off..end]);
                let out = s
                    .on_article_finished(
                        &id,
                        off as u64,
                        (end - off) as u64,
                        crc32(&data[off..end]),
                        with_bytes.then_some(&data[off..end]),
                    )
                    .unwrap();
                assert!(out.unpause.is_none());
            }
        }
        assert!(lost > 0);
        s.flush();
        let st = s.status();
        assert_eq!(st.unarrived + st.partially_arrived, 0);
        assert!(st.damaged > 0);
        assert!(st.early_cutover_possible, "{st:?}");
        assert_eq!(st.pending_folds, 0);
        let (folds, _) = s.fold_stats();
        assert_eq!(folds, st.verified as u64);
        // Repair only part00 (the others are complete already).
        let f0 = fid(&fx, "part00.rar");
        let rep = s.repair_available_targets_now(&[f0]).unwrap();
        assert_eq!(rep.erasures, st.damaged);
        assert_eq!(rep.repaired_slices.len(), st.damaged);
        assert_eq!(
            rep.files,
            vec![(f0, VolumeStatus::CompleteAndVerified, true)]
        );
        for (n, d) in &fx.files {
            assert_eq!(std::fs::read(fx.dir.join(n)).unwrap(), *d, "{n}");
        }
        assert_eq!(s.status().damaged, 0);
        assert!(s.status().early_cutover_possible);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn download_simulation_inline_folding() {
        simulate(0, true);
    }

    #[test]
    fn download_simulation_folder_pool_disk_bytes() {
        simulate(3, false);
    }

    #[test]
    fn concurrent_article_writers() {
        let fx = fixture("conc", &[80_000, 40_000], 1000, 8, VolumeScheme::Single);
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                preallocated_syndrome_slots: 8,
                fold_threads: 2,
                fold_queue_depth: 1,
                ..Default::default()
            },
        )
        .unwrap();
        for (name, data) in &fx.files {
            std::fs::File::create(fx.dir.join(name))
                .unwrap()
                .set_len(data.len() as u64)
                .unwrap();
        }
        // 4 writer threads share the session; each handles an interleaved subset of articles.
        let article = 1000usize;
        std::thread::scope(|sc| {
            for w in 0..4 {
                let s = s.clone();
                let fx = &fx;
                sc.spawn(move || {
                    for (name, data) in &fx.files {
                        let id = fid(fx, name);
                        let path = fx.dir.join(name);
                        let n = data.len().div_ceil(article);
                        for si in (0..n).filter(|i| i % 4 == w) {
                            let off = si * article;
                            let end = (off + article).min(data.len());
                            // Slice 7 of part00 is lost.
                            if name == "part00.rar" && si == 7 {
                                s.on_article_failed_permanently(
                                    &id,
                                    off as u64,
                                    (end - off) as u64,
                                )
                                .unwrap();
                                continue;
                            }
                            write_at(&path, off as u64, &data[off..end]);
                            s.on_article_finished(
                                &id,
                                off as u64,
                                (end - off) as u64,
                                crc32(&data[off..end]),
                                Some(&data[off..end]),
                            )
                            .unwrap();
                        }
                    }
                });
            }
        });
        s.flush();
        let st = s.status();
        assert_eq!(st.verified, 119);
        assert_eq!(st.damaged, 1);
        assert_eq!(st.pending_folds, 0);
        let (folds, inline) = s.fold_stats();
        assert_eq!(folds, 119);
        let _ = inline; // may or may not have overflowed the tiny queue
        s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap();
        let f0 = fid(&fx, "part00.rar");
        let rep = s.repair_available_targets_now(&[f0]).unwrap();
        assert_eq!(rep.repaired_slices, vec![(f0, 7)]);
        assert_eq!(
            std::fs::read(fx.dir.join("part00.rar")).unwrap(),
            fx.files[0].1
        );
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn session_memory_rejects_huge_slices_before_allocation() {
        let mut fx = fixture("session_huge", &[4096], 4096, 0, VolumeScheme::Single);
        fx.set.main.as_mut().unwrap().slice_size = 1 << 40;
        assert!(matches!(
            StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()),
            Err(RepairError::StreamingMemoryLimit { .. })
        ));
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn session_memory_caps_growth_and_folder_backlog() {
        let fx = fixture(
            "session_growth",
            &[4 * 65536],
            65536,
            4,
            VolumeScheme::Uniform(1),
        );
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                preallocated_syndrome_slots: 1,
                max_syndrome_bytes: 2 * 65536,
                max_working_bytes: 1 << 20,
                fold_threads: 128,
                fold_queue_depth: 128,
                ..Default::default()
            },
        )
        .unwrap();
        let o = &s.inner.opts;
        assert!(
            (o.fold_threads * (o.fold_queue_depth + 1)) as u64 * 65536
                + (o.max_working_bytes / (2 * 65536)) * 65536
                <= o.max_working_bytes
        );
        assert!(o.max_staging_bytes <= o.max_working_bytes);
        let absorbed: usize = fx
            .vols
            .iter()
            .map(|v| s.on_recovery_volume_arrived(v, None).unwrap())
            .sum();
        assert_eq!(absorbed, 2);
        assert_eq!(s.status().syndrome_slots, 2);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn session_memory_valid_duplicate_survives_corrupt_packet() {
        let fx = fixture("session_duplicate", &[4096], 4096, 1, VolumeScheme::Single);
        let parity = load_par2_file(&fx.vols[0], ScanOptions::FULL).unwrap();
        let r = parity.recovery.values().next().unwrap();
        let original = std::fs::read(&fx.vols[0]).unwrap();
        let start = r.packet_offset as usize;
        let mut prefixed = original[start..start + r.header_length() as usize].to_vec();
        prefixed[(r.data_offset - r.packet_offset) as usize] ^= 1;
        prefixed.extend_from_slice(&original);
        std::fs::write(&fx.vols[0], prefixed).unwrap();
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                max_syndrome_slots: 1,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap(), 1);
        let id = fid(&fx, "part00.rar");
        s.repair_available_targets_now(&[id]).unwrap();
        assert_eq!(
            std::fs::read(fx.dir.join("part00.rar")).unwrap(),
            fx.files[0].1
        );
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn session_memory_corrupt_parity_does_not_consume_a_slot() {
        let fx = fixture(
            "session_corrupt",
            &[8192],
            4096,
            2,
            VolumeScheme::Uniform(1),
        );
        let parity = load_par2_file(&fx.vols[0], ScanOptions::FULL).unwrap();
        let r = parity.recovery.values().next().unwrap();
        let mut data = std::fs::read(&fx.vols[0]).unwrap();
        data[r.data_offset as usize] ^= 1;
        std::fs::write(&fx.vols[0], data).unwrap();
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                preallocated_syndrome_slots: 0,
                max_syndrome_bytes: 4096,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap(), 0);
        assert_eq!(s.status().syndrome_slots, 0);
        assert_eq!(s.on_recovery_volume_arrived(&fx.vols[1], None).unwrap(), 1);
        assert_eq!(s.status().ready_recovery, 1);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn session_memory_bulk_article_does_not_reread_supplied_bytes() {
        let fx = fixture("session_bulk_bytes", &[8192], 4096, 0, VolumeScheme::Single);
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                max_staging_bytes: 4096,
                ..Default::default()
            },
        )
        .unwrap();
        let id = fid(&fx, "part00.rar");
        let data = &fx.files[0].1;
        assert!(!fx.dir.join("part00.rar").exists());
        s.on_article_finished(&id, 0, data.len() as u64, crc32(data), Some(data))
            .unwrap();
        assert_eq!(s.status().verified, 2);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn session_memory_releases_completed_staging_on_error() {
        let fx = fixture("session_staging", &[8192], 4096, 0, VolumeScheme::Single);
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                max_staging_bytes: 4096,
                ..Default::default()
            },
        )
        .unwrap();
        let id = fid(&fx, "part00.rar");
        let data = &fx.files[0].1;
        // Complete a previously reported tail with an article that cannot supply
        // all bytes of the second slice; that slice must read the missing file.
        s.on_article_finished(&id, 6144, 2048, crc32(&data[6144..]), None)
            .unwrap();
        assert!(matches!(
            s.on_article_finished(&id, 0, 6144, crc32(&data[..6144]), Some(&data[..6144])),
            Err(RepairError::Io { .. })
        ));
        assert_eq!(s.inner.tracker.lock().unwrap().staging_bytes, 0);
        std::fs::write(fx.dir.join("part00.rar"), data).unwrap();
        s.on_article_finished(&id, 0, data.len() as u64, crc32(data), None)
            .unwrap();
        assert_eq!(s.status().verified, 2);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn session_memory_caps_default_preallocation() {
        let fx = fixture("session_bytes", &[4096], 4 << 20, 0, VolumeScheme::Single);
        let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
        assert!(
            s.status().syndrome_slots <= 16,
            "{} slots",
            s.status().syndrome_slots
        );
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn session_memory_restores_syndromes_after_target_open_error() {
        let fx = fixture("session_restore", &[8192], 4096, 2, VolumeScheme::Single);
        let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
        s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap();
        let before: Vec<Vec<u8>> = s
            .inner
            .slots
            .read()
            .unwrap()
            .iter()
            .map(|slot| slot.lock().unwrap().data.clone())
            .collect();
        let target = fx.dir.join("part00.rar");
        std::fs::create_dir(&target).unwrap();
        let id = fid(&fx, "part00.rar");
        assert!(matches!(
            s.repair_available_targets_now(&[id]),
            Err(RepairError::Io { .. })
        ));
        let after: Vec<Vec<u8>> = s
            .inner
            .slots
            .read()
            .unwrap()
            .iter()
            .map(|slot| slot.lock().unwrap().data.clone())
            .collect();
        assert_eq!(after, before, "failed repair lost syndrome contents");
        std::fs::remove_dir(&target).unwrap();
        s.repair_available_targets_now(&[id]).unwrap();
        assert_eq!(std::fs::read(target).unwrap(), fx.files[0].1);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn early_cutover_rejects_oversized_matrix_before_target_creation() {
        let fx = fixture("matrix_budget", &[1449 * 4], 4, 1449, VolumeScheme::Single);
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                solve_mem_limit_bytes: 16 << 20,
                max_syndrome_slots: 1449,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap(),
            1449
        );
        let id = fid(&fx, "part00.rar");
        assert!(matches!(
            s.repair_available_targets_now(&[id]),
            Err(RepairError::RecoveryMemoryLimit {
                missing_blocks: 1449,
                ..
            })
        ));
        assert!(!fx.dir.join("part00.rar").exists());
        // A refused solve leaves the ready syndromes available for another attempt.
        assert_eq!(s.status().ready_recovery, 1449);
        assert!(
            s.inner
                .slots
                .read()
                .unwrap()
                .iter()
                .all(|slot| slot.lock().unwrap().data.len() == 4)
        );
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn early_cutover_repairs_target_volume_while_rest_still_downloading() {
        // part00 finished with 2 damaged slices; part01 and part02 (18 slices) not downloaded
        // yet; 24 recovery blocks available → D + U = 20 <= 24. Only part00 rows are computed.
        let fx = fixture(
            "early",
            &[30_000, 12_000, 6_000],
            1000,
            24,
            VolumeScheme::Single,
        );
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                preallocated_syndrome_slots: 24,
                ..Default::default()
            },
        )
        .unwrap();
        let f0 = fid(&fx, "part00.rar");
        let d0 = &fx.files[0].1;
        let p0 = fx.dir.join("part00.rar");
        std::fs::File::create(&p0)
            .unwrap()
            .set_len(d0.len() as u64)
            .unwrap();
        for si in 0..30 {
            let off = si * 1000;
            if matches!(si, 4 | 17) {
                s.on_article_failed_permanently(&f0, off as u64, 1000)
                    .unwrap();
                continue;
            }
            write_at(&p0, off as u64, &d0[off..off + 1000]);
            s.on_article_finished(&f0, off as u64, 1000, crc32(&d0[off..off + 1000]), None)
                .unwrap();
        }
        assert_eq!(
            s.volume_status(&f0).unwrap(),
            VolumeStatus::Incomplete {
                verified: 28,
                damaged: 2,
                unarrived: 0
            }
        );
        // Not possible before the volume arrives.
        assert!(matches!(
            s.repair_available_targets_now(&[f0]),
            Err(RepairError::NotEnoughRecovery {
                needed: 20,
                available: 0
            })
        ));
        assert_eq!(s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap(), 24);
        let st = s.status();
        assert!(st.early_cutover_possible);
        assert_eq!(st.ready_recovery, 24);
        let rep = s.repair_available_targets_now(&[f0]).unwrap();
        assert_eq!(rep.erasures, 20);
        assert_eq!(rep.recovery_used, 20);
        assert_eq!(rep.repaired_slices.len(), 2);
        assert_eq!(
            rep.files,
            vec![(f0, VolumeStatus::CompleteAndVerified, true)]
        );
        assert_eq!(std::fs::read(&p0).unwrap(), *d0);
        // The other parts were not touched (still absent).
        assert!(!fx.dir.join("part01.rar").exists());
        // Later the rest arrives normally and verifies; repairing them is a no-op.
        for (name, data) in fx.files.iter().skip(1) {
            let id = fid(&fx, name);
            let path = fx.dir.join(name);
            std::fs::write(&path, data).unwrap();
            s.on_article_finished(&id, 0, data.len() as u64, crc32(data), None)
                .unwrap();
            assert_eq!(
                s.volume_status(&id).unwrap(),
                VolumeStatus::CompleteAndVerified
            );
        }
        let all: Vec<FileId> = fx.files.iter().map(|(n, _)| fid(&fx, n)).collect();
        let rep = s.repair_available_targets_now(&all).unwrap();
        assert_eq!(rep.erasures, 0);
        assert!(rep.repaired_slices.is_empty());
        assert!(
            rep.files
                .iter()
                .all(|(_, st, ok)| *st == VolumeStatus::CompleteAndVerified && *ok)
        );
        // Or reconstruct a never-downloaded part entirely (U slices requested explicitly).
        let fx2 = fixture("early2", &[8_000, 5_000], 1000, 8, VolumeScheme::Single);
        let s2 = StreamingParSession::new(&fx2.set, &fx2.dir, SessionOptions::default()).unwrap();
        let (n0, d0) = &fx2.files[0];
        std::fs::write(fx2.dir.join(n0), d0).unwrap();
        s2.on_article_finished(&fid(&fx2, n0), 0, d0.len() as u64, crc32(d0), None)
            .unwrap();
        s2.on_recovery_volume_arrived(&fx2.vols[0], None).unwrap();
        let f1 = fid(&fx2, "part01.rar");
        let rep = s2.repair_available_targets_now(&[f1]).unwrap();
        assert_eq!(rep.repaired_slices.len(), 5);
        assert_eq!(
            std::fs::read(fx2.dir.join("part01.rar")).unwrap(),
            fx2.files[1].1
        );
        std::fs::remove_dir_all(&fx.dir).unwrap();
        std::fs::remove_dir_all(&fx2.dir).unwrap();
    }

    #[test]
    fn live_donor_splicing_mode_a() {
        // `D + U > R` prevents Reed-Solomon recovery, but a twin posting supplies the missing bytes.
        let fx = fixture("splice", &[20_000, 50_000], 1000, 2, VolumeScheme::Single);
        let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
        let f0 = fid(&fx, "part00.rar");
        let d0 = &fx.files[0].1;
        let p0 = fx.dir.join("part00.rar");
        std::fs::File::create(&p0)
            .unwrap()
            .set_len(d0.len() as u64)
            .unwrap();
        // Articles of 750 bytes; articles 3 and 10 lost (hole 2250..3000 and 7500..8250).
        for si in 0..27 {
            let off = si * 750;
            let end = (off + 750).min(d0.len());
            if matches!(si, 3 | 10) {
                s.on_article_failed_permanently(&f0, off as u64, (end - off) as u64)
                    .unwrap();
                continue;
            }
            write_at(&p0, off as u64, &d0[off..end]);
            s.on_article_finished(
                &f0,
                off as u64,
                (end - off) as u64,
                crc32(&d0[off..end]),
                None,
            )
            .unwrap();
        }
        // 2250..3000 → slice 2; 7500..8250 → slices 7 and 8.
        assert_eq!(
            s.volume_status(&f0).unwrap(),
            VolumeStatus::Incomplete {
                verified: 17,
                damaged: 3,
                unarrived: 0
            }
        );
        assert!(!s.status().early_cutover_possible);
        // Wrong donor bytes: nothing healed.
        let bogus = vec![0xEEu8; 750];
        assert!(
            s.try_splice_live_slice(&f0, ByteRange::new(2250, 750), &bogus, &p0)
                .unwrap()
                .is_empty()
        );
        // Correct donor bytes for the first hole.
        let healed = s
            .try_splice_live_slice(&f0, ByteRange::new(2250, 750), &d0[2250..3000], &p0)
            .unwrap();
        assert_eq!(healed, vec![2]);
        // Second hole spans slices 7 and 8.
        let healed = s
            .try_splice_live_slice(&f0, ByteRange::new(7500, 750), &d0[7500..8250], &p0)
            .unwrap();
        assert_eq!(healed, vec![7, 8]);
        // Remaining damaged slices (if any) come from articles whose other half was also lost.
        let st = s.volume_status(&f0).unwrap();
        if st != VolumeStatus::CompleteAndVerified {
            // Heal whatever is left with donor bytes for the whole file.
            let healed = s
                .try_splice_live_slice(&f0, ByteRange::new(0, d0.len() as i64), d0, &p0)
                .unwrap();
            assert!(!healed.is_empty());
        }
        assert_eq!(
            s.volume_status(&f0).unwrap(),
            VolumeStatus::CompleteAndVerified
        );
        assert_eq!(std::fs::read(&p0).unwrap(), *d0);
        // Already-verified slices are skipped; empty / invalid ranges ignored.
        assert!(
            s.try_splice_live_slice(&f0, ByteRange::new(0, 1000), d0, &p0)
                .unwrap()
                .is_empty()
        );
        assert!(
            s.try_splice_live_slice(&f0, ByteRange::new(0, 0), d0, &p0)
                .unwrap()
                .is_empty()
        );
        assert!(
            s.try_splice_live_slice(&f0, ByteRange::new(5, 10), &d0[..3], &p0)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            s.try_splice_live_slice(&FileId([1; 16]), ByteRange::new(0, 1), d0, &p0),
            Err(RepairError::UnknownFile(_))
        ));
        // Healed slices were folded: with the single 2-block volume, a later 1-slice loss in
        // part01 is repairable using the syndromes.
        let f1 = fid(&fx, "part01.rar");
        let d1 = &fx.files[1].1;
        let p1 = fx.dir.join("part01.rar");
        std::fs::File::create(&p1)
            .unwrap()
            .set_len(d1.len() as u64)
            .unwrap();
        for si in 0..50 {
            let off = si * 1000;
            if si == 25 {
                s.on_article_failed_permanently(&f1, off as u64, 1000)
                    .unwrap();
                continue;
            }
            write_at(&p1, off as u64, &d1[off..off + 1000]);
            s.on_article_finished(&f1, off as u64, 1000, crc32(&d1[off..off + 1000]), None)
                .unwrap();
        }
        s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap();
        let rep = s.repair_available_targets_now(&[f1]).unwrap();
        assert_eq!(rep.repaired_slices, vec![(f1, 25)]);
        assert_eq!(std::fs::read(&p1).unwrap(), *d1);
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn late_exponent_slot_allocation_backfills_from_disk_and_cap() {
        // Pre-allocate only exponents 0 and 1; the volume carries 0..5. Slots 2..4 are created
        // on arrival (cap 5) and back-filled from the already written target files.
        let fx = fixture("late", &[15_000, 9_000], 1000, 6, VolumeScheme::Single);
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                preallocated_syndrome_slots: 2,
                max_syndrome_slots: 5,
                max_staging_bytes: 0,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(s.status().syndrome_slots, 2);
        for (name, data) in &fx.files {
            let id = fid(&fx, name);
            let path = fx.dir.join(name);
            std::fs::File::create(&path)
                .unwrap()
                .set_len(data.len() as u64)
                .unwrap();
            for (si, chunk) in data.chunks(1000).enumerate() {
                if name == "part00.rar" && matches!(si, 1 | 6 | 11 | 14) {
                    s.on_article_failed_permanently(&id, (si * 1000) as u64, 1000)
                        .unwrap();
                    continue;
                }
                write_at(&path, (si * 1000) as u64, chunk);
                // Bytes offered but staging budget is 0 → verified from disk.
                s.on_article_finished(
                    &id,
                    (si * 1000) as u64,
                    chunk.len() as u64,
                    crc32(chunk),
                    Some(chunk),
                )
                .unwrap();
            }
        }
        assert_eq!(s.status().damaged, 4);
        assert_eq!(s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap(), 5); // The sixth exceeds the cap.
        let st = s.status();
        assert_eq!(st.syndrome_slots, 5);
        assert_eq!(st.ready_recovery, 5);
        assert!(st.early_cutover_possible);
        // Re-arrival of the same volume is a no-op.
        assert_eq!(s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap(), 0);
        let f0 = fid(&fx, "part00.rar");
        let rep = s.repair_available_targets_now(&[f0]).unwrap();
        assert_eq!(rep.repaired_slices.len(), 4);
        assert_eq!(rep.recovery_used, 4);
        assert_eq!(
            std::fs::read(fx.dir.join("part00.rar")).unwrap(),
            fx.files[0].1
        );
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }

    #[test]
    fn parquick_crc_precheck_rejects_corrupt_articles_without_md5() {
        let fx = fixture("quick", &[6_000], 1000, 2, VolumeScheme::Single);
        let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
        let f0 = fid(&fx, "part00.rar");
        let d0 = &fx.files[0].1;
        let p0 = fx.dir.join("part00.rar");
        std::fs::File::create(&p0)
            .unwrap()
            .set_len(d0.len() as u64)
            .unwrap();
        // Articles of 500 bytes tile each slice exactly → combined CRC path. Article 3 is
        // written corrupted but reported with the CRC of the corrupt bytes.
        for si in 0..12 {
            let off = si * 500;
            let mut chunk = d0[off..off + 500].to_vec();
            if si == 3 {
                chunk[7] ^= 1;
            }
            write_at(&p0, off as u64, &chunk);
            let out = s
                .on_article_finished(&f0, off as u64, 500, crc32(&chunk), None)
                .unwrap();
            if si == 3 {
                assert_eq!(
                    out.events,
                    vec![SliceEvent {
                        file_id: f0,
                        slice_idx: 1,
                        state: SliceState::Damaged
                    }]
                );
                // Nothing queued: the scheduler reports the shortfall instead of volumes.
                let a = out.unpause.as_ref().unwrap();
                assert!(
                    a.volume_ids_to_unpause.is_empty()
                        && a.blocks_requested == 0
                        && a.shortfall == 1
                );
            }
        }
        assert_eq!(
            s.volume_status(&f0).unwrap(),
            VolumeStatus::Incomplete {
                verified: 5,
                damaged: 1,
                unarrived: 0
            }
        );
        // Missing-IFSC set: slices can never be verified individually.
        let bytes = std::fs::read(fx.dir.join("set.par2")).unwrap();
        let raws: Vec<_> = PacketIter::new(&bytes[..], ScanOptions::UNVERIFIED)
            .map(|r| r.unwrap())
            .collect();
        let mut stripped = Vec::new();
        for r in raws {
            if r.header.kind() != PacketType::Ifsc {
                stripped.extend_from_slice(
                    &bytes[r.offset as usize..(r.offset + r.header.length) as usize],
                );
            }
        }
        let set2 = crate::packet::load_par2_bytes(&stripped, ScanOptions::FULL).unwrap();
        let s2 = StreamingParSession::new(&set2, &fx.dir, SessionOptions::default()).unwrap();
        let out = s2
            .on_article_finished(&f0, 0, 1000, crc32(&d0[..1000]), Some(&d0[..1000]))
            .unwrap();
        assert_eq!(out.events[0].state, SliceState::Damaged);
        // Session construction errors.
        let mut no_main = set2.clone();
        no_main.main = None;
        assert!(matches!(
            StreamingParSession::new(&no_main, &fx.dir, SessionOptions::default()),
            Err(RepairError::NoMainPacket)
        ));
        let mut no_desc = set2.clone();
        no_desc.file_descs.clear();
        assert!(matches!(
            StreamingParSession::new(&no_desc, &fx.dir, SessionOptions::default()),
            Err(RepairError::IncompleteMetadata { .. })
        ));
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }
}
