//! Verify and repair while the download is still in flight.
//!
//! PAR2 is linear, so the equation of each recovery exponent `e`,
//!
//! ```text
//! S̃_e = R_e ⊕ ⨁_{i ∈ Verified} C_i^e · D_i  =  ⨁_{j ∈ Damaged ∪ Pending} C_j^e · D_j ,
//! ```
//!
//! can be accumulated one verified slice at a time. [`SyndromeBank`] keeps one `slice_size`
//! buffer per tracked exponent: a verified input slice is multiplied into every buffer in a
//! single cache-tiled SIMD pass and then dropped; a recovery slice is XORed into its buffer
//! whenever it arrives (before, during or after the data). The moment the unknown slices
//! (damaged *or not yet downloaded*) are no more numerous than the buffers whose recovery slice
//! has arrived, the whole set is solvable from the bank alone — no byte is read twice, and the
//! remaining downloads can be cancelled.
//!
//! [`StreamingSliceAssembler`] sits on top: it accepts out-of-order `(file, offset, bytes)`
//! chunks as yEnc articles decode (716 800-byte articles do not align with 1 MiB slices), stages
//! only the slices an article boundary cuts through, zero pads the final slice of each file,
//! verifies every completed slice against the IFSC checksums and folds it into the bank.

use crate::gf2::crc32;
use crate::gf16::simd::Kernel;
use crate::gf16::{input_constant_logs, rs_coefficient};
use crate::packet::SliceChecksum;
use crate::reed_solomon::plan_recovery;
use crate::repair::{RepairError, fold_tiled, xor_into};
use md5::{Digest, Md5};
use std::collections::BTreeMap;

/// Running syndromes `S̃_e` for a set of tracked exponents.
#[derive(Clone, Debug)]
pub struct SyndromeBank {
    slice_size: usize,
    logs: Vec<u16>,
    exponents: Vec<u32>,
    bufs: Vec<Vec<u8>>,
    have_recovery: Vec<bool>,
    folded: Vec<bool>,
    folded_count: usize,
    kernel: Kernel,
}

impl SyndromeBank {
    /// Bank for `total_slices` input slices and the given recovery exponents.
    pub fn new(
        slice_size: usize,
        total_slices: usize,
        exponents: &[u32],
        kernel: Kernel,
    ) -> Result<Self, RepairError> {
        if slice_size == 0 {
            return Err(RepairError::ZeroSliceSize);
        }
        let logs = input_constant_logs(total_slices).map_err(|_| RepairError::TooManyInputs)?;
        let mut exps = exponents.to_vec();
        exps.sort_unstable();
        exps.dedup();
        let n = exps.len();
        Ok(Self {
            slice_size,
            logs,
            exponents: exps,
            bufs: vec![vec![0u8; slice_size]; n],
            have_recovery: vec![false; n],
            folded: vec![false; total_slices],
            folded_count: 0,
            kernel,
        })
    }

    /// Slice size.
    pub fn slice_size(&self) -> usize {
        self.slice_size
    }

    /// Total input slices.
    pub fn total_slices(&self) -> usize {
        self.folded.len()
    }

    /// Tracked exponents (ascending).
    pub fn exponents(&self) -> &[u32] {
        &self.exponents
    }

    /// Whether input slice `global` has been folded.
    pub fn is_folded(&self, global: usize) -> bool {
        self.folded.get(global).copied().unwrap_or(false)
    }

    /// Number of folded (verified) slices.
    pub fn folded_count(&self) -> usize {
        self.folded_count
    }

    /// Input slices not yet folded (damaged or pending).
    pub fn unknown_slices(&self) -> Vec<usize> {
        self.folded
            .iter()
            .enumerate()
            .filter(|(_, f)| !**f)
            .map(|(i, _)| i)
            .collect()
    }

    /// Exponents whose recovery slice has arrived: their buffers are complete syndromes.
    pub fn ready_syndromes(&self) -> Vec<u32> {
        self.exponents
            .iter()
            .zip(&self.have_recovery)
            .filter(|(_, h)| **h)
            .map(|(e, _)| *e)
            .collect()
    }

    /// `unknown_slices().len() <= ready_syndromes().len()`.
    pub fn can_solve_now(&self) -> bool {
        self.folded.len().saturating_sub(self.folded_count)
            <= self.have_recovery.iter().filter(|h| **h).count()
    }

    /// Fold a verified input slice (exactly `slice_size` bytes, zero padded) into every buffer.
    pub fn fold_verified(&mut self, global: usize, data: &[u8]) -> Result<(), RepairError> {
        if data.len() != self.slice_size {
            return Err(RepairError::SliceSizeMismatch {
                index: global,
                expected: self.slice_size,
                got: data.len(),
            });
        }
        match self.folded.get(global) {
            None => return Err(RepairError::BadIndex(global)),
            Some(true) => return Ok(()), // idempotent
            Some(false) => {}
        }
        let log = self.logs.get(global).copied().unwrap_or(0);
        let coeffs: Vec<u16> = self
            .exponents
            .iter()
            .map(|&e| rs_coefficient(log, e))
            .collect();
        fold_tiled(&self.kernel, &mut self.bufs, data, &coeffs);
        if let Some(f) = self.folded.get_mut(global) {
            *f = true;
        }
        self.folded_count = self.folded_count.saturating_add(1);
        Ok(())
    }

    /// XOR a recovery slice into its buffer. Returns `Ok(true)` when it was folded; unknown
    /// exponents and duplicate deliveries are ignored (`Ok(false)`).
    pub fn xor_recovery(&mut self, exponent: u32, data: &[u8]) -> Result<bool, RepairError> {
        if data.len() != self.slice_size {
            return Err(RepairError::SliceSizeMismatch {
                index: exponent as usize,
                expected: self.slice_size,
                got: data.len(),
            });
        }
        let Some(j) = self.exponents.iter().position(|&e| e == exponent) else {
            return Ok(false);
        };
        if self.have_recovery.get(j).copied().unwrap_or(false) {
            return Ok(false); // duplicate delivery
        }
        if let Some(b) = self.bufs.get_mut(j) {
            xor_into(b, data);
        }
        if let Some(h) = self.have_recovery.get_mut(j) {
            *h = true;
        }
        Ok(true)
    }

    /// Solve for every unknown slice: `(global index, data)`.
    pub fn solve_now(&self) -> Result<Vec<(usize, Vec<u8>)>, RepairError> {
        let unknown = self.unknown_slices();
        self.solve_selected(&unknown)
    }

    /// Solve only for `wanted` (each must be unknown); every unknown slice still counts toward
    /// the syndromes required.
    pub fn solve_selected(&self, wanted: &[usize]) -> Result<Vec<(usize, Vec<u8>)>, RepairError> {
        let mut rows: Vec<usize> = wanted.to_vec();
        rows.sort_unstable();
        rows.dedup();
        for &w in &rows {
            match self.folded.get(w) {
                None => return Err(RepairError::BadIndex(w)),
                Some(true) => return Err(RepairError::NotMissing(w)),
                Some(false) => {}
            }
        }
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let ready = self.ready_syndromes();
        let plan = plan_recovery(&self.logs, &self.folded, &ready, &self.kernel)?;
        let syn: Vec<&[u8]> = plan
            .used_exponents
            .iter()
            .map(|e| {
                self.exponents
                    .iter()
                    .position(|x| x == e)
                    .and_then(|j| self.bufs.get(j))
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
            })
            .collect();
        let mut out: Vec<Vec<u8>> = vec![vec![0u8; self.slice_size]; rows.len()];
        for (j, s) in syn.iter().enumerate() {
            let coeffs: Vec<u16> = rows
                .iter()
                .map(|w| {
                    plan.missing
                        .iter()
                        .position(|m| m == w)
                        .map_or(0, |m| plan.inverse.get(m, j))
                })
                .collect();
            fold_tiled(&self.kernel, &mut out, s, &coeffs);
        }
        Ok(rows.into_iter().zip(out).collect())
    }
}

/// Layout of one input file for the assembler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileLayout {
    /// File id.
    pub file_id: [u8; 16],
    /// File size.
    pub size: u64,
    /// Expected slice checksums (`ceil(size / slice_size)` entries).
    pub slices: Vec<SliceChecksum>,
}

/// State of an input slice in the assembler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SliceState {
    /// Not (fully) received.
    Pending,
    /// Verified and folded.
    Verified,
    /// Known bad (checksum mismatch or a damaged article range).
    Damaged,
}

/// Something the assembler observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    /// A slice completed, verified and was folded into the bank.
    SliceVerified {
        /// Global slice index.
        global: usize,
    },
    /// A slice completed but failed its IFSC checksums.
    SliceMismatch {
        /// Global slice index.
        global: usize,
    },
    /// A slice was marked damaged by a failed article.
    SliceDamaged {
        /// Global slice index.
        global: usize,
    },
    /// A recovery slice was folded into the bank.
    RecoveryReceived {
        /// Exponent.
        exponent: u32,
    },
    /// The bank can now solve every unknown slice (emitted once per transition).
    ReadyToSolve,
}

/// Aggregate status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamStatus {
    /// Still collecting.
    Collecting {
        /// Verified slices.
        verified: usize,
        /// Damaged + pending slices.
        unknown: usize,
        /// Ready syndromes.
        ready: usize,
    },
    /// Every unknown slice is solvable from the bank right now.
    ReadyToSolve {
        /// Damaged + pending slices.
        unknown: usize,
        /// Ready syndromes.
        ready: usize,
    },
}

#[derive(Clone, Debug)]
struct Staging {
    buf: Vec<u8>,
    /// Covered byte ranges within the slice (merged, sorted).
    covered: Vec<(usize, usize)>,
}

impl Staging {
    fn add(&mut self, start: usize, end: usize) {
        self.covered.push((start, end));
        self.covered.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.covered.len());
        for &(s, e) in &self.covered {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.covered = merged;
    }

    fn complete(&self, len: usize) -> bool {
        matches!(self.covered.as_slice(), [(0, e)] if *e >= len)
    }
}

/// Reassembles PAR2 slices from arbitrary byte ranges and feeds the syndrome bank.
#[derive(Clone, Debug)]
pub struct StreamingSliceAssembler {
    bank: SyndromeBank,
    files: Vec<FileLayout>,
    first_slice: Vec<usize>,
    state: Vec<SliceState>,
    staging: BTreeMap<usize, Staging>,
    staging_bytes: usize,
    max_staging_bytes: usize,
    announced_ready: bool,
}

impl StreamingSliceAssembler {
    /// Assembler over `files` (any order; sorted into `libpar2` file-id order here) tracking `exponents`.
    /// `max_staging_bytes` bounds the partially-filled slice buffers (0 = unbounded).
    pub fn new(
        slice_size: usize,
        mut files: Vec<FileLayout>,
        exponents: &[u32],
        kernel: Kernel,
        max_staging_bytes: usize,
    ) -> Result<Self, RepairError> {
        if slice_size == 0 {
            return Err(RepairError::ZeroSliceSize);
        }
        files.sort_by_key(|f| crate::bytes::file_id_key(&f.file_id));
        let mut first_slice = Vec::with_capacity(files.len());
        let mut total = 0usize;
        for f in &files {
            let expected = f.size.div_ceil(slice_size as u64);
            if expected != f.slices.len() as u64 {
                return Err(RepairError::BadIndex(f.slices.len()));
            }
            first_slice.push(total);
            total = total
                .checked_add(f.slices.len())
                .ok_or(RepairError::TooManyInputs)?;
        }
        let bank = SyndromeBank::new(slice_size, total, exponents, kernel)?;
        Ok(Self {
            bank,
            files,
            first_slice,
            state: vec![SliceState::Pending; total],
            staging: BTreeMap::new(),
            staging_bytes: 0,
            max_staging_bytes,
            announced_ready: false,
        })
    }

    /// The underlying bank.
    pub fn bank(&self) -> &SyndromeBank {
        &self.bank
    }

    /// Files in file-id order.
    pub fn files(&self) -> &[FileLayout] {
        &self.files
    }

    /// Slice size.
    pub fn slice_size(&self) -> usize {
        self.bank.slice_size()
    }

    /// Total input slices.
    pub fn total_slices(&self) -> usize {
        self.state.len()
    }

    /// State of a global slice.
    pub fn slice_state(&self, global: usize) -> Option<SliceState> {
        self.state.get(global).copied()
    }

    /// Bytes currently held in partial-slice staging buffers.
    pub fn staging_bytes(&self) -> usize {
        self.staging_bytes
    }

    /// Global slice number of `(file, slice)`.
    pub fn global_slice(&self, file: usize, slice: usize) -> Option<usize> {
        (slice < self.files.get(file)?.slices.len()).then(|| {
            self.first_slice
                .get(file)
                .copied()
                .unwrap_or(0)
                .saturating_add(slice)
        })
    }

    /// `(file, slice)` of a global slice.
    pub fn locate_global(&self, global: usize) -> Option<(usize, usize)> {
        let fi = self
            .first_slice
            .partition_point(|&s| s <= global)
            .checked_sub(1)?;
        let slice = global.checked_sub(*self.first_slice.get(fi)?)?;
        (slice < self.files.get(fi)?.slices.len()).then_some((fi, slice))
    }

    fn file_index(&self, file_id: &[u8; 16]) -> Option<usize> {
        self.files.iter().position(|f| f.file_id == *file_id)
    }

    /// Current status.
    pub fn status(&self) -> StreamStatus {
        let unknown = self.state.len().saturating_sub(self.bank.folded_count());
        let ready = self.bank.ready_syndromes().len();
        if self.bank.can_solve_now() {
            StreamStatus::ReadyToSolve { unknown, ready }
        } else {
            StreamStatus::Collecting {
                verified: self.bank.folded_count(),
                unknown,
                ready,
            }
        }
    }

    /// Whether every unknown slice can be solved now.
    pub fn can_solve_now(&self) -> bool {
        self.bank.can_solve_now()
    }

    fn check_ready(&mut self, events: &mut Vec<StreamEvent>) {
        if self.bank.can_solve_now() {
            if !self.announced_ready {
                self.announced_ready = true;
                events.push(StreamEvent::ReadyToSolve);
            }
        } else {
            self.announced_ready = false;
        }
    }

    /// Verify a complete (padded) slice buffer and fold it.
    fn complete_slice(
        &mut self,
        global: usize,
        fi: usize,
        si: usize,
        buf: &[u8],
        events: &mut Vec<StreamEvent>,
    ) {
        let Some(exp) = self.files.get(fi).and_then(|f| f.slices.get(si)) else {
            return;
        };
        let ok = crc32(buf) == exp.crc32 && <[u8; 16]>::from(Md5::digest(buf)) == exp.md5;
        if ok && self.bank.fold_verified(global, buf).is_ok() {
            if let Some(s) = self.state.get_mut(global) {
                *s = SliceState::Verified;
            }
            events.push(StreamEvent::SliceVerified { global });
        } else {
            if let Some(s) = self.state.get_mut(global) {
                *s = SliceState::Damaged;
            }
            events.push(StreamEvent::SliceMismatch { global });
        }
    }

    /// Deliver decoded bytes of file `file_id` starting at `byte_offset`. Bytes beyond the file
    /// size are ignored. Returns the events this chunk produced.
    pub fn push_chunk(
        &mut self,
        file_id: &[u8; 16],
        byte_offset: u64,
        data: &[u8],
    ) -> Result<Vec<StreamEvent>, RepairError> {
        let mut events = Vec::new();
        let Some(fi) = self.file_index(file_id) else {
            return Err(RepairError::BadIndex(usize::MAX));
        };
        let (size, ss) = (
            self.files.get(fi).map_or(0, |f| f.size),
            self.bank.slice_size() as u64,
        );
        if byte_offset >= size || data.is_empty() {
            return Ok(events);
        }
        let end = byte_offset.saturating_add(data.len() as u64).min(size);
        let mut pos = byte_offset;
        while pos < end {
            let si = usize::try_from(pos / ss).unwrap_or(usize::MAX);
            let slice_start = (si as u64).saturating_mul(ss);
            let slice_len = usize::try_from(size.saturating_sub(slice_start).min(ss)).unwrap_or(0);
            let seg_end = slice_start.saturating_add(slice_len as u64).min(end);
            let in_slice = usize::try_from(pos - slice_start).unwrap_or(0);
            let seg_len = usize::try_from(seg_end - pos).unwrap_or(0);
            let src_off = usize::try_from(pos - byte_offset).unwrap_or(0);
            let Some(segment) = data.get(src_off..src_off.saturating_add(seg_len)) else {
                break;
            };
            let Some(global) = self.global_slice(fi, si) else {
                break;
            };
            let state = self
                .state
                .get(global)
                .copied()
                .unwrap_or(SliceState::Pending);
            if state == SliceState::Pending {
                if in_slice == 0 && seg_len == slice_len {
                    // Whole slice in this chunk: verify straight from the article.
                    if slice_len == self.bank.slice_size() {
                        self.complete_slice(global, fi, si, segment, &mut events);
                    } else {
                        let mut padded = vec![0u8; self.bank.slice_size()];
                        if let Some(d) = padded.get_mut(..slice_len) {
                            d.copy_from_slice(segment);
                        }
                        self.complete_slice(global, fi, si, &padded, &mut events);
                    }
                } else {
                    let ss_us = self.bank.slice_size();
                    if !self.staging.contains_key(&global) {
                        if self.max_staging_bytes != 0
                            && self.staging_bytes.saturating_add(ss_us) > self.max_staging_bytes
                        {
                            return Err(RepairError::Io {
                                context: "staging budget exhausted".into(),
                                source: std::io::Error::new(
                                    std::io::ErrorKind::OutOfMemory,
                                    "staging budget exhausted",
                                ),
                            });
                        }
                        self.staging.insert(
                            global,
                            Staging {
                                buf: vec![0u8; ss_us],
                                covered: Vec::new(),
                            },
                        );
                        self.staging_bytes = self.staging_bytes.saturating_add(ss_us);
                    }
                    let done = if let Some(st) = self.staging.get_mut(&global) {
                        if let Some(d) = st.buf.get_mut(in_slice..in_slice.saturating_add(seg_len))
                        {
                            d.copy_from_slice(segment);
                        }
                        st.add(in_slice, in_slice.saturating_add(seg_len));
                        st.complete(slice_len)
                    } else {
                        false
                    };
                    if done && let Some(st) = self.staging.remove(&global) {
                        self.staging_bytes = self.staging_bytes.saturating_sub(st.buf.len());
                        self.complete_slice(global, fi, si, &st.buf, &mut events);
                    }
                }
            }
            pos = seg_end;
        }
        self.check_ready(&mut events);
        Ok(events)
    }

    /// An article covering `[byte_offset, byte_offset + len)` of `file_id` failed for good:
    /// every pending slice it touches becomes damaged (verified slices are unaffected).
    pub fn mark_range_damaged(
        &mut self,
        file_id: &[u8; 16],
        byte_offset: u64,
        len: u64,
    ) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        let Some(fi) = self.file_index(file_id) else {
            return events;
        };
        let (size, ss) = (
            self.files.get(fi).map_or(0, |f| f.size),
            self.bank.slice_size() as u64,
        );
        if len == 0 || byte_offset >= size {
            return events;
        }
        let end = byte_offset.saturating_add(len).min(size);
        let first = usize::try_from(byte_offset / ss).unwrap_or(usize::MAX);
        let last = usize::try_from((end - 1) / ss).unwrap_or(usize::MAX);
        for si in first..=last {
            let Some(global) = self.global_slice(fi, si) else {
                break;
            };
            if self.state.get(global).copied() == Some(SliceState::Pending) {
                if let Some(s) = self.state.get_mut(global) {
                    *s = SliceState::Damaged;
                }
                if let Some(st) = self.staging.remove(&global) {
                    self.staging_bytes = self.staging_bytes.saturating_sub(st.buf.len());
                }
                events.push(StreamEvent::SliceDamaged { global });
            }
        }
        self.check_ready(&mut events);
        events
    }

    /// A recovery slice arrived (any time). Untracked exponents are ignored.
    pub fn push_recovery(
        &mut self,
        exponent: u32,
        data: &[u8],
    ) -> Result<Vec<StreamEvent>, RepairError> {
        let mut events = Vec::new();
        if self.bank.xor_recovery(exponent, data)? {
            events.push(StreamEvent::RecoveryReceived { exponent });
        }
        self.check_ready(&mut events);
        Ok(events)
    }

    /// Solve every damaged and pending slice from the bank: `(global, data)`.
    pub fn solve_now(&self) -> Result<Vec<(usize, Vec<u8>)>, RepairError> {
        self.bank.solve_now()
    }

    /// Solve only the given unknown slices (e.g. an archive's header and tail).
    pub fn solve_selected_slices(
        &self,
        wanted: &[usize],
    ) -> Result<Vec<(usize, Vec<u8>)>, RepairError> {
        self.bank.solve_selected(wanted)
    }

    /// Global indices of damaged slices.
    pub fn damaged_slices(&self) -> Vec<usize> {
        self.state
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == SliceState::Damaged)
            .map(|(i, _)| i)
            .collect()
    }

    /// Global indices of pending slices.
    pub fn pending_slices(&self) -> Vec<usize> {
        self.state
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == SliceState::Pending)
            .map(|(i, _)| i)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::encode_reference;

    fn data(n: usize, seed: u32) -> Vec<u8> {
        (0..n as u32)
            .map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed) >> 13) as u8)
            .collect()
    }

    fn layout(id: u8, bytes: &[u8], ss: usize) -> (FileLayout, Vec<Vec<u8>>) {
        let padded: Vec<Vec<u8>> = bytes
            .chunks(ss)
            .map(|c| {
                let mut p = c.to_vec();
                p.resize(ss, 0);
                p
            })
            .collect();
        let slices = padded
            .iter()
            .map(|p| SliceChecksum {
                md5: Md5::digest(p).into(),
                crc32: crc32(p),
            })
            .collect();
        (
            FileLayout {
                file_id: [id; 16],
                size: bytes.len() as u64,
                slices,
            },
            padded,
        )
    }

    #[test]
    fn out_of_order_articles_early_cutoff_and_surgical_solve() {
        let k = Kernel::detect();
        let ss = 1000usize;
        let a = data(3500, 1); // 4 slices (last padded)
        let b = data(2000, 2); // 2 slices
        let (la, pa) = layout(5, &a, ss);
        let (lb, pb) = layout(9, &b, ss);
        // file-id order: a (5) then b (9)
        let all: Vec<Vec<u8>> = pa.iter().chain(&pb).cloned().collect();
        let refs: Vec<&[u8]> = all.iter().map(|v| v.as_slice()).collect();
        let rec = encode_reference(ss, &refs, &[0, 1, 2]);
        let mut asm =
            StreamingSliceAssembler::new(ss, vec![lb.clone(), la.clone()], &[0, 1, 2], k, 0)
                .unwrap();
        assert_eq!(asm.files()[0].file_id, [5; 16]);
        assert_eq!(asm.total_slices(), 6);
        assert_eq!(asm.global_slice(1, 1), Some(5));
        assert_eq!(asm.locate_global(4), Some((1, 0)));

        // Recovery arrives first.
        let ev = asm.push_recovery(1, &rec[1]).unwrap();
        assert_eq!(ev, vec![StreamEvent::RecoveryReceived { exponent: 1 }]);
        assert!(asm.push_recovery(7, &rec[1]).unwrap().is_empty()); // untracked
        assert!(asm.push_recovery(2, &rec[2][..10]).is_err());

        // 700-byte "articles" of file a, out of order: article 2 (1400..2100), then 0, then 1.
        let ev = asm.push_chunk(&[5; 16], 1400, &a[1400..2100]).unwrap();
        assert!(ev.is_empty());
        assert_eq!(asm.staging_bytes(), 2 * ss); // slices 1 and 2 partially staged
        let ev = asm.push_chunk(&[5; 16], 0, &a[0..700]).unwrap();
        assert!(ev.is_empty());
        let ev = asm.push_chunk(&[5; 16], 700, &a[700..1400]).unwrap();
        assert_eq!(
            ev,
            vec![
                StreamEvent::SliceVerified { global: 0 },
                StreamEvent::SliceVerified { global: 1 }
            ]
        );
        assert_eq!(asm.staging_bytes(), ss);
        // Article 3 (2100..2800) still leaves slice 2 (2000..3000) open; article 4 (2800..3500)
        // would finish it and carry the padded tail slice 3.
        let ev = asm.push_chunk(&[5; 16], 2100, &a[2100..2800]).unwrap();
        assert!(ev.is_empty());
        assert_eq!(asm.staging_bytes(), ss);
        // Article 4 lost: slices 2 and 3 damaged, staging released.
        let ev = asm.mark_range_damaged(&[5; 16], 2800, 700);
        assert_eq!(
            ev,
            vec![
                StreamEvent::SliceDamaged { global: 2 },
                StreamEvent::SliceDamaged { global: 3 }
            ]
        );
        assert_eq!(asm.staging_bytes(), 0);
        assert_eq!(asm.slice_state(3), Some(SliceState::Damaged));
        // File b: slice 0 whole, slice 1 pending. Unknown = {2, 3, 5} > ready {1}.
        let ev = asm.push_chunk(&[9; 16], 0, &b[..1000]).unwrap();
        assert_eq!(ev, vec![StreamEvent::SliceVerified { global: 4 }]);
        assert!(!asm.can_solve_now());
        assert_eq!(
            asm.status(),
            StreamStatus::Collecting {
                verified: 3,
                unknown: 3,
                ready: 1
            }
        );
        let ev = asm.push_recovery(0, &rec[0]).unwrap();
        assert_eq!(ev, vec![StreamEvent::RecoveryReceived { exponent: 0 }]);
        // Third recovery slice → ready, without downloading b's second slice.
        let ev = asm.push_recovery(2, &rec[2]).unwrap();
        assert_eq!(
            ev,
            vec![
                StreamEvent::RecoveryReceived { exponent: 2 },
                StreamEvent::ReadyToSolve
            ]
        );
        assert_eq!(
            asm.status(),
            StreamStatus::ReadyToSolve {
                unknown: 3,
                ready: 3
            }
        );
        assert_eq!(asm.damaged_slices(), vec![2, 3]);
        assert_eq!(asm.pending_slices(), vec![5]);
        let solved = asm.solve_now().unwrap();
        assert_eq!(
            solved,
            vec![(2, pa[2].clone()), (3, pa[3].clone()), (5, pb[1].clone())]
        );
        // Surgical: just the pending tail of b.
        assert_eq!(
            asm.solve_selected_slices(&[5]).unwrap(),
            vec![(5, pb[1].clone())]
        );
        assert!(matches!(
            asm.solve_selected_slices(&[0]),
            Err(RepairError::NotMissing(0))
        ));
        // Duplicate delivery and late data are harmless.
        assert!(asm.push_recovery(0, &rec[0]).unwrap().is_empty());
        let ev = asm.push_chunk(&[9; 16], 1000, &b[1000..]).unwrap();
        assert_eq!(ev, vec![StreamEvent::SliceVerified { global: 5 }]);
        assert_eq!(asm.bank().folded_count(), 4);
        // Mismatching data is reported.
        let mut asm2 = StreamingSliceAssembler::new(ss, vec![la.clone()], &[0], k, 0).unwrap();
        let mut bad = a[..1000].to_vec();
        bad[3] ^= 1;
        assert_eq!(
            asm2.push_chunk(&[5; 16], 0, &bad).unwrap(),
            vec![StreamEvent::SliceMismatch { global: 0 }]
        );
        assert!(asm2.push_chunk(&[7; 16], 0, &bad).is_err());
        assert!(asm2.push_chunk(&[5; 16], 99_999, &bad).unwrap().is_empty());
        assert!(asm2.mark_range_damaged(&[7; 16], 0, 1).is_empty());
        // Staging budget.
        let mut asm3 = StreamingSliceAssembler::new(ss, vec![la.clone()], &[0], k, ss).unwrap();
        assert!(asm3.push_chunk(&[5; 16], 10, &a[10..20]).is_ok());
        assert!(asm3.push_chunk(&[5; 16], 1010, &a[1010..1020]).is_err());
        assert!(StreamingSliceAssembler::new(0, vec![], &[0], k, 0).is_err());
        let mut wrong = la.clone();
        wrong.slices.pop();
        assert!(StreamingSliceAssembler::new(ss, vec![wrong], &[0], k, 0).is_err());
    }

    #[test]
    fn bank_direct_use() {
        let k = Kernel::detect();
        let ss = 512;
        let inputs: Vec<Vec<u8>> = (0..5).map(|i| data(ss, i)).collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
        let rec = encode_reference(ss, &refs, &[3, 8]);
        let mut bank = SyndromeBank::new(ss, 5, &[8, 3, 3], k).unwrap();
        assert_eq!(bank.exponents(), &[3, 8]);
        for i in [0usize, 2, 4] {
            bank.fold_verified(i, &inputs[i]).unwrap();
        }
        bank.fold_verified(2, &inputs[2]).unwrap(); // idempotent
        assert_eq!(bank.folded_count(), 3);
        assert_eq!(bank.unknown_slices(), vec![1, 3]);
        assert!(!bank.can_solve_now());
        assert!(bank.solve_now().is_err());
        assert!(bank.xor_recovery(3, &rec[0]).unwrap());
        assert!(bank.xor_recovery(8, &rec[1]).unwrap());
        assert!(bank.can_solve_now());
        assert_eq!(bank.ready_syndromes(), vec![3, 8]);
        assert_eq!(
            bank.solve_now().unwrap(),
            vec![(1, inputs[1].clone()), (3, inputs[3].clone())]
        );
        assert!(bank.fold_verified(9, &inputs[0]).is_err());
        assert!(bank.fold_verified(1, &inputs[0][..5]).is_err());
        assert!(matches!(
            bank.solve_selected(&[0]),
            Err(RepairError::NotMissing(0))
        ));
        assert!(matches!(
            bank.solve_selected(&[77]),
            Err(RepairError::BadIndex(77))
        ));
        assert!(bank.solve_selected(&[]).unwrap().is_empty());
        assert!(bank.is_folded(0) && !bank.is_folded(1) && !bank.is_folded(99));
        assert!(SyndromeBank::new(0, 1, &[0], k).is_err());
    }
}
