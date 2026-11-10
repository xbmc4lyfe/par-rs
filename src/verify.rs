//! In-memory slice verification against a PAR2 set, with rolling-CRC discovery of misplaced
//! slices and a repair assessment.
//!
//! [`SetVerifier`] maps the recovery-set files (sorted ascending by their file id taken as a
//! little-endian 128-bit integer, the `libpar2` order) onto the global input slice numbering `0..total_input_slices`. A buffer is
//! checked slice by slice at the aligned offsets (CRC-32 first, MD5 only on a CRC hit); when
//! slices are missing, a [`RollingCrc32`] window slides over the whole buffer and recovers
//! slices of *any* file of the set that sit at a shifted offset (inserted / deleted bytes,
//! concatenated parts, mislabelled files).

use crate::gf2::{RollingCrc32, crc32};
use crate::inspect::Par2Inspection;
use md5::{Digest, Md5};
use std::collections::HashMap;

pub use crate::packet::SliceChecksum;

/// One input file of the set as the verifier needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSpec {
    /// File id (sort key).
    pub file_id: [u8; 16],
    /// Declared size.
    pub size: u64,
    /// Whole-file MD5, if a `FileDesc` was available.
    pub md5: Option<[u8; 16]>,
    /// Per-slice checksums (`ceil(size / block_size)` entries).
    pub slices: Vec<SliceChecksum>,
}

/// Verdict for one slice of a verified file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SliceStatus {
    /// Verified at its natural offset.
    Verified,
    /// Data present at the natural offset but it does not match.
    Damaged,
    /// Found at another offset of the same buffer (the natural offset is damaged).
    Misplaced {
        /// Byte offset where the slice was found.
        offset: u64,
    },
    /// The buffer ends before the slice's natural offset.
    Missing,
}

/// A slice of some file found at an arbitrary offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoundSlice {
    /// File index (verifier order).
    pub file: usize,
    /// Slice index within that file.
    pub slice: usize,
    /// Global slice number.
    pub global: usize,
    /// Offset in the verified buffer.
    pub offset: u64,
}

/// Verification of one buffer against one expected file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileVerification {
    /// File index (verifier order).
    pub file: usize,
    /// Buffer length equals the declared size.
    pub size_ok: bool,
    /// Whole-file MD5 verdict (`None` when the set has no MD5 for the file or the size differs).
    pub md5_ok: Option<bool>,
    /// Per-slice verdicts.
    pub slices: Vec<SliceStatus>,
    /// Slices of this or other files found at non-natural offsets (only searched when some
    /// slice of this file failed).
    pub found: Vec<FoundSlice>,
    /// Number of this file's slices verified (aligned or misplaced).
    pub verified: usize,
}

impl FileVerification {
    /// Every slice verified at its natural offset and the size matches.
    pub fn is_intact(&self) -> bool {
        self.size_ok
            && self.slices.iter().all(|s| *s == SliceStatus::Verified)
            && self.md5_ok != Some(false)
    }
}

/// Verification of a whole set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerificationReport {
    /// Per-buffer results.
    pub files: Vec<FileVerification>,
    /// Total input slices of the set.
    pub total_slices: usize,
    /// Global slices located somewhere (`Some((buffer index, offset))`).
    pub located: Vec<Option<(usize, u64)>>,
    /// Global slices not located anywhere.
    pub missing: Vec<usize>,
}

/// Can the set be repaired?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairAssessment {
    /// Total input slices.
    pub total_slices: usize,
    /// Missing input slices.
    pub missing_slices: usize,
    /// Recovery slices available.
    pub recovery_slices: usize,
    /// `missing_slices <= recovery_slices`.
    pub repairable: bool,
    /// Recovery slices still needed (`0` when repairable).
    pub shortfall: usize,
}

/// Slice-level verifier for one recovery set.
#[derive(Clone, Debug)]
pub struct SetVerifier {
    block_size: u64,
    files: Vec<SourceSpec>,
    first_slice: Vec<usize>,
    total: usize,
    /// CRC → `(file, slice)` candidates.
    index: HashMap<u32, Vec<(usize, usize)>>,
    /// 64 Ki-bit pre-filter on the low 16 CRC bits.
    filter: Vec<u64>,
}

impl SetVerifier {
    /// Build a verifier; files are sorted by file id. `None` when `block_size == 0`, a file's
    /// slice count disagrees with its size, or the block size does not fit in memory.
    pub fn new(block_size: u64, mut files: Vec<SourceSpec>) -> Option<Self> {
        if block_size == 0 || usize::try_from(block_size).is_err() {
            return None;
        }
        files.sort_by_key(|a| crate::bytes::file_id_key(&a.file_id));
        let mut first_slice = Vec::with_capacity(files.len());
        let mut total = 0usize;
        let mut index: HashMap<u32, Vec<(usize, usize)>> = HashMap::new();
        let mut filter = vec![0u64; 1024];
        for (fi, f) in files.iter().enumerate() {
            let expected = f.size.div_ceil(block_size);
            if expected != f.slices.len() as u64 {
                return None;
            }
            first_slice.push(total);
            total = total.checked_add(f.slices.len())?;
            for (si, s) in f.slices.iter().enumerate() {
                index.entry(s.crc32).or_default().push((fi, si));
                let bit = (s.crc32 & 0xFFFF) as usize;
                if let Some(w) = filter.get_mut(bit / 64) {
                    *w |= 1u64 << (bit % 64);
                }
            }
        }
        Some(Self {
            block_size,
            files,
            first_slice,
            total,
            index,
            filter,
        })
    }

    /// Verifier for the primary set of an inspection (the set of its first `Main` packet).
    /// Files without an IFSC packet are skipped (they cannot be slice-verified).
    pub fn from_inspection(insp: &Par2Inspection) -> Option<Self> {
        let main = insp.main.first()?;
        let files: Vec<SourceSpec> = main
            .recovery_set
            .iter()
            .filter_map(|id| {
                let desc = insp
                    .files
                    .iter()
                    .find(|f| f.set_id == main.set_id && f.file_id == *id);
                let ifsc = insp
                    .ifsc
                    .iter()
                    .find(|i| i.set_id == main.set_id && i.file_id == *id)?;
                let size = desc.map(|d| d.length)?;
                Some(SourceSpec {
                    file_id: *id,
                    size,
                    md5: desc.map(|d| d.md5),
                    slices: ifsc
                        .slices
                        .iter()
                        .map(|&(md5, crc32)| SliceChecksum { md5, crc32 })
                        .collect(),
                })
            })
            .collect();
        Self::new(main.slice_size, files)
    }

    /// Block (slice) size.
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Total input slices.
    pub fn total_slices(&self) -> usize {
        self.total
    }

    /// Files in verifier (file id) order.
    pub fn files(&self) -> &[SourceSpec] {
        &self.files
    }

    /// Index of the file with `file_id`.
    pub fn file_index(&self, file_id: &[u8; 16]) -> Option<usize> {
        self.files.iter().position(|f| f.file_id == *file_id)
    }

    /// Global slice number of slice `slice` of file `file`.
    pub fn global_slice(&self, file: usize, slice: usize) -> Option<usize> {
        let f = self.files.get(file)?;
        (slice < f.slices.len()).then(|| {
            self.first_slice
                .get(file)
                .copied()
                .unwrap_or(0)
                .saturating_add(slice)
        })
    }

    /// `(file, slice)` of a global slice number.
    pub fn locate_global(&self, global: usize) -> Option<(usize, usize)> {
        let fi = self
            .first_slice
            .partition_point(|&s| s <= global)
            .checked_sub(1)?;
        let first = *self.first_slice.get(fi)?;
        let slice = global.checked_sub(first)?;
        (slice < self.files.get(fi)?.slices.len()).then_some((fi, slice))
    }

    #[inline]
    fn may_contain(&self, crc: u32) -> bool {
        let bit = (crc & 0xFFFF) as usize;
        self.filter
            .get(bit / 64)
            .is_some_and(|w| w & (1u64 << (bit % 64)) != 0)
    }

    /// MD5 of `data` zero padded to the block size.
    fn padded_md5(&self, data: &[u8]) -> [u8; 16] {
        let bs = usize::try_from(self.block_size).unwrap_or(usize::MAX);
        let mut ctx = Md5::new();
        ctx.update(data);
        let pad = bs.saturating_sub(data.len());
        let zeros = [0u8; 4096];
        let mut left = pad;
        while left > 0 {
            let n = left.min(zeros.len());
            ctx.update(zeros.get(..n).unwrap_or(&zeros));
            left -= n;
        }
        ctx.finalize().into()
    }

    /// Check one slice's bytes (`data.len() <= block_size`, zero padded) against expectations.
    pub fn slice_matches(&self, expected: &SliceChecksum, data: &[u8]) -> bool {
        let bs = usize::try_from(self.block_size).unwrap_or(usize::MAX);
        if data.len() > bs {
            return false;
        }
        let crc = if data.len() == bs {
            crc32(data)
        } else {
            crate::gf2::crc32_combine(
                crc32(data),
                crate::gf2::crc32_zeros(bs - data.len()),
                bs - data.len(),
            )
        };
        crc == expected.crc32 && self.padded_md5(data) == expected.md5
    }

    /// Verify `data` as the contents of file `file`.
    pub fn verify_file(&self, file: usize, data: &[u8]) -> FileVerification {
        let Some(spec) = self.files.get(file) else {
            return FileVerification {
                file,
                size_ok: false,
                md5_ok: None,
                slices: Vec::new(),
                found: Vec::new(),
                verified: 0,
            };
        };
        let bs = usize::try_from(self.block_size).unwrap_or(usize::MAX);
        let size_ok = data.len() as u64 == spec.size;
        let mut slices = Vec::with_capacity(spec.slices.len());
        let mut verified = 0usize;
        for (si, exp) in spec.slices.iter().enumerate() {
            let start = si.saturating_mul(bs);
            if start >= data.len() {
                slices.push(SliceStatus::Missing);
                continue;
            }
            let end = start.saturating_add(bs).min(data.len());
            let chunk = data.get(start..end).unwrap_or(&[]);
            if self.slice_matches(exp, chunk) {
                slices.push(SliceStatus::Verified);
                verified = verified.saturating_add(1);
            } else {
                slices.push(SliceStatus::Damaged);
            }
        }
        let md5_ok = spec
            .md5
            .filter(|_| size_ok)
            .map(|m| <[u8; 16]>::from(Md5::digest(data)) == m);
        let mut found = Vec::new();
        if slices.iter().any(|s| *s != SliceStatus::Verified) {
            found = self.sliding_search(data, |fi, si| {
                fi == file && slices.get(si).is_some_and(|s| *s == SliceStatus::Verified)
            });
            for f in &found {
                if f.file == file
                    && let Some(s) = slices.get_mut(f.slice)
                    && *s != SliceStatus::Verified
                {
                    if !matches!(*s, SliceStatus::Misplaced { .. }) {
                        verified = verified.saturating_add(1);
                    }
                    *s = SliceStatus::Misplaced { offset: f.offset };
                }
            }
        }
        FileVerification {
            file,
            size_ok,
            md5_ok,
            slices,
            found,
            verified,
        }
    }

    /// Slide a block-sized window over `data` (continuing into virtual zero padding at the end)
    /// and report every slice of the set found, skipping `(file, slice)` pairs for which
    /// `already(file, slice)` is true.
    pub fn sliding_search(
        &self,
        data: &[u8],
        already: impl Fn(usize, usize) -> bool,
    ) -> Vec<FoundSlice> {
        let mut out = Vec::new();
        let bs = usize::try_from(self.block_size).unwrap_or(usize::MAX);
        let Some(roller) = RollingCrc32::new(self.block_size) else {
            return out;
        };
        if data.is_empty() {
            return out;
        }
        // Initial window: the first `bs` bytes (zero padded when the buffer is shorter).
        let first_len = data.len().min(bs);
        let first = data.get(..first_len).unwrap_or(&[]);
        let mut crc = if first_len == bs {
            crc32(first)
        } else {
            crate::gf2::crc32_combine(
                crc32(first),
                crate::gf2::crc32_zeros(bs - first_len),
                bs - first_len,
            )
        };
        let mut reported: HashMap<(usize, usize), ()> = HashMap::new();
        let last_start = data.len().saturating_sub(1);
        for pos in 0..=last_start {
            if pos != 0 {
                let out_byte = data.get(pos - 1).copied().unwrap_or(0);
                let in_byte = data
                    .get(pos.saturating_add(bs).saturating_sub(1))
                    .copied()
                    .unwrap_or(0);
                crc = roller.roll(crc, out_byte, in_byte);
            }
            if !self.may_contain(crc) {
                continue;
            }
            let Some(cands) = self.index.get(&crc) else {
                continue;
            };
            let end = pos.saturating_add(bs).min(data.len());
            let chunk = data.get(pos..end).unwrap_or(&[]);
            let mut digest: Option<[u8; 16]> = None;
            for &(fi, si) in cands {
                if already(fi, si) || reported.contains_key(&(fi, si)) {
                    continue;
                }
                let Some(exp) = self.files.get(fi).and_then(|f| f.slices.get(si)) else {
                    continue;
                };
                let d = *digest.get_or_insert_with(|| self.padded_md5(chunk));
                if d == exp.md5 {
                    reported.insert((fi, si), ());
                    out.push(FoundSlice {
                        file: fi,
                        slice: si,
                        global: self
                            .first_slice
                            .get(fi)
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(si),
                        offset: pos as u64,
                    });
                }
            }
        }
        out
    }

    /// Verify several buffers (`(file index, contents)`) and locate every slice of the set.
    pub fn verify_files(&self, buffers: &[(usize, &[u8])]) -> VerificationReport {
        let mut report = VerificationReport {
            total_slices: self.total,
            located: vec![None; self.total],
            ..VerificationReport::default()
        };
        for (bi, &(file, data)) in buffers.iter().enumerate() {
            let fv = self.verify_file(file, data);
            let bs = self.block_size;
            for (si, st) in fv.slices.iter().enumerate() {
                if let Some(g) = self.global_slice(file, si) {
                    let loc = match st {
                        SliceStatus::Verified => Some((bi, si as u64 * bs)),
                        SliceStatus::Misplaced { offset } => Some((bi, *offset)),
                        _ => None,
                    };
                    if let (Some(slot), Some(l)) = (report.located.get_mut(g), loc)
                        && slot.is_none()
                    {
                        *slot = Some(l);
                    }
                }
            }
            for f in &fv.found {
                if let Some(slot) = report.located.get_mut(f.global)
                    && slot.is_none()
                {
                    *slot = Some((bi, f.offset));
                }
            }
            report.files.push(fv);
        }
        report.missing = report
            .located
            .iter()
            .enumerate()
            .filter(|(_, l)| l.is_none())
            .map(|(g, _)| g)
            .collect();
        report
    }

    /// Repairability given `recovery_slices` usable recovery slices.
    pub fn assess(&self, report: &VerificationReport, recovery_slices: usize) -> RepairAssessment {
        let missing = report.missing.len();
        RepairAssessment {
            total_slices: self.total,
            missing_slices: missing,
            recovery_slices,
            repairable: missing <= recovery_slices,
            shortfall: missing.saturating_sub(recovery_slices),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(n: usize, seed: u32) -> Vec<u8> {
        (0..n as u32)
            .map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed) >> 13) as u8)
            .collect()
    }

    fn spec(id: u8, bytes: &[u8], bs: usize) -> SourceSpec {
        let slices = bytes
            .chunks(bs)
            .map(|c| {
                let mut p = c.to_vec();
                p.resize(bs, 0);
                SliceChecksum {
                    md5: Md5::digest(&p).into(),
                    crc32: crc32(&p),
                }
            })
            .collect();
        SourceSpec {
            file_id: [id; 16],
            size: bytes.len() as u64,
            md5: Some(Md5::digest(bytes).into()),
            slices,
        }
    }

    #[test]
    fn aligned_misplaced_and_assessment() {
        let bs = 1000usize;
        let a = data(4500, 1);
        let b = data(2000, 2);
        let v = SetVerifier::new(bs as u64, vec![spec(9, &a, bs), spec(3, &b, bs)]).unwrap();
        assert_eq!(v.total_slices(), 7);
        assert_eq!(v.files()[0].file_id, [3; 16]); // sorted by id: b first
        assert_eq!(v.file_index(&[9; 16]), Some(1));
        assert_eq!(v.global_slice(1, 2), Some(4));
        assert_eq!(v.locate_global(4), Some((1, 2)));
        assert_eq!(v.locate_global(7), None);
        assert_eq!(v.global_slice(1, 5), None);

        let ok = v.verify_file(1, &a);
        assert!(ok.is_intact());
        assert_eq!(ok.verified, 5);
        assert_eq!(ok.md5_ok, Some(true));
        assert!(ok.found.is_empty());

        // Corrupt slice 1, shift the tail by inserting 3 bytes before slice 3.
        let mut dmg = a.clone();
        dmg[1500] ^= 0xFF;
        dmg.splice(3000..3000, [1u8, 2, 3]);
        let r = v.verify_file(1, &dmg);
        assert!(!r.size_ok);
        assert_eq!(r.md5_ok, None);
        assert_eq!(r.slices[0], SliceStatus::Verified);
        assert_eq!(r.slices[1], SliceStatus::Damaged);
        assert_eq!(r.slices[2], SliceStatus::Verified);
        assert_eq!(r.slices[3], SliceStatus::Misplaced { offset: 3003 });
        assert_eq!(r.slices[4], SliceStatus::Misplaced { offset: 4003 });
        assert_eq!(r.verified, 4);
        assert!(!r.is_intact());

        // Truncated buffer: missing slices and the short tail still verifies with padding.
        let r = v.verify_file(1, &a[..2300]);
        assert_eq!(r.slices[2], SliceStatus::Damaged);
        assert_eq!(r.slices[3], SliceStatus::Missing);
        assert_eq!(r.slices[4], SliceStatus::Missing);
        let r = v.verify_file(1, &a[..4000]);
        assert_eq!(r.slices[4], SliceStatus::Missing);
        assert!(r.slices[..4].iter().all(|s| *s == SliceStatus::Verified));

        // A buffer that is really file b, offered as file a: its slices are found via sliding.
        let r = v.verify_file(1, &b);
        let found_b: Vec<(usize, usize, u64)> = r
            .found
            .iter()
            .map(|f| (f.file, f.slice, f.offset))
            .collect();
        assert_eq!(found_b, vec![(0, 0, 0), (0, 1, 1000)]);

        let report = v.verify_files(&[(1, &dmg), (0, &b)]);
        assert_eq!(report.total_slices, 7);
        assert_eq!(report.missing, vec![3]); // global 3 = file a slice 1
        assert_eq!(report.located[5], Some((0, 3003)));
        assert_eq!(report.located[0], Some((1, 0)));
        let asmt = v.assess(&report, 1);
        assert!(asmt.repairable);
        assert_eq!(asmt.shortfall, 0);
        let asmt = v.assess(&report, 0);
        assert_eq!(
            (asmt.repairable, asmt.shortfall, asmt.missing_slices),
            (false, 1, 1)
        );

        assert!(v.verify_file(5, &a).slices.is_empty());
        assert!(SetVerifier::new(0, vec![]).is_none());
        let mut bad = spec(1, &a, bs);
        bad.slices.pop();
        assert!(SetVerifier::new(bs as u64, vec![bad]).is_none());
        assert!(v.sliding_search(&[], |_, _| false).is_empty());
    }
}
