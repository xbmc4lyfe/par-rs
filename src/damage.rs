//! Live-download hole tracking, damage projection and zero-read ("ParQuick") verification.
//!
//! nzbget knows, for every downloaded file, which yEnc articles (segments) arrived intact and
//! what their decoded CRC-32s are. That information lets us:
//!
//! * project how many PAR2 blocks are damaged while the download is still running
//!   ([`blocks_touched`], [`project_par_damage`]) and abort early when the recovery set can
//!   never cover the damage ([`par_cannot_cover`]);
//! * verify completely downloaded files with **zero disk I/O** by combining the IFSC
//!   per-slice CRCs into a whole-file CRC and comparing it with the download CRC
//!   ([`verify_success_file_crc`]);
//! * verify partially downloaded files by combining the CRCs of intact articles in memory and
//!   reading only the bytes where article and slice boundaries do not line up
//!   ([`verify_partial_file`], [`smart_calc_range_crc`]).
//!
//! All offsets are `i64` to match the nzbget data model. Ranges given as `(start, end)` to
//! the CRC helpers are **inclusive** of `end` (as in `ParChecker::SmartCalcFileRangeCrc`).

use crate::crc::{Crc32, Crc32Combiner, crc32_combine, crc32_zeros};
use std::fs::File;
use std::io;

/// A byte range `[offset, offset + size)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ByteRange {
    /// Start offset.
    pub offset: i64,
    /// Length in bytes.
    pub size: i64,
}

impl ByteRange {
    /// New range.
    pub const fn new(offset: i64, size: i64) -> Self {
        Self { offset, size }
    }

    /// Exclusive end.
    pub const fn end(&self) -> i64 {
        self.offset + self.size
    }

    /// Whether the range is empty or negative.
    pub const fn is_empty(&self) -> bool {
        self.size <= 0
    }
}

/// Sort by offset and merge overlapping / adjacent ranges, dropping empty ones.
pub fn normalize_ranges(ranges: &[ByteRange]) -> Vec<ByteRange> {
    let mut v: Vec<ByteRange> = ranges.iter().copied().filter(|r| !r.is_empty()).collect();
    v.sort_unstable();
    let mut out: Vec<ByteRange> = Vec::with_capacity(v.len());
    for r in v {
        if let Some(last) = out.last_mut()
            && r.offset <= last.end()
        {
            let end = last.end().max(r.end());
            last.size = end - last.offset;
            continue;
        }
        out.push(r);
    }
    out
}

/// Number of distinct `slice_size`-byte blocks touched by `holes` (damaged byte ranges).
/// Overlapping holes within one block are counted once.
pub fn blocks_touched(holes: &[ByteRange], slice_size: u64) -> i32 {
    if slice_size == 0 {
        return 0;
    }
    let ss = slice_size as i64;
    let mut intervals: Vec<(i64, i64)> = holes
        .iter()
        .filter(|h| !h.is_empty())
        .map(|h| {
            let first = h.offset.max(0) / ss;
            let last = (h.end() - 1).max(0) / ss;
            (first, last)
        })
        .collect();
    intervals.sort_unstable();
    let mut count: i64 = 0;
    let mut cur: Option<(i64, i64)> = None;
    for (a, b) in intervals {
        match cur {
            Some((ca, cb)) if a <= cb + 1 => cur = Some((ca, cb.max(b))),
            Some((ca, cb)) => {
                count += cb - ca + 1;
                cur = Some((a, b));
            }
            None => cur = Some((a, b)),
        }
    }
    if let Some((ca, cb)) = cur {
        count += cb - ca + 1;
    }
    count.min(i32::MAX as i64) as i32
}

/// Whether `[from, to)` is contiguously tiled by `sorted_ranges` (sorted by offset; overlaps
/// allowed). An empty interval is trivially covered.
pub fn range_covered(sorted_ranges: &[ByteRange], from: i64, to: i64) -> bool {
    if from >= to {
        return true;
    }
    let mut cur = from;
    for r in sorted_ranges {
        if r.is_empty() || r.end() <= cur {
            continue;
        }
        if r.offset > cur {
            return false;
        }
        cur = cur.max(r.end());
        if cur >= to {
            return true;
        }
    }
    false
}

/// Gaps of `[0, file_size)` not covered by `covered` (any order, overlaps allowed).
pub fn compute_holes(covered: &[ByteRange], file_size: i64) -> Vec<ByteRange> {
    let mut holes = Vec::new();
    if file_size <= 0 {
        return holes;
    }
    let mut cur = 0i64;
    for r in normalize_ranges(covered) {
        if r.offset >= file_size {
            break;
        }
        if r.offset > cur {
            holes.push(ByteRange::new(cur, r.offset - cur));
        }
        cur = cur.max(r.end());
        if cur >= file_size {
            break;
        }
    }
    if cur < file_size {
        holes.push(ByteRange::new(cur, file_size - cur));
    }
    holes
}

/// Damage information for one file of the recovery set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileDamage<'a> {
    /// Byte ranges known to be bad (failed articles).
    pub holes: &'a [ByteRange],
    /// Blocks of this file if the whole file is missing (no article arrived); `None` if the
    /// file exists (possibly partially).
    pub missing_file_blocks: Option<i32>,
}

/// Projected number of damaged input blocks across all files.
pub fn project_par_damage(files: &[FileDamage<'_>], slice_size: u64) -> i32 {
    let mut total: i64 = 0;
    for f in files {
        total += match f.missing_file_blocks {
            Some(b) => b.max(0) as i64,
            None => blocks_touched(f.holes, slice_size) as i64,
        };
    }
    total.min(i32::MAX as i64) as i32
}

/// Whether the projected damage exceeds what the available recovery blocks can repair.
pub fn par_cannot_cover(damaged_blocks: i32, available_recovery_blocks: i32) -> bool {
    damaged_blocks > available_recovery_blocks.max(0)
}

// ---------------------------------------------------------------------------------------------
// Segments and CRC arithmetic
// ---------------------------------------------------------------------------------------------

/// A downloaded article (yEnc part) as written to the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Offset within the file.
    pub offset: i64,
    /// Decoded size.
    pub size: i64,
    /// CRC-32 of the decoded data (valid only when `success`).
    pub crc: u32,
    /// Whether the article was downloaded and decoded successfully.
    pub success: bool,
}

impl Segment {
    /// Exclusive end.
    pub const fn end(&self) -> i64 {
        self.offset + self.size
    }
}

/// Reads raw bytes to compute CRCs where in-memory article CRCs do not line up with slices.
pub trait RangeReader {
    /// CRC-32 of `len` bytes starting at `start`.
    fn range_crc(&mut self, start: u64, len: u64) -> io::Result<u32>;
}

impl RangeReader for File {
    fn range_crc(&mut self, start: u64, len: u64) -> io::Result<u32> {
        let mut buf = vec![0u8; (len as usize).min(64 * 1024)];
        let mut h = Crc32::new();
        let mut pos = start;
        let mut remaining = len;
        while remaining > 0 {
            let n = (remaining as usize).min(buf.len());
            crate::packet::read_exact_at(self, pos, &mut buf[..n])?;
            h.update(&buf[..n]);
            pos += n as u64;
            remaining -= n as u64;
        }
        Ok(h.finish())
    }
}

impl RangeReader for &[u8] {
    fn range_crc(&mut self, start: u64, len: u64) -> io::Result<u32> {
        let s = usize::try_from(start).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let e = s
            .checked_add(len as usize)
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let d = self.get(s..e).ok_or(io::ErrorKind::UnexpectedEof)?;
        Ok(crate::crc::crc32(d))
    }
}

/// A reader that refuses every read; use when the file must not be touched (forces callers
/// to fall back to full verification whenever article CRCs alone are insufficient).
pub struct NoDiskAccess;

impl RangeReader for NoDiskAccess {
    fn range_crc(&mut self, _start: u64, _len: u64) -> io::Result<u32> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "disk access disabled",
        ))
    }
}

/// CRC-32 of the inclusive byte range `[start, end]` of a file, combining the CRCs of
/// successfully downloaded segments that lie fully inside the range and reading from disk
/// only the parts not covered by whole intact segments (partial overlaps at either end,
/// gaps, and failed segments).
///
/// `segments` must be sorted by offset and non-overlapping.
pub fn smart_calc_range_crc(
    segments: &[Segment],
    start: i64,
    end: i64,
    reader: &mut dyn RangeReader,
) -> io::Result<u32> {
    if end < start {
        return Ok(0);
    }
    let range_end = end + 1; // exclusive
    let mut crc: u32 = 0;
    let mut cur = start;
    let read_part =
        |crc: &mut u32, from: i64, to: i64, reader: &mut dyn RangeReader| -> io::Result<()> {
            if to > from {
                let part = reader.range_crc(from as u64, (to - from) as u64)?;
                *crc = crc32_combine(*crc, part, (to - from) as u64);
            }
            Ok(())
        };
    for seg in segments {
        if seg.end() <= cur || seg.size <= 0 {
            continue;
        }
        if seg.offset >= range_end {
            break;
        }
        if seg.offset > cur {
            // Gap before this segment: read from disk.
            read_part(&mut crc, cur, seg.offset.min(range_end), reader)?;
            cur = seg.offset.min(range_end);
            if cur >= range_end {
                break;
            }
        }
        if seg.success && seg.offset == cur && seg.end() <= range_end {
            // Whole intact segment inside the range: combine in memory.
            crc = crc32_combine(crc, seg.crc, seg.size as u64);
            cur = seg.end();
        } else {
            // Partial overlap or failed segment: read the overlapping part.
            let to = seg.end().min(range_end);
            read_part(&mut crc, cur, to, reader)?;
            cur = to;
        }
        if cur >= range_end {
            break;
        }
    }
    if cur < range_end {
        read_part(&mut crc, cur, range_end, reader)?;
    }
    Ok(crc)
}

/// Zero-read verification of a completely downloaded file: compares the download CRC
/// (extended with zeros to `block_count * slice_size`) with the CRC obtained by combining
/// the IFSC per-slice CRCs. Port of `ParChecker::VerifySuccessDataFile`.
pub fn verify_success_file_crc(
    download_crc: u32,
    file_size: u64,
    block_crcs: &[u32],
    slice_size: u64,
) -> bool {
    let total = slice_size.saturating_mul(block_crcs.len() as u64);
    let padded = if total > file_size {
        crc32_zeros(download_crc, total - file_size)
    } else {
        download_crc
    };
    let par_crc = crate::crc::combine_block_crcs(block_crcs, slice_size);
    par_crc == padded
}

/// Blocks presumed valid from the article download status alone (no CRC check):
/// a block is presumed valid when a contiguous chain of successful segments starts at or
/// before the block and reaches its end. Port of the first loop of
/// `ParChecker::VerifyPartialDataFile`.
pub fn presumed_valid_blocks(
    segments: &[Segment],
    file_size: i64,
    slice_size: i64,
    block_count: usize,
) -> Vec<bool> {
    let mut valid = vec![false; block_count];
    if slice_size <= 0 {
        return valid;
    }
    for (i, slot) in valid.iter_mut().enumerate() {
        let block_start = i as i64 * slice_size;
        let block_end = if block_start + slice_size < file_size - 1 {
            block_start + slice_size
        } else {
            file_size - 1
        };
        let mut block_ok = false;
        let mut end_found = false;
        let mut cur = 0i64;
        for seg in segments {
            if !block_ok && seg.success && seg.offset <= block_start && seg.end() >= block_start {
                block_ok = true;
                cur = seg.offset;
            }
            if block_ok {
                if !(seg.success && seg.offset == cur) {
                    block_ok = false;
                    break;
                }
                if seg.end() >= block_end {
                    end_found = true;
                    break;
                }
                cur = seg.end();
            }
        }
        *slot = block_ok && end_found;
    }
    valid
}

/// Verify a partially downloaded file using article CRCs. Returns the per-block validity
/// vector when every run of presumed-valid blocks checks out, or `None` when a CRC mismatch
/// (or an unreadable range) means the file needs a full scan. Port of
/// `ParChecker::VerifyPartialDataFile`.
pub fn verify_partial_file(
    segments: &[Segment],
    file_size: i64,
    block_crcs: &[u32],
    slice_size: i64,
    reader: &mut dyn RangeReader,
) -> io::Result<Option<Vec<bool>>> {
    if slice_size <= 0 {
        return Ok(None);
    }
    let valid = presumed_valid_blocks(segments, file_size, slice_size, block_crcs.len());
    let comb = Crc32Combiner::new(slice_size as u64);
    let mut i = 0usize;
    while i < valid.len() {
        if !valid[i] {
            i += 1;
            continue;
        }
        let run_start = i;
        let mut par_crc = block_crcs[i];
        i += 1;
        while i < valid.len() && valid[i] {
            par_crc = comb.combine(par_crc, block_crcs[i]);
            i += 1;
        }
        let run_end = i - 1;
        let bytes_start = run_start as i64 * slice_size;
        let bytes_end = run_end as i64 * slice_size + slice_size - 1;
        let clamped_end = bytes_end.min(file_size - 1);
        let mut download_crc =
            match smart_calc_range_crc(segments, bytes_start, clamped_end, reader) {
                Ok(c) => c,
                Err(e) if e.kind() == io::ErrorKind::Unsupported => return Ok(None),
                Err(e) => return Err(e),
            };
        if bytes_end > file_size - 1 {
            download_crc = crc32_zeros(download_crc, (bytes_end - (file_size - 1)) as u64);
        }
        if download_crc != par_crc {
            return Ok(None);
        }
    }
    Ok(Some(valid))
}

/// Outcome of a zero/minimal-read verification attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuickVerdict {
    /// All blocks verified intact.
    Complete,
    /// The listed blocks (by index) are intact; the rest are damaged.
    Partial(Vec<bool>),
    /// Article information contradicts the PAR2 checksums (or is missing); a full scan is
    /// required.
    NeedsFullScan,
}

/// Download status of a file as tracked by the downloader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DownloadStatus<'a> {
    /// Every article arrived; `crc` is the CRC of the whole decoded file.
    Success {
        /// Whole-file CRC-32.
        crc: u32,
    },
    /// Some articles failed; the segment list carries per-article status.
    Partial {
        /// Sorted, non-overlapping segments.
        segments: &'a [Segment],
    },
    /// Not a single article arrived.
    Failure,
}

/// Quick verification entry point combining [`verify_success_file_crc`] and
/// [`verify_partial_file`]. `file_size` is the size of the file on disk.
pub fn quick_verify(
    status: &DownloadStatus<'_>,
    file_size: u64,
    block_crcs: &[u32],
    slice_size: u64,
    reader: &mut dyn RangeReader,
) -> io::Result<QuickVerdict> {
    if block_crcs.is_empty() {
        return Ok(QuickVerdict::Complete);
    }
    match status {
        DownloadStatus::Success { crc } => {
            let expected_blocks = file_size.div_ceil(slice_size.max(1)) as usize;
            if expected_blocks != block_crcs.len() {
                return Ok(QuickVerdict::NeedsFullScan);
            }
            if verify_success_file_crc(*crc, file_size, block_crcs, slice_size) {
                Ok(QuickVerdict::Complete)
            } else {
                Ok(QuickVerdict::NeedsFullScan)
            }
        }
        DownloadStatus::Partial { segments } => {
            match verify_partial_file(
                segments,
                file_size as i64,
                block_crcs,
                slice_size as i64,
                reader,
            )? {
                Some(v) if v.iter().all(|&b| b) => Ok(QuickVerdict::Complete),
                Some(v) => Ok(QuickVerdict::Partial(v)),
                None => Ok(QuickVerdict::NeedsFullScan),
            }
        }
        DownloadStatus::Failure => Ok(QuickVerdict::Partial(vec![false; block_crcs.len()])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::crc32;

    fn r(o: i64, s: i64) -> ByteRange {
        ByteRange::new(o, s)
    }

    #[test]
    fn range_basics() {
        let x = r(10, 5);
        assert_eq!(x.end(), 15);
        assert!(!x.is_empty());
        assert!(r(0, 0).is_empty());
        assert!(r(0, -1).is_empty());
        assert_eq!(
            normalize_ranges(&[r(10, 5), r(0, 3), r(12, 10), r(3, 2), r(50, 0)]),
            vec![r(0, 5), r(10, 12)]
        );
        assert!(normalize_ranges(&[]).is_empty());
    }

    #[test]
    fn blocks_touched_merges_intervals() {
        assert_eq!(blocks_touched(&[], 100), 0);
        assert_eq!(blocks_touched(&[r(0, 1)], 100), 1);
        assert_eq!(blocks_touched(&[r(0, 100)], 100), 1);
        assert_eq!(blocks_touched(&[r(0, 101)], 100), 2);
        assert_eq!(blocks_touched(&[r(99, 2)], 100), 2);
        assert_eq!(blocks_touched(&[r(0, 50), r(50, 50)], 100), 1);
        assert_eq!(blocks_touched(&[r(0, 50), r(250, 10), r(120, 10)], 100), 3);
        assert_eq!(blocks_touched(&[r(0, 50), r(0, 50)], 100), 1);
        assert_eq!(blocks_touched(&[r(0, 1000)], 100), 10);
        assert_eq!(blocks_touched(&[r(0, 1000), r(500, 1)], 100), 10);
        assert_eq!(blocks_touched(&[r(0, 0)], 100), 0);
        assert_eq!(blocks_touched(&[r(0, 10)], 0), 0);
        assert_eq!(blocks_touched(&[r(-5, 10)], 100), 1);
    }

    #[test]
    fn coverage_and_holes() {
        let ranges = [r(0, 10), r(10, 10), r(25, 5), r(28, 10)];
        assert!(range_covered(&ranges, 0, 20));
        assert!(range_covered(&ranges, 5, 15));
        assert!(!range_covered(&ranges, 0, 21));
        assert!(!range_covered(&ranges, 15, 30));
        assert!(range_covered(&ranges, 25, 38));
        assert!(range_covered(&ranges, 30, 30));
        assert!(range_covered(&[], 5, 5));
        assert!(!range_covered(&[], 0, 1));
        assert_eq!(compute_holes(&ranges, 40), vec![r(20, 5), r(38, 2)]);
        assert_eq!(compute_holes(&ranges, 38), vec![r(20, 5)]);
        assert_eq!(compute_holes(&[], 10), vec![r(0, 10)]);
        assert_eq!(compute_holes(&ranges, 0), Vec::<ByteRange>::new());
        assert_eq!(compute_holes(&[r(5, 100)], 10), vec![r(0, 5)]);
        assert_eq!(compute_holes(&[r(0, 10), r(50, 10)], 20), vec![r(10, 10)]);
    }

    #[test]
    fn damage_projection() {
        let a = [r(0, 10), r(250, 10)];
        let b: [ByteRange; 0] = [];
        let files = [
            FileDamage {
                holes: &a,
                missing_file_blocks: None,
            },
            FileDamage {
                holes: &b,
                missing_file_blocks: Some(7),
            },
            FileDamage {
                holes: &b,
                missing_file_blocks: None,
            },
        ];
        assert_eq!(project_par_damage(&files, 100), 2 + 7);
        assert!(par_cannot_cover(9, 8));
        assert!(!par_cannot_cover(9, 9));
        assert!(!par_cannot_cover(0, 0));
        assert!(par_cannot_cover(1, -5));
    }

    fn make_file(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u32).wrapping_mul(2654435761) as u8)
            .map(|b| b ^ 0x5A)
            .collect()
    }

    fn segments_for(data: &[u8], article: usize, failed: &[usize]) -> Vec<Segment> {
        data.chunks(article)
            .enumerate()
            .map(|(i, c)| Segment {
                offset: (i * article) as i64,
                size: c.len() as i64,
                crc: crc32(c),
                success: !failed.contains(&i),
            })
            .collect()
    }

    fn block_crcs_for(data: &[u8], slice: usize) -> Vec<u32> {
        data.chunks(slice)
            .map(|c| {
                let mut p = c.to_vec();
                p.resize(slice, 0);
                crc32(&p)
            })
            .collect()
    }

    #[test]
    fn smart_range_crc_matches_direct_computation() {
        let data = make_file(10_000);
        for article in [700usize, 1000, 1024, 333] {
            let segs = segments_for(&data, article, &[3]);
            for (s, e) in [
                (0i64, 9999i64),
                (0, 699),
                (700, 1399),
                (500, 2500),
                (2999, 3000),
                (9000, 9999),
                (3000, 3000),
                (0, 0),
            ] {
                let mut reader: &[u8] = &data;
                let got = smart_calc_range_crc(&segs, s, e, &mut reader).unwrap();
                assert_eq!(
                    got,
                    crc32(&data[s as usize..=e as usize]),
                    "article={article} range={s}..={e}"
                );
            }
            // Pure in-memory path: aligned range of intact segments needs no reads.
            let mut nodisk = NoDiskAccess;
            let aligned_end = (2 * article - 1) as i64;
            assert_eq!(
                smart_calc_range_crc(&segs, 0, aligned_end, &mut nodisk).unwrap(),
                crc32(&data[..2 * article])
            );
            // Misaligned → needs disk → error propagates.
            assert!(smart_calc_range_crc(&segs, 1, aligned_end, &mut nodisk).is_err());
        }
        let mut reader: &[u8] = &data;
        assert_eq!(smart_calc_range_crc(&[], 5, 4, &mut reader).unwrap(), 0);
        // No segments at all → everything read from disk.
        assert_eq!(
            smart_calc_range_crc(&[], 100, 199, &mut reader).unwrap(),
            crc32(&data[100..200])
        );
        // Range extends beyond the last segment.
        let segs = segments_for(&data[..5000], 1000, &[]);
        assert_eq!(
            smart_calc_range_crc(&segs, 4500, 6000, &mut reader).unwrap(),
            crc32(&data[4500..=6000])
        );
    }

    #[test]
    fn success_file_verification() {
        let data = make_file(12_345);
        let crcs = block_crcs_for(&data, 1000);
        assert_eq!(crcs.len(), 13);
        assert!(verify_success_file_crc(
            crc32(&data),
            data.len() as u64,
            &crcs,
            1000
        ));
        assert!(!verify_success_file_crc(
            crc32(&data) ^ 1,
            data.len() as u64,
            &crcs,
            1000
        ));
        // Exact multiple: no padding.
        let exact = &data[..12_000];
        let crcs = block_crcs_for(exact, 1000);
        assert!(verify_success_file_crc(crc32(exact), 12_000, &crcs, 1000));
        let mut reader: &[u8] = &data;
        assert_eq!(
            quick_verify(
                &DownloadStatus::Success { crc: crc32(exact) },
                12_000,
                &crcs,
                1000,
                &mut reader
            )
            .unwrap(),
            QuickVerdict::Complete
        );
        assert_eq!(
            quick_verify(
                &DownloadStatus::Success { crc: crc32(exact) },
                12_001,
                &crcs,
                1000,
                &mut reader
            )
            .unwrap(),
            QuickVerdict::NeedsFullScan
        );
        assert_eq!(
            quick_verify(
                &DownloadStatus::Success { crc: 0 },
                12_000,
                &crcs,
                1000,
                &mut reader
            )
            .unwrap(),
            QuickVerdict::NeedsFullScan
        );
        assert_eq!(
            quick_verify(&DownloadStatus::Failure, 12_000, &crcs, 1000, &mut reader).unwrap(),
            QuickVerdict::Partial(vec![false; 12])
        );
        assert_eq!(
            quick_verify(&DownloadStatus::Failure, 0, &[], 1000, &mut reader).unwrap(),
            QuickVerdict::Complete
        );
    }

    #[test]
    fn presumed_valid_blocks_follow_article_chains() {
        let data = make_file(10_000);
        // Articles of 750 bytes, blocks of 1000: block i spans articles floor(i*1000/750)..
        let segs = segments_for(&data, 750, &[2]); // bytes 1500..2249 failed → blocks 1 and 2 affected
        let v = presumed_valid_blocks(&segs, 10_000, 1000, 10);
        assert_eq!(
            v,
            vec![true, false, false, true, true, true, true, true, true, true]
        );
        // Aligned articles, one failure.
        let segs = segments_for(&data, 1000, &[4]);
        let v = presumed_valid_blocks(&segs, 10_000, 1000, 10);
        assert_eq!(v.iter().filter(|&&b| !b).count(), 1);
        assert!(!v[4]);
        // No segments → nothing valid.
        assert!(
            presumed_valid_blocks(&[], 10_000, 1000, 10)
                .iter()
                .all(|&b| !b)
        );
        assert!(
            presumed_valid_blocks(&segs, 10_000, 0, 10)
                .iter()
                .all(|&b| !b)
        );
    }

    #[test]
    fn partial_file_verification() {
        let data = make_file(12_345);
        let crcs = block_crcs_for(&data, 1000);
        let mut disk = data.clone();
        // Articles of 700 bytes; articles 5 and 12 failed and are zero-filled on disk.
        let failed = [5usize, 12];
        let segs = segments_for(&data, 700, &failed);
        for &f in &failed {
            let s = f * 700;
            let e = (s + 700).min(disk.len());
            disk[s..e].fill(0);
        }
        let mut reader: &[u8] = &disk;
        let v = verify_partial_file(&segs, disk.len() as i64, &crcs, 1000, &mut reader)
            .unwrap()
            .unwrap();
        // Article 5 = bytes 3500..4199 → blocks 3,4 damaged; article 12 = 8400..9099 → blocks 8,9.
        let expect: Vec<bool> = (0..13).map(|b| !matches!(b, 3 | 4 | 8 | 9)).collect();
        assert_eq!(v, expect);
        assert_eq!(
            quick_verify(
                &DownloadStatus::Partial { segments: &segs },
                disk.len() as u64,
                &crcs,
                1000,
                &mut reader
            )
            .unwrap(),
            QuickVerdict::Partial(expect.clone())
        );

        // A presumed-valid block that is actually corrupt on disk with a wrong article CRC → full scan.
        let mut bad_segs = segs.clone();
        bad_segs[0].crc ^= 1;
        let mut reader: &[u8] = &disk;
        assert!(
            verify_partial_file(&bad_segs, disk.len() as i64, &crcs, 1000, &mut reader)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            quick_verify(
                &DownloadStatus::Partial {
                    segments: &bad_segs
                },
                disk.len() as u64,
                &crcs,
                1000,
                &mut reader
            )
            .unwrap(),
            QuickVerdict::NeedsFullScan
        );

        // Disk access forbidden and misaligned articles → cannot verify → full scan.
        assert!(
            verify_partial_file(&segs, disk.len() as i64, &crcs, 1000, &mut NoDiskAccess)
                .unwrap()
                .is_none()
        );

        // All articles fine → Complete.
        let good = segments_for(&data, 700, &[]);
        let mut reader: &[u8] = &data;
        assert_eq!(
            quick_verify(
                &DownloadStatus::Partial { segments: &good },
                data.len() as u64,
                &crcs,
                1000,
                &mut reader
            )
            .unwrap(),
            QuickVerdict::Complete
        );
        // Aligned articles with no disk access needed at all.
        let aligned = segments_for(&data, 1000, &[2]);
        let v = verify_partial_file(&aligned, data.len() as i64, &crcs, 1000, &mut NoDiskAccess)
            .unwrap()
            .unwrap();
        assert_eq!(v.iter().filter(|&&b| !b).count(), 1);
        assert!(
            verify_partial_file(&aligned, data.len() as i64, &crcs, 0, &mut NoDiskAccess)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn file_range_reader() {
        let data = make_file(5000);
        let dir = std::env::temp_dir().join(format!("par-rs-damage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.bin");
        std::fs::write(&p, &data).unwrap();
        let mut f = File::open(&p).unwrap();
        assert_eq!(f.range_crc(100, 2000).unwrap(), crc32(&data[100..2100]));
        assert_eq!(f.range_crc(0, 0).unwrap(), 0);
        assert!(f.range_crc(4000, 2000).is_err());
        let mut m: &[u8] = &data;
        assert!(m.range_crc(4000, 2000).is_err());
        assert!(m.range_crc(u64::MAX, 1).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
