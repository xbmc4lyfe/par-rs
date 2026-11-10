//! Block scanner: locates PAR2 input slices inside arbitrary files.
//!
//! The scanner finds slices in files that are intact, renamed, split (`.001`, `.002`),
//! concatenated, or damaged in the middle:
//!
//! 1. **Aligned probe.** Every `slice_size`-aligned offset is checked first; if a file is an
//!    exact (possibly renamed) copy, this finds all its blocks with one CRC and one MD5 per
//!    block and no sliding at all.
//! 2. **Sliding window.** On a mismatch the CRC-32 of the `slice_size`-byte window is rolled
//!    one byte at a time in `O(1)` using a [`WindowTable`]. Each window CRC is tested against
//!    a one-bit pre-filter, then against an open-addressed hash table of all known slice CRCs,
//!    and only real hits are confirmed with a 16-byte MD5.
//! 3. **Virtual zero padding.** Near the end of the file the window extends past EOF with
//!    zero bytes, exactly like the padded last slice of a PAR2 file, so misaligned final
//!    slices are found too.
//!
//! The scanner also produces the fused file hashes (CRC-32, MD5, 16k MD5) of the data it
//! streams, so a verification pass reads every byte exactly once.

use crate::crc::{self, INIT, WindowTable};
use crate::hasher::{FileHasher, FileHashes, md5};
use crate::packet::PacketSource;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

/// Identifies one input slice of the recovery set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockRef {
    /// Index of the source file (in `libpar2` order).
    pub file_index: u32,
    /// Slice index within that file.
    pub block_index: u32,
}

/// Known checksums of one input slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChecksumEntry {
    /// CRC-32 of the (zero padded) slice.
    pub crc32: u32,
    /// MD5 of the (zero padded) slice.
    pub md5: [u8; 16],
    /// Which slice this is.
    pub block: BlockRef,
}

const EMPTY: u32 = u32::MAX;

/// Hash index of every known slice CRC with an MD5 confirmation step.
#[derive(Clone, Debug)]
pub struct ChecksumIndex {
    slice_size: u64,
    entries: Vec<ChecksumEntry>,
    keys: Vec<u32>,
    vals: Vec<u32>,
    mask: usize,
    filter: Vec<u64>,
    filter_mask: usize,
    duplicate_crcs: usize,
}

#[inline(always)]
fn mix(crc: u32) -> u64 {
    // Cheap avalanche so that adjacent CRCs spread over buckets.
    (crc as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 20
}

impl ChecksumIndex {
    /// Build the index for slices of `slice_size` bytes.
    pub fn new(slice_size: u64, entries: Vec<ChecksumEntry>) -> Self {
        assert!(slice_size > 0, "slice size must be positive");
        let n = entries.len().max(1);
        let cap = (n * 2).next_power_of_two().max(16);
        let mut keys = vec![EMPTY; cap];
        let mut vals = vec![EMPTY; cap];
        let mask = cap - 1;
        let filter_bits = (n * 16).next_power_of_two().max(64);
        let mut filter = vec![0u64; filter_bits / 64];
        let filter_mask = filter_bits - 1;
        let mut duplicate_crcs = 0usize;
        for (i, e) in entries.iter().enumerate() {
            let mut slot = (mix(e.crc32) as usize) & mask;
            loop {
                if vals[slot] == EMPTY {
                    keys[slot] = e.crc32;
                    vals[slot] = i as u32;
                    break;
                }
                if keys[slot] == e.crc32 {
                    duplicate_crcs += 1;
                }
                slot = (slot + 1) & mask;
            }
            let bit = (e.crc32 as usize) & filter_mask;
            filter[bit / 64] |= 1u64 << (bit % 64);
        }
        Self {
            slice_size,
            entries,
            keys,
            vals,
            mask,
            filter,
            filter_mask,
            duplicate_crcs,
        }
    }

    /// Slice size.
    pub fn slice_size(&self) -> u64 {
        self.slice_size
    }

    /// Number of indexed slices.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries.
    pub fn entries(&self) -> &[ChecksumEntry] {
        &self.entries
    }

    /// Number of entries whose CRC collides with an earlier entry (identical slices or true
    /// CRC collisions). When zero, a CRC match identifies a slice uniquely.
    pub fn duplicate_crcs(&self) -> usize {
        self.duplicate_crcs
    }

    /// One-bit pre-filter: `false` means the CRC is definitely not indexed.
    #[inline(always)]
    pub fn might_contain(&self, crc: u32) -> bool {
        let bit = (crc as usize) & self.filter_mask;
        (self.filter[bit / 64] >> (bit % 64)) & 1 != 0
    }

    /// Entries whose CRC equals `crc`.
    pub fn lookup(&self, crc: u32) -> impl Iterator<Item = &ChecksumEntry> + '_ {
        let start = (mix(crc) as usize) & self.mask;
        let mut slot = start;
        let mut done = false;
        std::iter::from_fn(move || {
            while !done {
                let v = self.vals[slot];
                if v == EMPTY {
                    done = true;
                    return None;
                }
                let k = self.keys[slot];
                slot = (slot + 1) & self.mask;
                if slot == start {
                    done = true;
                }
                if k == crc {
                    return Some(&self.entries[v as usize]);
                }
            }
            None
        })
    }
}

/// A slice located in a scanned file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoundBlock {
    /// Offset of the slice data within the scanned file.
    pub offset: u64,
    /// Which slice it is.
    pub block: BlockRef,
}

/// Scanner statistics and results.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Slices found (one entry per matching slice; identical slices may share an offset).
    pub found: Vec<FoundBlock>,
    /// Bytes of the file processed.
    pub bytes_scanned: u64,
    /// Window CRCs that passed the pre-filter and hit the hash table.
    pub crc_hits: u64,
    /// CRC hits whose MD5 did not confirm.
    pub md5_misses: u64,
    /// Blocks found at `slice_size`-aligned offsets.
    pub aligned_hits: u64,
    /// Blocks found at unaligned offsets by the sliding window.
    pub sliding_hits: u64,
    /// Bytes examined by the sliding window.
    pub slid_bytes: u64,
    /// Fused hashes of the whole file.
    pub file_hashes: Option<FileHashes>,
    /// Whether the scan was cancelled.
    pub cancelled: bool,
}

impl ScanReport {
    /// Whether every block of `expected` (the slices of one file, in order) was found at its
    /// natural offset.
    pub fn is_full_match(&self, expected: &[ChecksumEntry], slice_size: u64) -> bool {
        expected.iter().enumerate().all(|(i, e)| {
            self.found
                .iter()
                .any(|f| f.block == e.block && f.offset == i as u64 * slice_size)
        })
    }
}

/// Scanner options.
#[derive(Clone, Copy, Debug)]
pub struct ScanConfig<'a> {
    /// Only probe aligned offsets (no sliding); used for rename-only passes.
    pub aligned_only: bool,
    /// Preferred buffer size (bytes). Raised automatically to hold at least one window.
    pub buffer_size: usize,
    /// Also compute the fused file hashes while scanning.
    pub hash_file: bool,
    /// Result of an earlier aligned check of the expected file (`true` = slice `b` verified at
    /// offset `b * slice_size`). When present (and as long as `expected`) the scanner skips its
    /// own aligned pass and does not re-hash those slices during the sliding scan.
    pub known_aligned: Option<&'a [bool]>,
}

impl Default for ScanConfig<'_> {
    fn default() -> Self {
        Self {
            aligned_only: false,
            buffer_size: 8 << 20,
            hash_file: true,
            known_aligned: None,
        }
    }
}

/// Streaming buffer over a [`PacketSource`] that keeps `[base, base + len)` loaded.
struct Window<'a, S: PacketSource + ?Sized> {
    src: &'a S,
    file_len: u64,
    buf: Vec<u8>,
    base: u64,
    len: usize,
    hasher: Option<FileHasher>,
    hashed_to: u64,
}

impl<'a, S: PacketSource + ?Sized> Window<'a, S> {
    fn new(src: &'a S, cap: usize, hash: bool) -> Self {
        Self {
            src,
            file_len: src.source_len(),
            buf: vec![0u8; cap],
            base: 0,
            len: 0,
            hasher: hash.then(FileHasher::new),
            hashed_to: 0,
        }
    }

    /// Make `[pos, min(pos + need, file_len))` resident, loading from `pos` onwards.
    fn ensure(&mut self, pos: u64, need: u64) -> io::Result<()> {
        let end = (pos + need).min(self.file_len);
        if pos >= self.base && end <= self.base + self.len as u64 {
            return Ok(());
        }
        // Reload starting at `pos` (keep whatever overlaps to avoid re-reading it).
        let keep_from = pos.max(self.base);
        let keep_to = (self.base + self.len as u64).min(pos + self.buf.len() as u64);
        let mut filled = 0usize;
        if keep_from == pos && keep_to > keep_from {
            let s = (keep_from - self.base) as usize;
            let e = (keep_to - self.base) as usize;
            self.buf.copy_within(s..e, 0);
            filled = e - s;
        }
        self.base = pos;
        let want = ((self.file_len - pos) as usize).min(self.buf.len());
        if want > filled {
            let (head, tail) = self.buf.split_at_mut(filled);
            let _ = head;
            self.src
                .read_at(pos + filled as u64, &mut tail[..want - filled])?;
        }
        self.len = want;
        if let Some(h) = &mut self.hasher {
            let abs_end = self.base + self.len as u64;
            if abs_end > self.hashed_to {
                let from = (self.hashed_to.max(self.base) - self.base) as usize;
                h.update(&self.buf[from..self.len]);
                self.hashed_to = abs_end;
            }
        }
        Ok(())
    }

    /// Resident bytes `[pos, pos + n)`; caller guarantees residency.
    #[inline]
    fn bytes(&self, pos: u64, n: usize) -> &[u8] {
        let s = (pos - self.base) as usize;
        &self.buf[s..s + n]
    }

    #[inline]
    fn byte(&self, pos: u64) -> u8 {
        self.buf[(pos - self.base) as usize]
    }

    fn finish_hash(mut self) -> Option<FileHashes> {
        // Hash any trailing bytes never made resident (cannot happen when scan reaches EOF,
        // but cancellation may stop early).
        if let Some(h) = &mut self.hasher {
            let mut pos = self.hashed_to;
            let mut tmp = vec![0u8; 1 << 20];
            while pos < self.file_len {
                let n = ((self.file_len - pos) as usize).min(tmp.len());
                self.src.read_at(pos, &mut tmp[..n]).ok()?;
                h.update(&tmp[..n]);
                pos += n as u64;
            }
        }
        self.hasher.map(|h| h.finish())
    }
}

/// Scan `src` for slices listed in `index`.
///
/// * `expected`: the slices of the file this source is believed to be (in order); when given
///   and the length matches, an aligned fast path checks them first.
/// * `cancel`: cooperative cancellation flag checked between buffer refills.
/// * `progress`: called with the number of bytes processed so far.
pub fn scan_source<S: PacketSource + ?Sized>(
    src: &S,
    index: &ChecksumIndex,
    expected: Option<&[ChecksumEntry]>,
    config: &ScanConfig,
    cancel: Option<&AtomicBool>,
    progress: &mut dyn FnMut(u64),
) -> io::Result<ScanReport> {
    let ss = index.slice_size();
    let ss_us = usize::try_from(ss)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "slice size too large"))?;
    let file_len = src.source_len();
    let mut report = ScanReport::default();
    let cap = config
        .buffer_size
        .max(ss_us + (64 << 10))
        .max(2 * ss_us.min(64 << 20));
    let mut win = Window::new(src, cap, config.hash_file);
    let is_cancelled = || cancel.is_some_and(|c| c.load(Ordering::Relaxed));

    if file_len == 0 {
        report.file_hashes = win.finish_hash();
        return Ok(report);
    }

    let mut scratch: Vec<u8> = Vec::new();
    // Confirm candidates at `pos` whose CRC is `crc_final`; returns true if any matched.
    let confirm = |pos: u64,
                   crc_final: u32,
                   win: &Window<'_, S>,
                   report: &mut ScanReport,
                   scratch: &mut Vec<u8>,
                   aligned: bool|
     -> bool {
        let mut digest: Option<[u8; 16]> = None;
        let mut any = false;
        for e in index.lookup(crc_final) {
            report.crc_hits += 1;
            let d = *digest.get_or_insert_with(|| {
                let avail = ((file_len - pos) as usize).min(ss_us);
                if avail == ss_us {
                    md5(win.bytes(pos, ss_us))
                } else {
                    scratch.clear();
                    scratch.extend_from_slice(win.bytes(pos, avail));
                    scratch.resize(ss_us, 0);
                    md5(scratch)
                }
            });
            if d == e.md5 {
                report.found.push(FoundBlock {
                    offset: pos,
                    block: e.block,
                });
                any = true;
            } else {
                report.md5_misses += 1;
            }
        }
        if any {
            if aligned {
                report.aligned_hits += 1;
            } else {
                report.sliding_hits += 1;
            }
        }
        any
    };

    // Fresh CRC of the (zero padded) window at `pos`.
    let window_crc_raw = |pos: u64, win: &Window<'_, S>| -> u32 {
        let avail = ((file_len - pos) as usize).min(ss_us);
        let raw = crc::update_raw(INIT, win.bytes(pos, avail));
        if avail < ss_us {
            crc::crc32_shift_raw(raw, (ss_us - avail) as u64)
        } else {
            raw
        }
    };

    // ---- Aligned fast path against the expected file ------------------------------------
    let mut pos: u64 = 0;
    // Slices of the expected file already verified at their natural offsets; the general
    // scan reuses these instead of hashing the same window again.
    let mut aligned_ok: Vec<bool> = Vec::new();
    if let Some(exp) = expected {
        let expected_len_ok = !exp.is_empty()
            && (exp.len() as u64 - 1) * ss < file_len
            && file_len <= exp.len() as u64 * ss;
        if let Some(known) = config.known_aligned.filter(|k| k.len() == exp.len()) {
            aligned_ok = known.to_vec();
        } else if expected_len_ok {
            let mut all = true;
            let mut p = 0u64;
            aligned_ok = Vec::with_capacity(exp.len());
            for e in exp {
                if is_cancelled() {
                    report.cancelled = true;
                    break;
                }
                win.ensure(p, ss)?;
                let crc = window_crc_raw(p, &win) ^ INIT;
                let ok = crc == e.crc32 && {
                    let avail = ((file_len - p) as usize).min(ss_us);
                    let d = if avail == ss_us {
                        md5(win.bytes(p, ss_us))
                    } else {
                        scratch.clear();
                        scratch.extend_from_slice(win.bytes(p, avail));
                        scratch.resize(ss_us, 0);
                        md5(&scratch)
                    };
                    d == e.md5
                };
                aligned_ok.push(ok);
                if ok {
                    report.found.push(FoundBlock {
                        offset: p,
                        block: e.block,
                    });
                    report.aligned_hits += 1;
                } else {
                    all = false;
                }
                p += ss;
                progress(p.min(file_len));
            }
            report.bytes_scanned = file_len;
            if all && !report.cancelled {
                report.file_hashes = win.finish_hash();
                return Ok(report);
            }
            // Partial: fall through to the general scan but keep the aligned finds; rescan
            // everything so blocks of other files / shifted blocks are discovered too.
            report.found.clear();
            report.aligned_hits = 0;
        }
    }
    // A verified aligned slice is reused only when its CRC is unique in the index: a shared
    // CRC may mean an identical slice of another file, which `confirm` must report too.
    let reuse_aligned = |pos: u64| -> Option<&ChecksumEntry> {
        let b = usize::try_from(pos / ss).ok()?;
        if !pos.is_multiple_of(ss) || !*aligned_ok.get(b)? {
            return None;
        }
        let e = &expected?[b];
        (index.lookup(e.crc32).count() == 1).then_some(e)
    };

    // ---- General scan ---------------------------------------------------------------------
    let wt = (!config.aligned_only).then(|| WindowTable::new(ss));
    while pos < file_len {
        if is_cancelled() {
            report.cancelled = true;
            break;
        }
        win.ensure(pos, ss)?;
        if let Some(e) = reuse_aligned(pos) {
            report.found.push(FoundBlock {
                offset: pos,
                block: e.block,
            });
            report.aligned_hits += 1;
            pos += ss;
            progress(pos.min(file_len));
            continue;
        }
        let mut raw = window_crc_raw(pos, &win);
        let aligned_here = pos.is_multiple_of(ss);
        let final_crc = raw ^ INIT;
        if index.might_contain(final_crc)
            && confirm(
                pos,
                final_crc,
                &win,
                &mut report,
                &mut scratch,
                aligned_here,
            )
        {
            pos += ss;
            progress(pos.min(file_len));
            continue;
        }
        let Some(wt) = &wt else {
            // Aligned-only mode: jump to the next slice boundary.
            pos += ss;
            progress(pos.min(file_len));
            continue;
        };
        // Slide byte by byte until the next confirmed match or EOF.
        let mut matched = false;
        while pos + 1 < file_len {
            let new_pos = pos + 1;
            let new_end = new_pos + ss;
            if new_end <= file_len {
                // Need bytes up to new_end resident.
                if new_end > win.base + win.len as u64 {
                    win.ensure(pos, ss + 1)?;
                    if is_cancelled() {
                        report.cancelled = true;
                        break;
                    }
                }
            }
            let new_byte = if new_end <= file_len {
                win.byte(new_end - 1)
            } else {
                0
            };
            let old_byte = win.byte(pos);
            raw = wt.slide_raw(raw, new_byte, old_byte);
            pos = new_pos;
            report.slid_bytes += 1;
            let final_crc = raw ^ INIT;
            if index.might_contain(final_crc) {
                if pos.is_multiple_of(1024) {
                    progress(pos);
                }
                if confirm(
                    pos,
                    final_crc,
                    &win,
                    &mut report,
                    &mut scratch,
                    pos.is_multiple_of(ss),
                ) {
                    matched = true;
                    break;
                }
            }
        }
        if report.cancelled {
            break;
        }
        if matched {
            pos += ss;
        } else {
            pos = file_len;
        }
        progress(pos.min(file_len));
    }
    report.bytes_scanned = pos.min(file_len);
    if !report.cancelled {
        report.bytes_scanned = file_len;
    }
    report.file_hashes = win.finish_hash();
    Ok(report)
}

/// Scan a file on disk.
pub fn scan_file(
    path: &std::path::Path,
    index: &ChecksumIndex,
    expected: Option<&[ChecksumEntry]>,
    config: &ScanConfig,
    cancel: Option<&AtomicBool>,
    progress: &mut dyn FnMut(u64),
) -> io::Result<ScanReport> {
    let src = crate::packet::FileSource::open(path)?;
    scan_source(&src, index, expected, config, cancel, progress)
}

/// Build the checksum entries of one file from its slice checksums.
pub fn entries_for_file(
    file_index: u32,
    slices: &[crate::packet::SliceChecksum],
) -> Vec<ChecksumEntry> {
    slices
        .iter()
        .enumerate()
        .map(|(i, s)| ChecksumEntry {
            crc32: s.crc32,
            md5: s.md5,
            block: BlockRef {
                file_index,
                block_index: i as u32,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::slice_checksums;

    fn rnd(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 17) as u8
            })
            .collect()
    }

    fn entries(file_index: u32, data: &[u8], ss: usize) -> Vec<ChecksumEntry> {
        data.chunks(ss)
            .enumerate()
            .map(|(i, c)| {
                let mut p = c.to_vec();
                p.resize(ss, 0);
                let (crc32, md5) = slice_checksums(&p);
                ChecksumEntry {
                    crc32,
                    md5,
                    block: BlockRef {
                        file_index,
                        block_index: i as u32,
                    },
                }
            })
            .collect()
    }

    fn no_progress() -> impl FnMut(u64) {
        |_| {}
    }

    #[test]
    fn index_lookup_and_filter() {
        let mut es = entries(0, &rnd(10_000, 1), 1000);
        es.push(ChecksumEntry {
            crc32: es[3].crc32,
            md5: [9; 16],
            block: BlockRef {
                file_index: 1,
                block_index: 0,
            },
        });
        let idx = ChecksumIndex::new(1000, es.clone());
        assert_eq!(idx.len(), 11);
        assert!(!idx.is_empty());
        assert_eq!(idx.slice_size(), 1000);
        assert_eq!(idx.duplicate_crcs(), 1);
        assert_eq!(idx.entries().len(), 11);
        for e in &es {
            assert!(idx.might_contain(e.crc32));
            let hits: Vec<&ChecksumEntry> = idx.lookup(e.crc32).collect();
            assert!(hits.contains(&e));
        }
        assert_eq!(idx.lookup(es[3].crc32).count(), 2);
        assert_eq!(idx.lookup(es[0].crc32).count(), 1);
        // A CRC that is not indexed yields nothing (filter may say maybe).
        let absent = (0u32..)
            .find(|c| !es.iter().any(|e| e.crc32 == *c))
            .unwrap();
        assert_eq!(idx.lookup(absent).count(), 0);
        let empty = ChecksumIndex::new(4, vec![]);
        assert!(empty.is_empty());
        assert_eq!(empty.lookup(0).count(), 0);
    }

    #[test]
    fn intact_file_full_match_aligned() {
        let data = rnd(23_456, 2);
        let ss = 1000;
        let es = entries(0, &data, ss);
        let idx = ChecksumIndex::new(ss as u64, es.clone());
        let r = scan_source(
            &data,
            &idx,
            Some(&es),
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert_eq!(r.found.len(), 24);
        assert!(r.is_full_match(&es, ss as u64));
        assert_eq!(r.aligned_hits, 24);
        assert_eq!(r.sliding_hits, 0);
        assert_eq!(r.slid_bytes, 0);
        assert_eq!(r.bytes_scanned, data.len() as u64);
        let fh = r.file_hashes.unwrap();
        assert_eq!(fh.md5_full, crate::hasher::md5(&data));
        assert_eq!(fh.crc32, crate::crc::crc32(&data));
        assert_eq!(fh.md5_16k, crate::hasher::md5_16k(&data));
        // Without expectations the general aligned probe finds the same.
        let r2 = scan_source(
            &data,
            &idx,
            None,
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert!(r2.is_full_match(&es, ss as u64));
        assert_eq!(r2.slid_bytes, 0);
        // Aligned-only mode too.
        let r3 = scan_source(
            &data,
            &idx,
            None,
            &ScanConfig {
                aligned_only: true,
                ..Default::default()
            },
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert!(r3.is_full_match(&es, ss as u64));
    }

    #[test]
    fn exact_multiple_length_and_tiny_files() {
        let ss = 512usize;
        let data = rnd(4 * ss, 3);
        let es = entries(0, &data, ss);
        let idx = ChecksumIndex::new(ss as u64, es.clone());
        let r = scan_source(
            &data,
            &idx,
            Some(&es),
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert!(r.is_full_match(&es, ss as u64));
        // One-byte file.
        let tiny = vec![7u8];
        let et = entries(1, &tiny, ss);
        let idx = ChecksumIndex::new(ss as u64, et.clone());
        let r = scan_source(
            &tiny,
            &idx,
            Some(&et),
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert!(r.is_full_match(&et, ss as u64));
        // Empty file: nothing to find, hashes of empty.
        let empty: Vec<u8> = vec![];
        let r = scan_source(
            &empty,
            &idx,
            None,
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert!(r.found.is_empty());
        assert_eq!(r.file_hashes.unwrap().len, 0);
    }

    #[test]
    fn damaged_middle_block_found_with_aligned_probe() {
        let ss = 1000usize;
        let data = rnd(10 * ss, 4);
        let es = entries(0, &data, ss);
        let idx = ChecksumIndex::new(ss as u64, es.clone());
        let mut damaged = data.clone();
        damaged[3 * ss + 10] ^= 0xFF;
        let mut last = 0;
        let r = scan_source(
            &damaged,
            &idx,
            Some(&es),
            &ScanConfig::default(),
            None,
            &mut |p| last = p,
        )
        .unwrap();
        assert_eq!(last, damaged.len() as u64);
        assert_eq!(r.found.len(), 9);
        assert!(!r.is_full_match(&es, ss as u64));
        assert!(r.found.iter().all(|f| f.block.block_index != 3));
        assert!(
            r.found
                .iter()
                .all(|f| f.offset == f.block.block_index as u64 * ss as u64)
        );
        // The damaged block made the scanner slide across it (1000 bytes) before re-aligning.
        assert_eq!(r.slid_bytes, ss as u64);
        assert_eq!(r.sliding_hits, 0);
    }

    #[test]
    fn inserted_and_deleted_bytes_are_handled_by_sliding() {
        let ss = 1000usize;
        let data = rnd(8 * ss + 345, 5);
        let es = entries(0, &data, ss);
        let idx = ChecksumIndex::new(ss as u64, es.clone());

        // Insert 17 garbage bytes after block 2 → blocks 3.. are shifted by 17.
        let mut shifted = data[..3 * ss].to_vec();
        shifted.extend_from_slice(&[0xAB; 17]);
        shifted.extend_from_slice(&data[3 * ss..]);
        let r = scan_source(
            &shifted,
            &idx,
            Some(&es),
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert_eq!(r.found.len(), 9, "{r:?}");
        for f in &r.found {
            let expect = if f.block.block_index < 3 {
                f.block.block_index as u64 * ss as u64
            } else {
                f.block.block_index as u64 * ss as u64 + 17
            };
            assert_eq!(f.offset, expect, "block {}", f.block.block_index);
        }
        assert!(r.sliding_hits >= 1);
        assert!(r.slid_bytes >= 17);
        // Last (padded) block found at an unaligned offset with virtual zero padding.
        assert!(
            r.found
                .iter()
                .any(|f| f.block.block_index == 8 && f.offset == 8 * ss as u64 + 17)
        );

        // Delete 100 bytes from block 1 → block 1 lost, others shifted back by 100.
        let mut cut = data.clone();
        cut.drain(ss + 200..ss + 300);
        let r = scan_source(
            &cut,
            &idx,
            Some(&es),
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert_eq!(r.found.len(), 8);
        assert!(r.found.iter().all(|f| f.block.block_index != 1));
        for f in &r.found {
            let expect = if f.block.block_index == 0 {
                0
            } else {
                f.block.block_index as u64 * ss as u64 - 100
            };
            assert_eq!(f.offset, expect);
        }

        // Aligned-only mode misses shifted blocks.
        let r = scan_source(
            &shifted,
            &idx,
            None,
            &ScanConfig {
                aligned_only: true,
                ..Default::default()
            },
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert_eq!(r.found.len(), 3);
    }

    #[test]
    fn split_fragments_and_concatenations() {
        let ss = 700usize;
        let a = rnd(5 * ss + 100, 6);
        let b = rnd(3 * ss, 7);
        let mut es = entries(0, &a, ss);
        es.extend(entries(1, &b, ss));
        let idx = ChecksumIndex::new(ss as u64, es.clone());

        // A split into two fragments at an arbitrary point: fragment 2 holds blocks 3..5 unaligned.
        let frag2 = &a[2 * ss + 123..];
        let r = scan_source(
            &frag2.to_vec(),
            &idx,
            None,
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        let idxs: Vec<u32> = r.found.iter().map(|f| f.block.block_index).collect();
        assert_eq!(idxs, vec![3, 4, 5]);
        assert_eq!(r.found[0].offset, (ss - 123) as u64);

        // Concatenation b ‖ a: all blocks of both files are found.
        let mut cat = b.clone();
        cat.extend_from_slice(&a);
        let r = scan_source(
            &cat,
            &idx,
            None,
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert_eq!(r.found.len(), 3 + 6);
        let b_found: Vec<_> = r.found.iter().filter(|f| f.block.file_index == 1).collect();
        assert_eq!(b_found.len(), 3);
        assert!(
            r.found
                .iter()
                .filter(|f| f.block.file_index == 0)
                .all(|f| f.offset == 3 * ss as u64 + f.block.block_index as u64 * ss as u64)
        );
    }

    #[test]
    fn identical_blocks_are_all_reported_and_crc_collisions_rejected_by_md5() {
        let ss = 512usize;
        let zeros = vec![0u8; 3 * ss];
        let mut es = entries(0, &zeros, ss); // three identical blocks
        let other = rnd(2 * ss, 8);
        es.extend(entries(1, &other, ss));
        // Fake collision: same CRC as other block 0 but a different MD5.
        es.push(ChecksumEntry {
            crc32: es[3].crc32,
            md5: [0xEE; 16],
            block: BlockRef {
                file_index: 2,
                block_index: 0,
            },
        });
        let idx = ChecksumIndex::new(ss as u64, es.clone());
        let r = scan_source(
            &zeros[..ss].to_vec(),
            &idx,
            None,
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert_eq!(r.found.len(), 3);
        assert!(r.found.iter().all(|f| f.offset == 0));
        let r = scan_source(
            &other,
            &idx,
            None,
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert_eq!(r.found.len(), 2);
        assert_eq!(r.md5_misses, 1);
        assert!(r.crc_hits >= 3);
    }

    #[test]
    fn large_file_with_small_buffer_crosses_refills() {
        let ss = 4096usize;
        let data = rnd(40 * ss + 999, 9);
        let es = entries(0, &data, ss);
        let idx = ChecksumIndex::new(ss as u64, es.clone());
        let cfg = ScanConfig {
            buffer_size: 1,
            ..Default::default()
        }; // forced to minimum
        // Shift everything by 5 bytes so the sliding path has to cross many refills.
        let mut shifted = vec![1u8, 2, 3, 4, 5];
        shifted.extend_from_slice(&data);
        let r = scan_source(&shifted, &idx, Some(&es), &cfg, None, &mut no_progress()).unwrap();
        assert_eq!(r.found.len(), 41, "{}", r.found.len());
        assert!(
            r.found
                .iter()
                .all(|f| f.offset == f.block.block_index as u64 * ss as u64 + 5)
        );
        assert_eq!(
            r.file_hashes.unwrap().md5_full,
            crate::hasher::md5(&shifted)
        );
    }

    #[test]
    fn cancellation_stops_early_and_still_hashes() {
        let ss = 1000usize;
        let data = rnd(50 * ss, 10);
        let es = entries(0, &data, ss);
        let idx = ChecksumIndex::new(ss as u64, es.clone());
        let cancel = AtomicBool::new(false);
        let mut calls = 0;
        let r = scan_source(
            &data,
            &idx,
            None,
            &ScanConfig::default(),
            Some(&cancel),
            &mut |_| {
                calls += 1;
                if calls == 5 {
                    cancel.store(true, Ordering::Relaxed);
                }
            },
        )
        .unwrap();
        assert!(r.cancelled);
        assert!(r.found.len() < 50);
        assert!(r.bytes_scanned < data.len() as u64);
        assert_eq!(r.file_hashes.unwrap().md5_full, crate::hasher::md5(&data));
        // Cancelled aligned fast path.
        let cancel = AtomicBool::new(true);
        let r = scan_source(
            &data,
            &idx,
            Some(&es),
            &ScanConfig::default(),
            Some(&cancel),
            &mut no_progress(),
        )
        .unwrap();
        assert!(r.cancelled);
    }

    #[test]
    fn scan_file_on_disk_and_entries_helper() {
        let ss = 300usize;
        let data = rnd(10 * ss + 7, 11);
        let slices: Vec<crate::packet::SliceChecksum> = data
            .chunks(ss)
            .map(|c| {
                let mut p = c.to_vec();
                p.resize(ss, 0);
                let (crc32, md5) = slice_checksums(&p);
                crate::packet::SliceChecksum { md5, crc32 }
            })
            .collect();
        let es = entries_for_file(4, &slices);
        assert_eq!(es.len(), 11);
        assert_eq!(
            es[10].block,
            BlockRef {
                file_index: 4,
                block_index: 10
            }
        );
        let idx = ChecksumIndex::new(ss as u64, es.clone());
        let dir = std::env::temp_dir().join(format!("par-rs-scan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.bin");
        std::fs::write(&p, &data).unwrap();
        let r = scan_file(
            &p,
            &idx,
            Some(&es),
            &ScanConfig::default(),
            None,
            &mut no_progress(),
        )
        .unwrap();
        assert!(r.is_full_match(&es, ss as u64));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            scan_file(
                &p,
                &idx,
                None,
                &ScanConfig::default(),
                None,
                &mut no_progress()
            )
            .is_err()
        );
    }
}
