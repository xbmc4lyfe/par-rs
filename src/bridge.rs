//! Obfuscated-file resolution: which downloaded (randomly named) file is which PAR2 input file.
//!
//! Usenet posts frequently carry obfuscated subjects and file names; the par2 set still knows
//! every real name, size, MD5 and (via IFSC) CRC-32. [`Par2Bridge`] maps candidates to files
//! in four passes, each only applied where the previous one left ambiguity:
//!
//! 1. **size chain**—a size that occurs exactly once on both sides is a match;
//! 2. **16 KiB MD5**—ties by size are broken with the MD5 of the candidate's first 16 KiB
//!    (available from article 1 alone);
//! 3. **CRC-32**—the candidate's whole-file CRC (folded from its yEnc part CRCs, see
//!    [`crate::gf2::fold_yenc_parts`]) against the IFSC-folded CRC of each file;
//! 4. **RAR5 volume number**—for same-size `.partNN.rar` volumes, the volume number stored in
//!    the RAR5 main archive header of the candidate's first bytes picks the part.

use crate::par2::{Inventory, Par2File};
use std::collections::HashMap;

/// A downloaded (possibly obfuscated) file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Candidate {
    /// Current (obfuscated) name; informational.
    pub name: String,
    /// Size on disk / from the NZB.
    pub size: u64,
    /// MD5 of the first `min(size, 16384)` bytes, if known.
    pub md5_16k: Option<[u8; 16]>,
    /// Whole-file CRC-32, if known (folded yEnc part CRCs).
    pub crc32: Option<u32>,
    /// Leading bytes of the file (a RAR5 signature + main header is under 64 bytes), if known.
    pub head: Option<Vec<u8>>,
}

/// Which pass resolved a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveMethod {
    /// Unique size on both sides.
    SizeChain,
    /// 16 KiB MD5 tie-breaker.
    Md5_16k,
    /// Folded whole-file CRC-32 vs IFSC CRC-32.
    Crc32,
    /// RAR5 main header volume number.
    Rar5Volume,
}

/// A resolved candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    /// Index into the candidate list.
    pub candidate: usize,
    /// Index into the bridge's file list.
    pub file: usize,
    /// How it was resolved.
    pub method: ResolveMethod,
}

/// Outcome of [`Par2Bridge::resolve`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BridgeReport {
    /// Resolved candidates, in candidate order.
    pub resolved: Vec<Resolution>,
    /// Candidates that matched no file.
    pub unresolved_candidates: Vec<usize>,
    /// Files no candidate matched.
    pub unmatched_files: Vec<usize>,
}

/// Resolver over the files of a par2 set.
#[derive(Clone, Debug)]
pub struct Par2Bridge {
    files: Vec<Par2File>,
}

impl Par2Bridge {
    /// Resolver for every file in `inventory`.
    pub fn new(inventory: &Inventory) -> Self {
        Self {
            files: inventory.files.clone(),
        }
    }

    /// Resolver for an explicit file list.
    pub fn from_files(files: Vec<Par2File>) -> Self {
        Self { files }
    }

    /// The files being resolved against.
    pub fn files(&self) -> &[Par2File] {
        &self.files
    }

    /// Resolve candidates to files.
    pub fn resolve(&self, candidates: &[Candidate]) -> BridgeReport {
        let mut file_taken = vec![false; self.files.len()];
        let mut cand_done: Vec<Option<Resolution>> = vec![None; candidates.len()];

        let mut by_size_files: HashMap<u64, Vec<usize>> = HashMap::new();
        for (i, f) in self.files.iter().enumerate() {
            by_size_files.entry(f.size).or_default().push(i);
        }
        let mut by_size_cands: HashMap<u64, Vec<usize>> = HashMap::new();
        for (i, c) in candidates.iter().enumerate() {
            by_size_cands.entry(c.size).or_default().push(i);
        }

        // Pass 1: unique sizes.
        for (size, cands) in &by_size_cands {
            if let ([c], Some([f])) = (cands.as_slice(), by_size_files.get(size).map(Vec::as_slice))
                && let (Some(slot), Some(taken)) = (cand_done.get_mut(*c), file_taken.get_mut(*f))
            {
                *slot = Some(Resolution {
                    candidate: *c,
                    file: *f,
                    method: ResolveMethod::SizeChain,
                });
                *taken = true;
            }
        }

        // Passes 2-4 per size group with ties.
        for (size, cands) in &by_size_cands {
            let Some(files) = by_size_files.get(size) else {
                continue;
            };
            // Pass 2: 16 KiB MD5.
            for &c in cands {
                if cand_done.get(c).is_some_and(Option::is_some) {
                    continue;
                }
                let Some(md5) = candidates.get(c).and_then(|x| x.md5_16k) else {
                    continue;
                };
                let hits: Vec<usize> = files
                    .iter()
                    .copied()
                    .filter(|&f| {
                        !file_taken.get(f).copied().unwrap_or(true)
                            && self.files.get(f).is_some_and(|pf| pf.md5_16k == md5)
                    })
                    .collect();
                if let [f] = hits.as_slice() {
                    Self::bind(
                        &mut cand_done,
                        &mut file_taken,
                        c,
                        *f,
                        ResolveMethod::Md5_16k,
                    );
                }
            }
            // Pass 3: folded CRC-32.
            for &c in cands {
                if cand_done.get(c).is_some_and(Option::is_some) {
                    continue;
                }
                let Some(crc) = candidates.get(c).and_then(|x| x.crc32) else {
                    continue;
                };
                let hits: Vec<usize> = files
                    .iter()
                    .copied()
                    .filter(|&f| {
                        !file_taken.get(f).copied().unwrap_or(true)
                            && self.files.get(f).is_some_and(|pf| pf.crc32 == Some(crc))
                    })
                    .collect();
                if let [f] = hits.as_slice() {
                    Self::bind(&mut cand_done, &mut file_taken, c, *f, ResolveMethod::Crc32);
                }
            }
            // Pass 4: `RAR5` volume numbers among the remaining same-size files.
            let remaining_files: Vec<(usize, u64)> = files
                .iter()
                .copied()
                .filter(|&f| !file_taken.get(f).copied().unwrap_or(true))
                .filter_map(|f| rar_part_number(&self.files.get(f)?.name).map(|p| (f, p)))
                .collect();
            if remaining_files.is_empty() {
                continue;
            }
            let first_part = remaining_files.iter().map(|&(_, p)| p).min().unwrap_or(0);
            for &c in cands {
                if cand_done.get(c).is_some_and(Option::is_some) {
                    continue;
                }
                let Some(vol) = candidates
                    .get(c)
                    .and_then(|x| x.head.as_deref())
                    .and_then(rar5_volume_number)
                else {
                    continue;
                };
                let want = first_part.saturating_add(vol);
                let hits: Vec<usize> = remaining_files
                    .iter()
                    .filter(|&&(f, p)| p == want && !file_taken.get(f).copied().unwrap_or(true))
                    .map(|&(f, _)| f)
                    .collect();
                if let [f] = hits.as_slice() {
                    Self::bind(
                        &mut cand_done,
                        &mut file_taken,
                        c,
                        *f,
                        ResolveMethod::Rar5Volume,
                    );
                }
            }
        }

        let mut report = BridgeReport::default();
        for (c, r) in cand_done.into_iter().enumerate() {
            match r {
                Some(r) => report.resolved.push(r),
                None => report.unresolved_candidates.push(c),
            }
        }
        report.unmatched_files = file_taken
            .iter()
            .enumerate()
            .filter(|(_, t)| !**t)
            .map(|(f, _)| f)
            .collect();
        report
    }

    fn bind(
        cand_done: &mut [Option<Resolution>],
        file_taken: &mut [bool],
        c: usize,
        f: usize,
        method: ResolveMethod,
    ) {
        if let (Some(slot), Some(taken)) = (cand_done.get_mut(c), file_taken.get_mut(f)) {
            *slot = Some(Resolution {
                candidate: c,
                file: f,
                method,
            });
            *taken = true;
        }
    }
}

/// Part number of a RAR volume name: `name.partNN.rar` → `NN`, `name.rNN` → `NN + 1`,
/// `name.rar` (old-style first volume) → `0`. `None` for non-RAR names.
pub fn rar_part_number(name: &str) -> Option<u64> {
    let lower = name.to_ascii_lowercase();
    if let Some(stem) = lower.strip_suffix(".rar") {
        if let Some(p) = stem.rfind(".part") {
            let digits = stem.get(p.saturating_add(5)..)?;
            return if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                digits.parse().ok()
            } else {
                None
            };
        }
        return Some(0);
    }
    // Names such as `name.r00` and `name.r01`.
    let (_, ext) = lower.rsplit_once('.')?;
    let digits = ext.strip_prefix('r')?;
    if digits.len() == 2 && digits.bytes().all(|b| b.is_ascii_digit()) {
        return digits.parse::<u64>().ok()?.checked_add(1);
    }
    None
}

/// RAR5 signature.
pub const RAR5_SIGNATURE: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

/// Read a RAR5 variable-length integer at `off`: `(value, bytes consumed)`.
pub fn rar5_vint(data: &[u8], off: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for i in 0..10usize {
        let b = *data.get(off.checked_add(i)?)?;
        value |= u64::from(b & 0x7F).checked_shl((7 * i) as u32)?;
        if b & 0x80 == 0 {
            return Some((value, i.saturating_add(1)));
        }
    }
    None
}

/// Volume number from the RAR5 main archive header at the start of `head`: `0` for the first
/// volume (the header carries no number), `n` for `.part(n+1)`. `None` if `head` is not a
/// RAR5 archive or the header is incomplete.
pub fn rar5_volume_number(head: &[u8]) -> Option<u64> {
    if head.get(..8)? != RAR5_SIGNATURE {
        return None;
    }
    // Header: `CRC32(4)`, header size(vint), type(vint), flags(vint), [extra size], [data size], archive flags(vint), [volume number].
    let mut off = 12usize;
    let (header_size, n) = rar5_vint(head, off)?;
    off = off.checked_add(n)?;
    let header_end = off.checked_add(usize::try_from(header_size).ok()?)?;
    let (htype, n) = rar5_vint(head, off)?;
    off = off.checked_add(n)?;
    if htype != 1 {
        return None; // not a main archive header
    }
    let (flags, n) = rar5_vint(head, off)?;
    off = off.checked_add(n)?;
    if flags & 0x01 != 0 {
        let (_, n) = rar5_vint(head, off)?;
        off = off.checked_add(n)?;
    }
    if flags & 0x02 != 0 {
        let (_, n) = rar5_vint(head, off)?;
        off = off.checked_add(n)?;
    }
    let (archive_flags, n) = rar5_vint(head, off)?;
    off = off.checked_add(n)?;
    if off > header_end {
        return None;
    }
    if archive_flags & 0x02 != 0 {
        let (vol, _) = rar5_vint(head, off)?;
        Some(vol)
    } else {
        // Volume flag without a number: first volume. Not a volume at all: single archive = 0.
        Some(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, size: u64, tag: u8) -> Par2File {
        Par2File {
            set_id: [1; 16],
            file_id: [tag; 16],
            md5: [tag; 16],
            md5_16k: [tag.wrapping_add(100); 16],
            size,
            name: name.to_owned(),
            bound: true,
            crc32: Some(u32::from(tag) * 7),
        }
    }

    fn rar5_head(volume: Option<u64>) -> Vec<u8> {
        let mut h = RAR5_SIGNATURE.to_vec();
        h.extend_from_slice(&[0, 0, 0, 0]); // crc
        let mut body = vec![1u8, 0]; // type main, flags 0
        match volume {
            Some(v) => {
                body.push(0x03); // archive flags: volume + number present
                body.push(v as u8);
            }
            None => body.push(0x01),
        }
        h.push(body.len() as u8);
        h.extend_from_slice(&body);
        h
    }

    #[test]
    fn vint_and_rar5_header() {
        assert_eq!(rar5_vint(&[0x05], 0), Some((5, 1)));
        assert_eq!(rar5_vint(&[0x80 | 0x05, 0x01], 0), Some((0x85, 2)));
        assert_eq!(rar5_vint(&[0x80], 0), None);
        assert_eq!(rar5_vint(&[], 0), None);
        assert_eq!(rar5_volume_number(&rar5_head(Some(3))), Some(3));
        assert_eq!(rar5_volume_number(&rar5_head(None)), Some(0));
        assert_eq!(rar5_volume_number(b"Rar!\x1a\x07\x00garbage"), None);
        assert_eq!(rar5_volume_number(&rar5_head(Some(3))[..14]), None);
        assert_eq!(rar_part_number("x.part07.rar"), Some(7));
        assert_eq!(rar_part_number("x.rar"), Some(0));
        assert_eq!(rar_part_number("x.r00"), Some(1));
        assert_eq!(rar_part_number("x.r9"), None);
        assert_eq!(rar_part_number("x.partX.rar"), None);
        assert_eq!(rar_part_number("x.mkv"), None);
    }

    #[test]
    fn four_pass_resolution() {
        let files = vec![
            file("a.part01.rar", 1000, 1),
            file("a.part02.rar", 1000, 2),
            file("a.part03.rar", 1000, 3),
            file("a.part04.rar", 500, 4),
            file("readme.nfo", 77, 5),
            file("b.part01.rar", 2000, 6),
            file("b.part02.rar", 2000, 7),
        ];
        let bridge = Par2Bridge::from_files(files);
        let cands = vec![
            Candidate {
                name: "x1".into(),
                size: 500,
                ..Default::default()
            }, // size chain
            Candidate {
                name: "x2".into(),
                size: 1000,
                md5_16k: Some([102; 16]),
                ..Default::default()
            }, // md5 -> part02
            Candidate {
                name: "x3".into(),
                size: 1000,
                crc32: Some(21),
                ..Default::default()
            }, // crc -> part03
            Candidate {
                name: "x4".into(),
                size: 1000,
                head: Some(rar5_head(None)),
                ..Default::default()
            }, // rar5 vol 0 -> part01
            Candidate {
                name: "x5".into(),
                size: 2000,
                head: Some(rar5_head(Some(1))),
                ..Default::default()
            }, // rar5 vol 1 -> b.part02
            Candidate {
                name: "x6".into(),
                size: 2000,
                ..Default::default()
            }, // ambiguous -> unresolved
            Candidate {
                name: "x7".into(),
                size: 9,
                ..Default::default()
            }, // no such size
        ];
        let r = bridge.resolve(&cands);
        let by_cand: HashMap<usize, (usize, ResolveMethod)> = r
            .resolved
            .iter()
            .map(|x| (x.candidate, (x.file, x.method)))
            .collect();
        assert_eq!(by_cand[&0], (3, ResolveMethod::SizeChain));
        assert_eq!(by_cand[&1], (1, ResolveMethod::Md5_16k));
        assert_eq!(by_cand[&2], (2, ResolveMethod::Crc32));
        assert_eq!(by_cand[&3], (0, ResolveMethod::Rar5Volume));
        assert_eq!(by_cand[&4], (6, ResolveMethod::Rar5Volume));
        assert_eq!(r.unresolved_candidates, vec![5, 6]);
        assert_eq!(r.unmatched_files, vec![4, 5]);
        assert_eq!(bridge.files().len(), 7);
        let empty = Par2Bridge::new(&Inventory::default()).resolve(&cands);
        assert_eq!(empty.resolved, vec![]);
        assert_eq!(empty.unresolved_candidates.len(), 7);
    }
}
