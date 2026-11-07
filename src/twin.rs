//! Recovery-set fingerprinting and twin / near-twin / alternative set classification.
//!
//! When several NZBs describe the same release, their PAR2 sets may be *twins* (identical
//! files and names), *near twins* (same file contents under different names — usable for
//! renaming and for borrowing recovery blocks) or *unrelated* (different contents). The
//! fingerprint is a 64-bit FNV-1a hash over the sorted, de-duplicated `"<md5>:<length>\n"`
//! lines of the file descriptions, formatted as `"{hash:016x}-{count}"`.

use crate::packet::{load_par2_bytes, FileDescPacket, PacketSet, ScanOptions};
use std::collections::BTreeSet;

/// Identity of one described file.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileSig {
    /// Raw PAR2 file name bytes.
    pub name: Vec<u8>,
    /// MD5 of the whole file.
    pub md5: [u8; 16],
    /// File length.
    pub length: u64,
}

impl FileSig {
    /// From a parsed file description.
    pub fn from_desc(fd: &FileDescPacket) -> Self {
        Self { name: fd.name.clone(), md5: fd.hash_full, length: fd.file_length }
    }

    /// Local (sanitised) name.
    pub fn local_name(&self) -> String {
        crate::packet::translate_filename_from_par2_to_local(&self.name)
    }
}

/// Signatures of all described files in a parsed set, in `libpar2` order.
pub fn sigs_of_set(set: &PacketSet) -> Vec<FileSig> {
    set.file_descs.values().map(FileSig::from_desc).collect()
}

/// Extract file signatures from in-memory PAR2 data.
///
/// Returns the signatures and whether a valid Main packet was found (i.e. the data is a
/// complete, usable set description rather than just surviving `FileDesc` packets).
pub fn par2_set(data: &[u8]) -> (Vec<FileSig>, bool) {
    match load_par2_bytes(data, ScanOptions::METADATA) {
        Ok(set) => {
            let has_main = set.main.is_some();
            (sigs_of_set(&set), has_main)
        }
        Err(_) => (Vec::new(), false),
    }
}

/// Slice (block) size announced by the Main packet of in-memory PAR2 data.
///
/// If no Main packet survived, the size is estimated from `FileDesc`/`IFSC` pairs: the
/// smallest multiple of 4 consistent with every file's length and slice count. Returns `0`
/// when nothing usable is present or the estimate is contradictory.
pub fn block_size(data: &[u8]) -> u64 {
    let Ok(set) = load_par2_bytes(data, ScanOptions::METADATA) else {
        return 0;
    };
    block_size_of_set(&set)
}

/// Same as [`block_size`] for an already parsed set.
pub fn block_size_of_set(set: &PacketSet) -> u64 {
    if let Some(ss) = set.slice_size() {
        return ss;
    }
    let mut lower: u64 = 4; // slice size must be > (len-1)/n ... and a multiple of 4
    let mut upper: u64 = u64::MAX;
    let mut any = false;
    for (id, fd) in &set.file_descs {
        let Some(ifsc) = set.ifscs.get(id) else {
            continue;
        };
        let n = ifsc.slices.len() as u64;
        if n == 0 || fd.file_length == 0 {
            continue;
        }
        any = true;
        // (n-1) * s < len <= n * s  ⇔  len / n <= s < len / (n-1)
        let min_s = fd.file_length.div_ceil(n);
        lower = lower.max(min_s.div_ceil(4) * 4);
        if n > 1 {
            // s <= (len - 1) / (n - 1)
            upper = upper.min((fd.file_length - 1) / (n - 1));
        }
    }
    if !any || lower > upper {
        return 0;
    }
    lower
}

/// FNV-1a 64-bit fingerprint of a set of signatures: `"{hash:016x}-{count}"`, or `""` for an
/// empty set. Lines are `"<md5_lower_hex>:<length>\n"`, sorted and de-duplicated.
pub fn fingerprint(sigs: &[FileSig]) -> String {
    let lines: BTreeSet<String> = sigs.iter().map(|s| format!("{}:{}\n", crate::packet::hex(&s.md5), s.length)).collect();
    if lines.is_empty() {
        return String::new();
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for line in &lines {
        for &b in line.as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{h:016x}-{}", lines.len())
}

/// Relationship between two PAR2 sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum TwinRelation {
    /// Same fingerprint and identical `(name, md5)` pairs: an exact twin.
    Twin = 0,
    /// Different fingerprint: describes other files.
    DescribesOtherFiles = 1,
    /// Same fingerprint but at least one file is named differently.
    NamesFilesOtherwise = 2,
}

impl TwinRelation {
    /// Numeric code (`0`, `1`, `2`) as used by the nzbget-rs call sites.
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// Compare our own set (names, MD5s and precomputed fingerprint) with candidate twin data.
///
/// `own_names[i]` and `own_md5s[i]` describe the same file. Returns
/// [`TwinRelation::Twin`] (0), [`TwinRelation::DescribesOtherFiles`] (1) or
/// [`TwinRelation::NamesFilesOtherwise`] (2).
pub fn compare_twin_par2_data(own_names: &[&[u8]], own_md5s: &[[u8; 16]], own_print: &str, twin_data: &[u8]) -> TwinRelation {
    let (twin_sigs, _) = par2_set(twin_data);
    let twin_print = fingerprint(&twin_sigs);
    if twin_print != own_print {
        return TwinRelation::DescribesOtherFiles;
    }
    let own: BTreeSet<(&[u8], [u8; 16])> = own_names.iter().copied().zip(own_md5s.iter().copied()).collect();
    let twin: BTreeSet<(&[u8], [u8; 16])> = twin_sigs.iter().map(|s| (s.name.as_slice(), s.md5)).collect();
    if own == twin {
        TwinRelation::Twin
    } else {
        TwinRelation::NamesFilesOtherwise
    }
}

/// Convenience over [`compare_twin_par2_data`] taking our own signatures.
pub fn compare_twin_sets(own: &[FileSig], twin_data: &[u8]) -> TwinRelation {
    let names: Vec<&[u8]> = own.iter().map(|s| s.name.as_slice()).collect();
    let md5s: Vec<[u8; 16]> = own.iter().map(|s| s.md5).collect();
    compare_twin_par2_data(&names, &md5s, &fingerprint(own), twin_data)
}

/// Map from a twin's names to our names for files with identical content (for renaming
/// obfuscated downloads using an alternative set). Only unambiguous MD5 matches are returned.
pub fn name_mapping(own: &[FileSig], twin: &[FileSig]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut by_md5: std::collections::BTreeMap<[u8; 16], Vec<&FileSig>> = Default::default();
    for s in own {
        by_md5.entry(s.md5).or_default().push(s);
    }
    let mut out = Vec::new();
    for t in twin {
        if let Some(cands) = by_md5.get(&t.md5)
            && cands.len() == 1 && cands[0].length == t.length && cands[0].name != t.name {
                out.push((t.name.clone(), cands[0].name.clone()));
            }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::build_test_set;

    fn data() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (b"one.bin".to_vec(), (0..3000u32).map(|i| (i * 3) as u8).collect()),
            (b"two.bin".to_vec(), (0..700u32).map(|i| (i * 11) as u8).collect()),
        ]
    }

    fn refs(f: &[(Vec<u8>, Vec<u8>)]) -> Vec<(&[u8], &[u8])> {
        f.iter().map(|(n, d)| (n.as_slice(), d.as_slice())).collect()
    }

    #[test]
    fn set_extraction_and_block_size() {
        let f = data();
        let (bytes, _) = build_test_set(&refs(&f), 1024, &[0]);
        let (sigs, has_main) = par2_set(&bytes);
        assert!(has_main);
        assert_eq!(sigs.len(), 2);
        assert_eq!(block_size(&bytes), 1024);
        let one = sigs.iter().find(|s| s.name == b"one.bin").unwrap();
        assert_eq!(one.length, 3000);
        assert_eq!(one.md5, crate::hasher::md5(&f[0].1));
        assert_eq!(one.local_name(), "one.bin");

        // Main packet shifted by a 4-byte prefix is still found.
        let mut shifted = vec![0u8; 4];
        shifted.extend_from_slice(&bytes);
        assert_eq!(block_size(&shifted), 1024);
        assert!(par2_set(&shifted).1);

        // Garbage: nothing.
        assert_eq!(par2_set(b"garbage").0.len(), 0);
        assert_eq!(block_size(b"garbage"), 0);
        assert_eq!(block_size(&[]), 0);
    }

    #[test]
    fn block_size_estimate_without_main() {
        let f = data();
        let (bytes, _) = build_test_set(&refs(&f), 1024, &[]);
        // Remove the Main packet (first packet).
        let raws: Vec<_> = crate::packet::PacketIter::new(&bytes[..], ScanOptions::UNVERIFIED).map(|r| r.unwrap()).collect();
        let main_len = raws[0].header.length as usize;
        let no_main = &bytes[main_len..];
        let (sigs, has_main) = par2_set(no_main);
        assert!(!has_main);
        assert_eq!(sigs.len(), 2);
        // one.bin: 3000 bytes in 3 slices → 1000 <= s <= 1499; two.bin: 700 in 1 slice → s >= 700.
        // Smallest multiple of 4 ≥ 1000 is 1000.
        assert_eq!(block_size(no_main), 1000);

        // Contradictory data yields 0.
        let mut set = load_par2_bytes(no_main, ScanOptions::METADATA).unwrap();
        for ifsc in set.ifscs.values_mut() {
            if ifsc.slices.len() == 1 {
                // Pretend two.bin (700 bytes) needs 5 slices → s in [140, 174], contradicts 1000.
                let s = ifsc.slices[0];
                ifsc.slices = vec![s; 5];
            }
        }
        assert_eq!(block_size_of_set(&set), 0);
        // Only FileDesc without IFSC → 0.
        set.ifscs.clear();
        assert_eq!(block_size_of_set(&set), 0);
    }

    #[test]
    fn fingerprint_is_order_independent_and_dedups() {
        let a = FileSig { name: b"a".to_vec(), md5: [1; 16], length: 10 };
        let b = FileSig { name: b"b".to_vec(), md5: [2; 16], length: 20 };
        let a2 = FileSig { name: b"renamed".to_vec(), md5: [1; 16], length: 10 };
        let p1 = fingerprint(&[a.clone(), b.clone()]);
        let p2 = fingerprint(&[b.clone(), a.clone()]);
        let p3 = fingerprint(&[a.clone(), b.clone(), a2.clone()]);
        assert_eq!(p1, p2);
        assert_eq!(p1, p3);
        assert!(p1.ends_with("-2"));
        assert_eq!(p1.len(), 16 + 2);
        assert_ne!(p1, fingerprint(std::slice::from_ref(&a)));
        assert_eq!(fingerprint(&[]), "");
        // Known FNV-1a value for a single line.
        let single = fingerprint(&[FileSig { name: vec![], md5: [0; 16], length: 0 }]);
        let line = format!("{}:0\n", "00".repeat(16));
        let mut h: u64 = 0xcbf29ce484222325;
        for b in line.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        assert_eq!(single, format!("{h:016x}-1"));
    }

    #[test]
    fn twin_classification() {
        let f = data();
        let (own_bytes, _) = build_test_set(&refs(&f), 1024, &[0]);
        let (own, _) = par2_set(&own_bytes);
        let own_print = fingerprint(&own);
        let names: Vec<&[u8]> = own.iter().map(|s| s.name.as_slice()).collect();
        let md5s: Vec<[u8; 16]> = own.iter().map(|s| s.md5).collect();

        // Exact twin (different slice size / recovery does not matter).
        let (twin_bytes, _) = build_test_set(&refs(&f), 512, &[1, 2]);
        assert_eq!(compare_twin_par2_data(&names, &md5s, &own_print, &twin_bytes), TwinRelation::Twin);
        assert_eq!(compare_twin_sets(&own, &twin_bytes), TwinRelation::Twin);
        assert_eq!(TwinRelation::Twin.code(), 0);

        // Same content, different names.
        let renamed: Vec<(Vec<u8>, Vec<u8>)> = f.iter().map(|(n, d)| ([b"x_".as_slice(), n].concat(), d.clone())).collect();
        let (alt_bytes, _) = build_test_set(&refs(&renamed), 1024, &[]);
        assert_eq!(compare_twin_par2_data(&names, &md5s, &own_print, &alt_bytes), TwinRelation::NamesFilesOtherwise);
        assert_eq!(TwinRelation::NamesFilesOtherwise.code(), 2);
        let (alt_sigs, _) = par2_set(&alt_bytes);
        let mapping = name_mapping(&own, &alt_sigs);
        assert_eq!(mapping.len(), 2);
        assert!(mapping.contains(&(b"x_one.bin".to_vec(), b"one.bin".to_vec())));

        // Different content.
        let mut other = f.clone();
        other[0].1[0] ^= 1;
        let (other_bytes, _) = build_test_set(&refs(&other), 1024, &[]);
        assert_eq!(compare_twin_par2_data(&names, &md5s, &own_print, &other_bytes), TwinRelation::DescribesOtherFiles);
        assert_eq!(TwinRelation::DescribesOtherFiles.code(), 1);
        assert_eq!(compare_twin_par2_data(&names, &md5s, &own_print, b"junk"), TwinRelation::DescribesOtherFiles);

        // Mapping ignores ambiguous MD5s and identical names.
        let dup = vec![own[0].clone(), FileSig { name: b"dup".to_vec(), ..own[0].clone() }];
        assert!(name_mapping(&dup, &alt_sigs).iter().all(|(_, to)| to != &own[0].name));
        assert!(name_mapping(&own, &own).is_empty());
    }
}
