//! Indexer-facing summary of a par2 buffer: which files a set describes, how big they are,
//! their hashes and (when the IFSC packets are present) their whole-file CRC-32, folded from
//! the slice checksums without reading the files.
//!
//! The types and functions keep the shape of the `atlas::par2` module they replace. Behaviour
//! guarantees:
//!
//! * resynchronising `PAR2\0PKT` scanning with `shaped` header checking (`len >= 64 && len % 4 == 0`);
//! * block sizes are isolated per `set_id`: a file's CRC is only folded with its own set's slice size;
//! * `UniFileN` packets replace the ASCII name; names are stripped of control / ANSI escape
//!   characters and path components;
//! * prefix safety: `inventory(&data[..cut])` never panics and is monotonic in `cut` — every
//!   file it reports is reported for every longer prefix.

use crate::bytes::{file_id_key, hex};
use crate::gf2::fold_ifsc_crcs;
use crate::inspect::{Par2Inspection, VerifyMode, inspect_par2_with};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

/// One input file of a recovery set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Par2File {
    /// Recovery set id.
    pub set_id: [u8; 16],
    /// File id (`MD5(md5_16k ‖ size ‖ name)`).
    pub file_id: [u8; 16],
    /// MD5 of the whole file.
    pub md5: [u8; 16],
    /// MD5 of the first 16 KiB.
    pub md5_16k: [u8; 16],
    /// File size.
    pub size: u64,
    /// Sanitised file name (Unicode name when present).
    pub name: String,
    /// Listed in its set's `Main` recovery set (i.e. covered by recovery data and bound to the
    /// set's block size).
    pub bound: bool,
    /// Whole-file CRC-32 folded from the IFSC slice checksums (needs the set's block size and
    /// a consistent IFSC packet).
    pub crc32: Option<u32>,
}

/// Summary of every set found in a buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Files, primary set first, ascending file id within a set (`libpar2` order: the id as a
    /// little-endian 128-bit integer).
    pub files: Vec<Par2File>,
    /// Block size of the primary set (the set of the first `Main` packet, else of the first
    /// `FileDesc`).
    pub block_size: Option<u64>,
    /// The primary set has a `Main` packet, every file of its recovery set has a `FileDesc`,
    /// and no packet was cut short.
    pub complete: bool,
    /// A packet claimed more bytes than the buffer holds.
    pub truncated: bool,
    /// `(set_id, file_id)` pairs with both a `FileDesc` and an IFSC packet whose slice count
    /// matches the file size at the set's block size: fully described, verifiable files.
    pub sealed: Vec<([u8; 16], [u8; 16])>,
}

fn base_par2_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // A token ending in `.par2`; volumes are rejected afterwards.
        #[allow(clippy::expect_used)] // literal pattern, verified by the unit tests
        regex::Regex::new(r#"(?i)([^"\s<>\[\]()]+)\.par2\b"#).expect("valid regex")
    })
}

/// Does a Usenet subject refer to the base `.par2` index file (not a `.volNNN+MM.par2`
/// volume)? Case-insensitive; quoted and unquoted names are recognised.
pub fn is_base_par2(subject: &str) -> bool {
    base_par2_regex().captures_iter(subject).any(|c| {
        let stem = c.get(1).map_or("", |m| m.as_str()).to_ascii_lowercase();
        match stem.rfind(".vol") {
            None => true,
            Some(p) => {
                let seg = stem.get(p.saturating_add(4)..).unwrap_or("");
                let is_volume = seg.split_once(['+', '-']).is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && a.bytes().all(|x| x.is_ascii_digit()) && b.bytes().all(|x| x.is_ascii_digit()));
                !is_volume
            }
        }
    })
}

/// Build the inventory of a par2 buffer. Metadata packets are MD5-verified (recovery data is
/// not hashed), so a corrupt description is never reported as a file.
pub fn inventory(data: &[u8]) -> Inventory {
    inventory_from(&inspect_par2_with(data, VerifyMode::Metadata))
}

/// Build the inventory from an existing inspection.
pub fn inventory_from(insp: &Par2Inspection) -> Inventory {
    let mut inv = Inventory { truncated: insp.truncated, ..Inventory::default() };
    // Per-set block size (first complete Main of each set wins) and recovery membership.
    let mut block_sizes: HashMap<[u8; 16], u64> = HashMap::new();
    let mut members: HashMap<[u8; 16], HashSet<[u8; 16]>> = HashMap::new();
    let mut set_order: Vec<[u8; 16]> = Vec::new();
    for m in &insp.main {
        if !set_order.contains(&m.set_id) {
            set_order.push(m.set_id);
        }
        block_sizes.entry(m.set_id).or_insert(m.slice_size);
        members.entry(m.set_id).or_default().extend(m.recovery_set.iter().copied());
    }
    for f in &insp.files {
        if !set_order.contains(&f.set_id) {
            set_order.push(f.set_id);
        }
    }
    let primary = set_order.first().copied();
    inv.block_size = primary.and_then(|s| block_sizes.get(&s).copied()).filter(|&b| b > 0);

    let unicode: HashMap<([u8; 16], [u8; 16]), &str> = insp.unicode_names.iter().map(|u| ((u.set_id, u.file_id), u.name.as_str())).collect();
    type IfscMap<'a> = HashMap<([u8; 16], [u8; 16]), &'a [([u8; 16], u32)]>;
    let ifsc: IfscMap<'_> = insp.ifsc.iter().map(|i| ((i.set_id, i.file_id), i.slices.as_slice())).collect();

    // Dedupe FileDesc by (set, file); keep the first occurrence.
    let mut by_set: BTreeMap<usize, BTreeMap<u128, Par2File>> = BTreeMap::new();
    for f in &insp.files {
        let Some(rank) = set_order.iter().position(|s| *s == f.set_id) else { continue };
        let entry = by_set.entry(rank).or_default();
        if entry.contains_key(&file_id_key(&f.file_id)) {
            continue;
        }
        let name = unicode.get(&(f.set_id, f.file_id)).map_or_else(|| f.name.clone(), |n| (*n).to_owned());
        let bound = members.get(&f.set_id).is_some_and(|m| m.contains(&f.file_id));
        let block = block_sizes.get(&f.set_id).copied().filter(|&b| b > 0);
        let mut crc32 = None;
        if let (Some(bs), Some(slices)) = (block, ifsc.get(&(f.set_id, f.file_id))) {
            let crcs: Vec<u32> = slices.iter().map(|(_, c)| *c).collect();
            crc32 = fold_ifsc_crcs(&crcs, bs, f.length);
            if crc32.is_some() {
                inv.sealed.push((f.set_id, f.file_id));
            }
        }
        entry.insert(file_id_key(&f.file_id), Par2File { set_id: f.set_id, file_id: f.file_id, md5: f.md5, md5_16k: f.md5_16k, size: f.length, name, bound, crc32 });
    }
    inv.files = by_set.into_values().flat_map(|m| m.into_values()).collect();
    inv.sealed.sort();
    inv.complete = match primary {
        Some(p) => {
            let has_main = block_sizes.contains_key(&p);
            let described: HashSet<[u8; 16]> = inv.files.iter().filter(|f| f.set_id == p).map(|f| f.file_id).collect();
            has_main && !insp.truncated && members.get(&p).is_some_and(|m| m.iter().all(|id| described.contains(id)))
        }
        None => false,
    };
    inv
}

/// `(name, size)` of every file in [`inventory`] order.
pub fn file_descriptions(data: &[u8]) -> Vec<(String, u64)> {
    inventory(data).files.into_iter().map(|f| (f.name, f.size)).collect()
}

/// A name for the set: the largest bound file of the primary set (ties broken by file id),
/// else the largest file of any set. `None` when the buffer describes no file.
pub fn display_name(data: &[u8]) -> Option<String> {
    let inv = inventory(data);
    let primary = inv.files.first()?.set_id;
    let pick = |pred: &dyn Fn(&Par2File) -> bool| inv.files.iter().filter(|f| pred(f)).max_by(|a, b| a.size.cmp(&b.size).then_with(|| file_id_key(&b.file_id).cmp(&file_id_key(&a.file_id))));
    pick(&|f| f.set_id == primary && f.bound).or_else(|| pick(&|_| true)).map(|f| f.name.clone())
}

/// Hex rendering of a set or file id (handy for indexer keys).
pub fn id_hex(id: &[u8; 16]) -> String {
    hex(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_detection() {
        assert!(is_base_par2("Release.Name-GRP [1/50] - \"release.par2\" yEnc (1/1)"));
        assert!(is_base_par2("release.PAR2"));
        assert!(!is_base_par2("Release [2/50] - \"release.vol000+01.par2\" yEnc"));
        assert!(!is_base_par2("release.vol07-13.par2"));
        assert!(!is_base_par2("release.part01.rar"));
        assert!(is_base_par2("odd.vol.par2"));
        assert!(is_base_par2("a.par2 and b.vol0+1.par2"));
        assert!(!is_base_par2("par2 is in the text but not a file"));
    }

    #[test]
    fn empty_and_garbage_inputs() {
        assert_eq!(inventory(b""), Inventory::default());
        let inv = inventory(b"PAR2\0PKT\x10\0\0\0\0\0\0\0garbage");
        assert!(inv.files.is_empty());
        assert_eq!(file_descriptions(b"xyz"), Vec::<(String, u64)>::new());
        assert_eq!(display_name(b"xyz"), None);
        assert_eq!(id_hex(&[0xab; 16]).len(), 32);
    }
}
