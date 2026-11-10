//! PAR2 file-name parsing, set grouping and recovery-volume selection.
//!
//! This is a faithful port of nzbget's `ParParser` (`ParseParFilename`, `SameParCollection`,
//! `FindMainPars`) plus the volume block estimation and selection heuristics used by the
//! download queue when additional recovery volumes have to be fetched.
//!
//! All functions operate on raw bytes so that non-UTF-8 names (common on Usenet) behave
//! exactly like the C++ implementation, which works on `char` arrays. Case folding is
//! caller-supplied so that locale-specific `tolower` behaviour can be reproduced; use
//! [`ascii_lower`] for the default.

/// Capacity of nzbget's `BString<1024>` used to hold file names: names are truncated to
/// 1023 bytes before parsing.
pub const NAME_CAPACITY: usize = 1024;

/// Byte case folding equivalent to C `tolower` in the "C" locale.
#[inline]
pub fn ascii_lower(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

/// Result of [`parse_par_filename`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParName {
    /// Length in bytes of the collection base name (the part before `.volXXX+YYY.par2` /
    /// `.par2`), measured on the (possibly truncated) input.
    pub base_len: usize,
    /// `0` for the main `.par2` file, `> 0` for `.volXXX+YYY.par2` (YYY), `-1` for the
    /// `.volXXX-YYY.par2` naming that does not carry a block count.
    pub blocks: i32,
}

impl ParName {
    /// Whether this is the main (index) `.par2` file.
    pub fn is_main(&self) -> bool {
        self.blocks == 0
    }

    /// Whether the block count is unknown (`.vol-` naming); callers estimate it from the size.
    pub fn blocks_unknown(&self) -> bool {
        self.blocks < 0
    }
}

/// Case-insensitive (after `fold`) search for `needle` in `hay` starting at `from`.
fn find_folded(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// C `atoi` semantics on bytes: skip leading whitespace, optional sign, then digits;
/// saturates instead of overflowing.
pub fn atoi(bytes: &[u8]) -> i32 {
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C) {
        i += 1;
    }
    let mut neg = false;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        neg = bytes[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        v = (v * 10 + (bytes[i] - b'0') as i64).min(i32::MAX as i64 + 1);
        i += 1;
    }
    let v = if neg { -v } else { v };
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// Port of `ParParser::ParseParFilename`.
///
/// * `confirmed`: the name is known to be a par2 filename; when `false`, everything after the
///   last `.par2` is cut off first (handles names like `file.par2.1` or `file.par2_dup`).
/// * `fold`: byte case folding applied before matching.
///
/// Returns `None` when the name is not a `.par2` name.
pub fn parse_par_filename(
    name: &[u8],
    confirmed: bool,
    fold: impl Fn(u8) -> u8,
) -> Option<ParName> {
    let truncated = &name[..name.len().min(NAME_CAPACITY - 1)];
    let mut f: Vec<u8> = truncated.iter().map(|&b| fold(b)).collect();
    if f.len() < 6 {
        return None;
    }
    if !confirmed {
        // Find the last occurrence of ".par2" and trim everything after it.
        let mut end = 0usize;
        let mut from = 0usize;
        while let Some(p) = find_folded(&f, b".par2", from) {
            end = p + 5;
            from = end;
        }
        f.truncate(end);
    }
    if f.len() < 6 || !f.ends_with(b".par2") {
        return None;
    }
    f.truncate(f.len() - 5);
    let mut blocks = 0i32;
    if let Some(dot) = f.iter().rposition(|&b| b == b'.')
        && f[dot..].starts_with(b".vol")
    {
        let seg = &f[dot..];
        if let Some(plus) = seg.iter().position(|&b| b == b'+') {
            blocks = atoi(&seg[plus + 1..]);
            f.truncate(dot);
        } else if seg.contains(&b'-') {
            blocks = -1;
            f.truncate(dot);
        }
    }
    Some(ParName {
        base_len: f.len(),
        blocks,
    })
}

/// Port of `ParParser::SameParCollection`: both names parse as par2 names with the same base
/// length and case-insensitively equal bases.
pub fn same_par_collection(a: &[u8], b: &[u8], confirmed: bool) -> bool {
    let (Some(pa), Some(pb)) = (
        parse_par_filename(a, confirmed, ascii_lower),
        parse_par_filename(b, confirmed, ascii_lower),
    ) else {
        return false;
    };
    pa.base_len == pb.base_len
        && a.len() >= pa.base_len
        && b.len() >= pb.base_len
        && a[..pa.base_len].eq_ignore_ascii_case(&b[..pb.base_len])
}

/// Port of `ParParser::FindMainPars`: one representative filename per par2 collection among
/// `names` (the first encountered), in encounter order.
pub fn find_main_pars<'a, I>(names: I) -> Vec<&'a [u8]>
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut out: Vec<&'a [u8]> = Vec::new();
    for name in names {
        if parse_par_filename(name, true, ascii_lower).is_none() {
            continue;
        }
        if !out
            .iter()
            .any(|&existing| same_par_collection(name, existing, true))
        {
            out.push(name);
        }
    }
    out
}

/// Directory-walking convenience for [`find_main_pars`]: returns file names (not paths).
pub fn find_main_pars_in_dir(dir: &std::path::Path) -> std::io::Result<Vec<std::ffi::OsString>> {
    let mut names: Vec<std::ffi::OsString> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        names.push(entry?.file_name());
    }
    names.sort();
    let bytes: Vec<Vec<u8>> = names.iter().map(|n| os_str_bytes(n)).collect();
    let mains = find_main_pars(bytes.iter().map(|b| b.as_slice()));
    Ok(names
        .iter()
        .zip(&bytes)
        .filter(|(_, b)| mains.iter().any(|m| std::ptr::eq(*m, b.as_slice())))
        .map(|(n, _)| n.clone())
        .collect())
}

/// Raw bytes of an OS string (lossy UTF-8 on non-Unix platforms).
pub fn os_str_bytes(s: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        s.to_string_lossy().into_owned().into_bytes()
    }
}

/// Allocation-free extraction of the `+YYY` block count from a `.volXXX+YYY.par2` name.
/// Returns `None` for main files, `.vol-` names, or anything that is not a volume name.
pub fn volume_blocks_bytes(name: &[u8]) -> Option<u32> {
    let n = name.len();
    if n < 10 || !name[n - 5..].eq_ignore_ascii_case(b".par2") {
        return None;
    }
    let stem = &name[..n - 5];
    // Locate the last ".vol" (case-insensitive).
    let mut i = stem.len().checked_sub(4)?;
    loop {
        if stem[i..i + 4].eq_ignore_ascii_case(b".vol") {
            break;
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
    let seg = &stem[i + 4..];
    let plus = seg.iter().position(|&b| b == b'+')?;
    let digits = &seg[plus + 1..];
    if digits.is_empty() || !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v: u64 = 0;
    for &d in digits {
        v = (v * 10 + (d - b'0') as u64).min(u32::MAX as u64);
    }
    Some(v as u32)
}

/// Parse `.volXXX+YYY.par2` into `(first_exponent, count)`.
pub fn volume_range(name: &[u8]) -> Option<(u32, u32)> {
    let count = volume_blocks_bytes(name)?;
    let n = name.len();
    let stem = &name[..n - 5];
    let mut i = stem.len().checked_sub(4)?;
    while !stem[i..i + 4].eq_ignore_ascii_case(b".vol") {
        i = i.checked_sub(1)?;
    }
    let seg = &stem[i + 4..];
    let plus = seg.iter().position(|&b| b == b'+')?;
    let first = &seg[..plus];
    if first.is_empty() || !first.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v: u64 = 0;
    for &d in first {
        v = (v * 10 + (d - b'0') as u64).min(u32::MAX as u64);
    }
    Some((v as u32, count))
}

/// Build a `par2cmdline`-style volume filename: `<base>.vol<first>+<count>.par2` with both
/// numbers zero-padded to `width` digits.
pub fn volume_filename(base: &str, first: u32, count: u32, width: usize) -> String {
    format!("{base}.vol{first:0width$}+{count:0width$}.par2")
}

/// Digits needed to print `max_value` (at least 2, like `par2cmdline`).
pub fn volume_number_width(max_value: u32) -> usize {
    let mut w = 1;
    let mut v = max_value;
    while v >= 10 {
        v /= 10;
        w += 1;
    }
    w.max(2)
}

/// Estimated block count of a *queued* (not yet downloaded) volume: when the name carries no
/// block count (`parsed_blocks < 0`), estimate from the encoded (yEnc) size assuming ~2 %
/// encoding overhead and 68 bytes of packet overhead per recovery slice.
pub fn calc_queued_volume_blocks(parsed_blocks: i32, encoded_size: i64, slice_size: i64) -> i32 {
    if parsed_blocks >= 0 {
        return parsed_blocks;
    }
    let per_block = slice_size.saturating_add(68);
    if per_block <= 0 || encoded_size <= 0 {
        return 0;
    }
    (encoded_size.saturating_mul(100) / 102 / per_block).clamp(0, i32::MAX as i64) as i32
}

/// Estimated block count of a *completed* (on-disk) volume: when the name carries no block
/// count, divide the file size by the per-slice packet size.
pub fn calc_completed_volume_blocks(parsed_blocks: i32, disk_size: i64, slice_size: i64) -> i32 {
    if parsed_blocks >= 0 {
        return parsed_blocks;
    }
    let per_block = slice_size.saturating_add(68);
    if per_block <= 0 || disk_size <= 0 {
        return 0;
    }
    (disk_size / per_block).clamp(0, i32::MAX as i64) as i32
}

/// Choose which queued volumes to download to obtain `block_needed` recovery blocks.
///
/// `sorted_block_counts` must be sorted ascending. Greedy selection, repeated until the
/// need is met or nothing is left:
///
/// 1. if some unselected volume alone covers the remaining need, take the **smallest** such
///    volume and stop;
/// 2. otherwise take the **largest** unselected volume and continue.
///
/// Superfluous volumes are then pruned smallest-first while the remainder still suffices.
///
/// Returns the selected indices (ascending) and the total number of blocks in **all**
/// available volumes (`block_found`), so callers can report `N needed, M available`.
pub fn select_more_pars(sorted_block_counts: &[i32], block_needed: i32) -> (Vec<usize>, i32) {
    debug_assert!(
        sorted_block_counts.windows(2).all(|w| w[0] <= w[1]),
        "input must be sorted ascending"
    );
    let block_found: i32 = sorted_block_counts
        .iter()
        .fold(0i32, |a, &b| a.saturating_add(b.max(0)));
    if block_needed <= 0 || sorted_block_counts.is_empty() {
        return (Vec::new(), block_found);
    }
    let n = sorted_block_counts.len();
    let mut taken = vec![false; n];
    let mut need = block_needed as i64;
    // Candidates with a positive block count, by ascending index (= ascending count).
    while need > 0 {
        let smallest_sufficient =
            (0..n).find(|&i| !taken[i] && sorted_block_counts[i] as i64 >= need);
        if let Some(i) = smallest_sufficient {
            taken[i] = true;
            need -= sorted_block_counts[i] as i64;
            break;
        }
        let Some(largest) = (0..n)
            .rev()
            .find(|&i| !taken[i] && sorted_block_counts[i] > 0)
        else {
            break;
        };
        taken[largest] = true;
        need -= sorted_block_counts[largest] as i64;
    }
    let mut selected: Vec<usize> = (0..n).filter(|&i| taken[i]).collect();
    if need <= 0 {
        // Prune smallest-first while the remaining selection still covers the need.
        let mut total: i64 = selected
            .iter()
            .map(|&i| sorted_block_counts[i] as i64)
            .sum();
        let mut i = 0;
        while i < selected.len() {
            let c = sorted_block_counts[selected[i]] as i64;
            if total - c >= block_needed as i64 {
                total -= c;
                selected.remove(i);
            } else {
                i += 1;
            }
        }
    }
    (selected, block_found)
}

/// Pick a twin set's volume for `left` missing blocks: the smallest volume with at least
/// `left` blocks, otherwise the largest one. `sorted_volume_blocks` must be ascending.
pub fn pick_twin_volume(sorted_volume_blocks: &[i32], left: i32) -> Option<usize> {
    if sorted_volume_blocks.is_empty() {
        return None;
    }
    sorted_volume_blocks
        .iter()
        .position(|&c| c >= left)
        .or(Some(sorted_volume_blocks.len() - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, confirmed: bool) -> Option<ParName> {
        parse_par_filename(name.as_bytes(), confirmed, ascii_lower)
    }

    #[test]
    fn parse_basic_names() {
        assert_eq!(
            p("abc.par2", true),
            Some(ParName {
                base_len: 3,
                blocks: 0
            })
        );
        assert_eq!(
            p("abc.PAR2", true),
            Some(ParName {
                base_len: 3,
                blocks: 0
            })
        );
        assert_eq!(
            p("abc.vol000+01.par2", true),
            Some(ParName {
                base_len: 3,
                blocks: 1
            })
        );
        assert_eq!(
            p("abc.vol07+08.par2", true),
            Some(ParName {
                base_len: 3,
                blocks: 8
            })
        );
        assert_eq!(
            p("abc.VOL07+08.PAR2", true),
            Some(ParName {
                base_len: 3,
                blocks: 8
            })
        );
        assert_eq!(
            p("abc.vol000-019.par2", true),
            Some(ParName {
                base_len: 3,
                blocks: -1
            })
        );
        assert_eq!(
            p("abc.vol.par2", true),
            Some(ParName {
                base_len: 7,
                blocks: 0
            })
        );
        assert_eq!(
            p("abc.volume+5.par2", true),
            Some(ParName {
                base_len: 3,
                blocks: 5
            })
        );
        assert_eq!(
            p("a.b.c.vol1+2.par2", true),
            Some(ParName {
                base_len: 5,
                blocks: 2
            })
        );
        assert!(p(".par2", true).is_none());
        assert_eq!(
            p("x.par2", true),
            Some(ParName {
                base_len: 1,
                blocks: 0
            })
        ); // exactly 6 bytes
        assert!(p("x.par", true).is_none()); // shorter than 6 bytes
        assert!(p("abc.par", true).is_none());
        assert!(p("abc.rar", true).is_none());
        assert!(p("abc.par2.1", true).is_none());
        let n = p("abc.vol01+02.par2", true).unwrap();
        assert!(!n.is_main() && !n.blocks_unknown());
        assert!(p("abc.par2", true).unwrap().is_main());
        assert!(p("abc.vol1-2.par2", true).unwrap().blocks_unknown());
    }

    #[test]
    fn unconfirmed_names_cut_after_last_par2() {
        assert_eq!(
            p("abc.par2.1", false),
            Some(ParName {
                base_len: 3,
                blocks: 0
            })
        );
        assert_eq!(
            p("abc.vol01+02.par2_dup", false),
            Some(ParName {
                base_len: 3,
                blocks: 2
            })
        );
        assert_eq!(
            p("abc.par2.vol01+02.par2.bak", false),
            Some(ParName {
                base_len: 8,
                blocks: 2
            })
        );
        assert!(p("abc.rar", false).is_none());
        assert!(p("par2", false).is_none());
        assert!(p("abc.par2", false).is_some());
    }

    #[test]
    fn truncation_at_1023_bytes() {
        let long = format!("{}.par2", "a".repeat(2000));
        assert!(p(&long, true).is_none()); // ".par2" cut away by truncation
        let fits = format!("{}.par2", "a".repeat(1018));
        assert_eq!(
            p(&fits, true),
            Some(ParName {
                base_len: 1018,
                blocks: 0
            })
        );
    }

    #[test]
    fn same_collection_and_find_main() {
        assert!(same_par_collection(b"abc.par2", b"ABC.vol01+02.par2", true));
        assert!(same_par_collection(
            b"abc.par2",
            b"abc.vol000-019.par2",
            true
        ));
        assert!(!same_par_collection(b"abc.par2", b"abcd.par2", true));
        assert!(!same_par_collection(b"abc.par2", b"xbc.par2", true));
        assert!(!same_par_collection(b"abc.par2", b"abc.rar", true));
        assert!(same_par_collection(
            b"abc.par2.1",
            b"abc.vol1+1.par2",
            false
        ));

        let names: Vec<&[u8]> = vec![
            b"movie.rar",
            b"movie.par2",
            b"movie.vol00+01.par2",
            b"Movie.vol01+02.PAR2",
            b"other.vol0+1.par2",
            b"other.par2",
            b"notes.txt",
        ];
        let mains = find_main_pars(names.iter().copied());
        assert_eq!(mains, vec![&b"movie.par2"[..], &b"other.vol0+1.par2"[..]]);
    }

    #[test]
    fn find_main_pars_on_disk() {
        let dir = std::env::temp_dir().join(format!("par-rs-fn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for n in ["b.par2", "b.vol0+1.par2", "a.vol1+2.par2", "c.txt"] {
            std::fs::write(dir.join(n), b"x").unwrap();
        }
        let mut mains = find_main_pars_in_dir(&dir).unwrap();
        mains.sort();
        assert_eq!(
            mains,
            vec![
                std::ffi::OsString::from("a.vol1+2.par2"),
                std::ffi::OsString::from("b.par2")
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(os_str_bytes(std::ffi::OsStr::new("ab")), b"ab");
    }

    #[test]
    fn atoi_semantics() {
        assert_eq!(atoi(b"12abc"), 12);
        assert_eq!(atoi(b"  +7"), 7);
        assert_eq!(atoi(b"-3"), -3);
        assert_eq!(atoi(b"abc"), 0);
        assert_eq!(atoi(b""), 0);
        assert_eq!(atoi(b"99999999999999"), i32::MAX);
        assert_eq!(atoi(b"-99999999999999"), i32::MIN);
    }

    #[test]
    fn volume_block_extraction() {
        assert_eq!(volume_blocks_bytes(b"abc.vol000+01.par2"), Some(1));
        assert_eq!(volume_blocks_bytes(b"abc.VOL12+034.PAR2"), Some(34));
        assert_eq!(volume_blocks_bytes(b"abc.vol000-019.par2"), None);
        assert_eq!(volume_blocks_bytes(b"abc.par2"), None);
        assert_eq!(volume_blocks_bytes(b"abc.vol+.par2"), None);
        assert_eq!(volume_blocks_bytes(b"abc.vol1+2x.par2"), None);
        assert_eq!(
            volume_blocks_bytes(b"abc.vol1+99999999999.par2"),
            Some(u32::MAX)
        );
        assert_eq!(volume_blocks_bytes(b"a.rar"), None);
        assert_eq!(volume_blocks_bytes(b"vol1+2.par2"), None);
        assert_eq!(volume_range(b"abc.vol07+08.par2"), Some((7, 8)));
        assert_eq!(volume_range(b"abc.vol+08.par2"), None);
        assert_eq!(volume_range(b"abc.vol0x+08.par2"), None);
        assert_eq!(volume_range(b"abc.par2"), None);
        assert_eq!(volume_filename("abc", 7, 8, 2), "abc.vol07+08.par2");
        assert_eq!(volume_filename("abc", 100, 50, 3), "abc.vol100+050.par2");
        assert_eq!(volume_number_width(5), 2);
        assert_eq!(volume_number_width(99), 2);
        assert_eq!(volume_number_width(100), 3);
        assert_eq!(volume_number_width(12345), 5);
    }

    #[test]
    fn block_estimates() {
        assert_eq!(calc_queued_volume_blocks(5, 1_000_000, 1000), 5);
        assert_eq!(calc_queued_volume_blocks(0, 1_000_000, 1000), 0);
        // 10 slices of 1000 bytes + 68 overhead each, yEnc-inflated by 2 %.
        let encoded = (10 * 1068) as i64 * 102 / 100;
        assert_eq!(
            calc_queued_volume_blocks(-1, encoded, 1000),
            (encoded * 100 / 102 / 1068) as i32
        );
        assert_eq!(
            calc_queued_volume_blocks(-1, 10 * 1068 * 102 / 100 + 100, 1000),
            10
        );
        assert_eq!(calc_queued_volume_blocks(-1, 0, 1000), 0);
        assert_eq!(
            calc_queued_volume_blocks(-1, 1000, 0),
            1000 * 100 / 102 / 68
        );
        assert_eq!(calc_queued_volume_blocks(-1, 1000, -100), 0);
        assert_eq!(calc_completed_volume_blocks(3, 999, 10), 3);
        assert_eq!(calc_completed_volume_blocks(-1, 10 * 1068 + 500, 1000), 10);
        assert_eq!(calc_completed_volume_blocks(-1, -5, 1000), 0);
        assert_eq!(calc_completed_volume_blocks(-1, 5, -68), 0);
    }

    #[test]
    fn selection_of_additional_volumes() {
        // Exact / smallest sufficient single volume.
        assert_eq!(select_more_pars(&[1, 2, 4, 8, 16], 4), (vec![2], 31));
        assert_eq!(select_more_pars(&[1, 2, 4, 8, 16], 5), (vec![3], 31));
        assert_eq!(select_more_pars(&[1, 2, 4, 8, 16], 16), (vec![4], 31));
        // Need more than any single volume: largest first, then the smallest that covers the rest.
        assert_eq!(select_more_pars(&[1, 2, 4, 8, 16], 20), (vec![2, 4], 31));
        assert_eq!(select_more_pars(&[1, 2, 4, 8, 16], 24), (vec![3, 4], 31));
        assert_eq!(select_more_pars(&[1, 2, 4, 8, 16], 25), (vec![0, 3, 4], 31));
        assert_eq!(
            select_more_pars(&[1, 2, 4, 8, 16], 31),
            (vec![0, 1, 2, 3, 4], 31)
        );
        assert_eq!(
            select_more_pars(&[1, 2, 4, 8, 16], 30),
            (vec![1, 2, 3, 4], 31)
        );
        // Not enough: everything (with blocks) is selected.
        assert_eq!(select_more_pars(&[1, 2, 4], 100), (vec![0, 1, 2], 7));
        assert_eq!(select_more_pars(&[1, 2, 16, 16], 17), (vec![0, 3], 35));
        assert_eq!(select_more_pars(&[2, 3, 16], 18), (vec![0, 2], 21));
        assert_eq!(select_more_pars(&[1, 1, 16], 17), (vec![0, 2], 18));
        // Pruning: need 7 from [5, 5, 6]: 6 then 5 → 11; nothing removable. Need 10 from [5,5,6]: 6,5 → 11.
        assert_eq!(select_more_pars(&[5, 5, 6], 7), (vec![0, 2], 16));
        // Need 12 from [4, 5, 6, 6]: 6, 6 → 12 exactly.
        assert_eq!(select_more_pars(&[4, 5, 6, 6], 12), (vec![2, 3], 21));
        // Need 13 from [1, 6, 6, 6]: 6, 6 → need 1 → take 1 → [0,2,3]; prune: drop 1? 12 < 13 keep.
        assert_eq!(select_more_pars(&[1, 6, 6, 6], 13), (vec![0, 2, 3], 19));
        // Prune removes a superfluous early pick: need 9 from [3, 4, 5, 8]: 8 → need 1 → smallest ≥1 is 3 → [0,3] = 11;
        // 11-3 = 8 < 9 keep. Need 8 from [2, 7, 7]: smallest sufficient none → 7 → need 1 → 2 → [0,2] = 9, prune 2? 7<8 keep.
        assert_eq!(select_more_pars(&[2, 7, 7], 8), (vec![0, 2], 16));
        // Zero / negative need, empty list, zero-size volumes.
        assert_eq!(select_more_pars(&[1, 2], 0), (vec![], 3));
        assert_eq!(select_more_pars(&[], 5), (vec![], 0));
        assert_eq!(select_more_pars(&[0, 0, 3], 2), (vec![2], 3));
        assert_eq!(select_more_pars(&[-1, 0, 3], 5), (vec![2], 3));
    }

    #[test]
    fn twin_volume_pick() {
        assert_eq!(pick_twin_volume(&[1, 2, 4, 8], 3), Some(2));
        assert_eq!(pick_twin_volume(&[1, 2, 4, 8], 8), Some(3));
        assert_eq!(pick_twin_volume(&[1, 2, 4, 8], 9), Some(3));
        assert_eq!(pick_twin_volume(&[1, 2, 4, 8], 0), Some(0));
        assert_eq!(pick_twin_volume(&[], 1), None);
    }
}
