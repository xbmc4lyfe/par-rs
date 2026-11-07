//! Bounds-checked little-endian readers over untrusted byte slices.

/// `data[off..off + N]` as an array, if present.
pub(crate) fn array<const N: usize>(data: &[u8], off: usize) -> Option<[u8; N]> {
    let end = off.checked_add(N)?;
    data.get(off..end)?.try_into().ok()
}

/// Little-endian `u32` at `off`.
pub(crate) fn u32_le(data: &[u8], off: usize) -> Option<u32> {
    array::<4>(data, off).map(u32::from_le_bytes)
}

/// Little-endian `u64` at `off`.
pub(crate) fn u64_le(data: &[u8], off: usize) -> Option<u64> {
    array::<8>(data, off).map(u64::from_le_bytes)
}

/// `data[off..off + len]`, if present.
pub(crate) fn take(data: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    let end = off.checked_add(len)?;
    data.get(off..end)
}

/// Strip trailing NUL padding.
pub(crate) fn trim_nul(data: &[u8]) -> &[u8] {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |p| p.saturating_add(1));
    data.get(..end).unwrap_or(data)
}

/// Sort key of a PAR2 file id: `libpar2` compares ids as little-endian 128-bit integers
/// (byte 15 most significant), and the global input slice numbering follows that order.
pub(crate) fn file_id_key(id: &[u8; 16]) -> u128 {
    u128::from_le_bytes(*id)
}

/// Lowercase hexadecimal rendering.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_are_bounds_checked() {
        let d = [1u8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(u32_le(&d, 0), Some(1));
        assert_eq!(u64_le(&d, 4), Some(2));
        assert_eq!(u32_le(&d, 9), None);
        assert_eq!(u64_le(&d, usize::MAX), None);
        assert_eq!(take(&d, 10, 2), Some(&d[10..]));
        assert_eq!(take(&d, 10, 3), None);
        assert_eq!(take(&d, usize::MAX, 1), None);
        assert_eq!(trim_nul(b"ab\0\0"), b"ab");
        assert_eq!(trim_nul(b"\0\0"), b"");
        assert_eq!(trim_nul(b""), b"");
        assert_eq!(hex(&[0xab, 0x01]), "ab01");
    }
}
