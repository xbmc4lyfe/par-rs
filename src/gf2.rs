//! GF(2) polynomial linear algebra over the bit-reflected IEEE 802.3 CRC-32 polynomial.
//!
//! A CRC-32 register is a polynomial over GF(2) modulo `P(x)` (reflected: bit 31 is `x^0`).
//! Appending `n` zero bytes multiplies the register by `x^(8n)`, which makes every operation
//! here `O(log n)`: combining two checksums, removing zero padding, stripping a known prefix or
//! suffix, folding yEnc article checksums into a file checksum, and folding PAR2 IFSC slice
//! checksums into the whole-file CRC without reading a byte. [`RollingCrc32`] slides a fixed
//! window one byte at a time with a 256-entry removal table.
//!
//! The signatures of the `atlas::gf2` module are preserved exactly.

use std::fmt;

/// Reflected IEEE 802.3 polynomial.
pub const GF2_POLY: u32 = 0xEDB8_8320;
/// Multiplicative order of `x` modulo `P` (`P` is primitive): `2^32 - 1`.
pub const GF2_ORDER: u64 = (1u64 << 32) - 1;

/// Multiply two polynomials modulo `P` (reflected representation; `1 << 31` is the unit).
pub const fn multmodp(a: u32, b: u32) -> u32 {
    if a == 0 || b == 0 {
        return 0;
    }
    let mut m: u32 = 1 << 31;
    let mut p: u32 = 0;
    let mut b = b;
    loop {
        if a & m != 0 {
            p ^= b;
            if a & m.wrapping_sub(1) == 0 {
                break;
            }
        }
        m >>= 1;
        b = if b & 1 != 0 {
            (b >> 1) ^ GF2_POLY
        } else {
            b >> 1
        };
    }
    p
}

/// `x^(2^k) mod P` for `k` in `0..32` (`x^(2^32) == x`, so the table wraps).
#[allow(clippy::indexing_slicing)] // compile-time table: an out-of-range index is a build error, not a panic
const X2N: [u32; 32] = {
    let mut t = [0u32; 32];
    let mut v: u32 = 1 << 30; // x^1
    let mut k = 0;
    while k < 32 {
        t[k] = v;
        v = multmodp(v, v);
        k += 1;
    }
    t
};

/// `x^(n · 2^k) mod P`.
pub fn x2nmodp(n: u64, k: u32) -> u32 {
    let mut p: u32 = 1 << 31; // x^0
    let mut n = n;
    let mut k = k;
    while n != 0 {
        if n & 1 != 0 {
            let idx = (k & 31) as usize;
            p = multmodp(X2N.get(idx).copied().unwrap_or(0), p);
        }
        n >>= 1;
        k = k.wrapping_add(1);
    }
    p
}

/// `x^n_bits mod P`: the operator that shifts a register past `n_bits` zero bits.
pub fn xpow(n_bits: u64) -> u32 {
    x2nmodp(n_bits, 0)
}

/// Operator for `n_bytes` zero bytes: `x^(8 · n_bytes)`.
fn xpow_bytes(n_bytes: u64) -> u32 {
    x2nmodp(n_bytes, 3)
}

/// Inverse of [`xpow_bytes`]: `x^(-8 · n_bytes) = x^(ORDER - (8 · n_bytes mod ORDER))`.
fn xpow_bytes_inv(n_bytes: u64) -> u32 {
    // 8 · n_bytes mod ORDER without overflow: n_bytes mod ORDER first (ORDER is odd, 8 is a unit).
    let bits = (n_bytes % GF2_ORDER).wrapping_mul(8) % GF2_ORDER;
    if bits == 0 {
        1 << 31
    } else {
        xpow(GF2_ORDER - bits)
    }
}

/// Byte-wise CRC-32 table (`T[b] = b · x^8 mod P`, with the byte in the low bits).
#[allow(clippy::indexing_slicing)] // compile-time table, see `X2N`
const TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ GF2_POLY
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

#[inline]
fn table(b: u8) -> u32 {
    TABLE.get(b as usize).copied().unwrap_or(0)
}

/// CRC-32 of `crc1`'s data followed by `crc2`'s data (`len2` bytes long).
pub fn crc32_combine(crc1: u32, crc2: u32, len2: usize) -> u32 {
    crc32_combine_u64(crc1, crc2, len2 as u64)
}

/// [`crc32_combine`] with a 64-bit length.
pub fn crc32_combine_u64(crc1: u32, crc2: u32, len2: u64) -> u32 {
    multmodp(xpow_bytes(len2), crc1) ^ crc2
}

/// CRC-32 of `len` zero bytes.
pub fn crc32_zeros(len: usize) -> u32 {
    crc32_zeros_u64(len as u64)
}

/// [`crc32_zeros`] with a 64-bit length.
pub fn crc32_zeros_u64(len: u64) -> u32 {
    multmodp(xpow_bytes(len), 0xFFFF_FFFF) ^ 0xFFFF_FFFF
}

/// Given the CRC of `data ‖ zeros(zero_len)`, recover the CRC of `data`.
pub fn crc32_unzero(padded_crc: u32, zero_len: usize) -> u32 {
    crc32_unzero_u64(padded_crc, zero_len as u64)
}

/// [`crc32_unzero`] with a 64-bit length.
pub fn crc32_unzero_u64(padded_crc: u32, zero_len: u64) -> u32 {
    multmodp(
        xpow_bytes_inv(zero_len),
        padded_crc ^ crc32_zeros_u64(zero_len),
    )
}

/// Alias of [`crc32_unzero`].
pub fn crc32_zero_unpad(padded_crc: u32, zero_len: usize) -> u32 {
    crc32_unzero(padded_crc, zero_len)
}

/// CRC-32 (IEEE) of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Given `crc(A ‖ B)` and `crc(B)` (`len_b` bytes), recover `crc(A)`.
pub fn crc32_uncombine_suffix(crc_ab: u32, crc_b: u32, len_b: u64) -> u32 {
    multmodp(xpow_bytes_inv(len_b), crc_ab ^ crc_b)
}

/// Given `crc(A ‖ B)` and `crc(A)`, recover `crc(B)` (`len_b` bytes).
pub fn crc32_uncombine_prefix(crc_ab: u32, crc_a: u32, len_b: u64) -> u32 {
    crc_ab ^ multmodp(xpow_bytes(len_b), crc_a)
}

/// The operator "append `len` bytes" (`x^(8·len) mod P`) as four 256-entry tables, so that
/// combining many checksums of the same length costs four lookups each instead of a 32-step
/// multiply: `crc · c` is GF(2)-linear in `crc`, so `T_k[b] = (b << 8k) · c` and the product is
/// the XOR of one lookup per byte of `crc`.
///
/// Build it once per slice size (≈2 µs) and reuse it: [`fold_ifsc_crcs_with`] and
/// [`ifsc_interval_crcs`] do, and the plain folds switch to one automatically past
/// [`Crc32Shift::MIN_PARTS`] parts.
#[derive(Clone)]
pub struct Crc32Shift {
    tables: Box<[[u32; 256]; 4]>,
    len: u64,
}

impl fmt::Debug for Crc32Shift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Crc32Shift({} bytes)", self.len)
    }
}

impl Crc32Shift {
    /// Part count from which building a table pays for itself in the folds.
    pub const MIN_PARTS: usize = 48;

    /// Operator for `len` bytes.
    pub fn new(len: u64) -> Self {
        Self::from_operator(xpow_bytes(len), len)
    }

    #[allow(clippy::indexing_slicing)] // every index is a `u8` or `0..4`, always in range
    fn from_operator(c: u32, len: u64) -> Self {
        let mut tables = Box::new([[0u32; 256]; 4]);
        for (k, table) in tables.iter_mut().enumerate() {
            let mut basis = [0u32; 8];
            for (bit, b) in basis.iter_mut().enumerate() {
                *b = multmodp(1u32 << (8 * k + bit), c);
            }
            for b in 1usize..256 {
                table[b] = table[b & (b - 1)] ^ basis[b.trailing_zeros() as usize];
            }
        }
        Self { tables, len }
    }

    /// The number of bytes this operator appends.
    pub fn byte_len(&self) -> u64 {
        self.len
    }

    /// `crc · x^(8·len)`: the CRC after appending `len` zero bytes to a register holding `crc`
    /// (raw register semantics; see [`crc32_zeros`] for finalised checksums).
    #[inline]
    #[allow(clippy::indexing_slicing)] // indices are bytes of `crc`
    pub fn apply(&self, crc: u32) -> u32 {
        let [b0, b1, b2, b3] = crc.to_le_bytes();
        self.tables[0][b0 as usize]
            ^ self.tables[1][b1 as usize]
            ^ self.tables[2][b2 as usize]
            ^ self.tables[3][b3 as usize]
    }

    /// [`crc32_combine`] with `len2 == self.len()`: CRC of `crc1`'s data followed by
    /// `crc2`'s data.
    #[inline]
    pub fn combine(&self, crc1: u32, crc2: u32) -> u32 {
        self.apply(crc1) ^ crc2
    }
}

/// Combines consecutive parts, switching to a [`Crc32Shift`] table when enough parts of one
/// length are expected.
struct Folder {
    shift: Option<Crc32Shift>,
    use_tables: bool,
    rebuilds: u8,
}

impl Folder {
    fn new(expected_parts: usize) -> Self {
        Self {
            shift: None,
            use_tables: expected_parts >= Crc32Shift::MIN_PARTS,
            rebuilds: 0,
        }
    }

    #[inline]
    fn combine(&mut self, acc: u32, crc: u32, len: u64) -> u32 {
        if !self.use_tables {
            return crc32_combine_u64(acc, crc, len);
        }
        if self.shift.as_ref().is_none_or(|s| s.byte_len() != len) {
            // Lengths that keep changing (not the one odd tail part) are not worth tables.
            if self.rebuilds >= 3 {
                self.use_tables = false;
                return crc32_combine_u64(acc, crc, len);
            }
            self.rebuilds += 1;
            self.shift = Some(Crc32Shift::new(len));
        }
        match &self.shift {
            Some(s) => s.combine(acc, crc),
            None => crc32_combine_u64(acc, crc, len),
        }
    }
}

/// Why a set of part checksums could not be folded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldError {
    /// No parts at all.
    Empty,
    /// Part `i` is absent.
    MissingPart(usize),
    /// Part `i` was supplied twice with different checksums or lengths.
    CorruptPart(usize),
    /// A part index is outside `0..total`, or the part count disagrees with `total`.
    LengthMismatch,
}

impl fmt::Display for FoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FoldError::Empty => f.write_str("no parts to fold"),
            FoldError::MissingPart(i) => write!(f, "part {i} is missing"),
            FoldError::CorruptPart(i) => {
                write!(f, "part {i} was supplied twice with different values")
            }
            FoldError::LengthMismatch => {
                f.write_str("part indices do not match the declared part count")
            }
        }
    }
}

impl std::error::Error for FoldError {}

/// Fold consecutive yEnc part checksums `(crc32, length)` into the file checksum.
pub fn fold_yenc_parts(parts: &[(u32, usize)]) -> Result<u32, FoldError> {
    let mut it = parts.iter();
    let Some(&(first, _)) = it.next() else {
        return Err(FoldError::Empty);
    };
    let mut folder = Folder::new(parts.len());
    Ok(it.fold(first, |acc, &(crc, len)| {
        folder.combine(acc, crc, len as u64)
    }))
}

/// Fold yEnc parts given as `(part index, crc32, length)` in any order; every index in
/// `0..total` must be present exactly once (duplicates must agree).
pub fn fold_yenc_indexed_parts(
    total: usize,
    parts: &[(usize, u32, usize)],
) -> Result<u32, FoldError> {
    if total == 0 || parts.is_empty() {
        return Err(FoldError::Empty);
    }
    if parts.iter().any(|&(i, _, _)| i >= total) {
        return Err(FoldError::LengthMismatch);
    }
    // Sorted copy (bounded by the caller's own part list, never by `total`).
    let mut sorted: Vec<(usize, u32, usize)> = parts.to_vec();
    sorted.sort_unstable();
    let mut expected = 0usize;
    let mut acc: Option<u32> = None;
    let mut last: Option<(usize, u32, usize)> = None;
    let mut folder = Folder::new(total);
    for &(i, crc, len) in &sorted {
        if let Some((li, lc, ll)) = last
            && li == i
        {
            if lc != crc || ll != len {
                return Err(FoldError::CorruptPart(i));
            }
            continue;
        }
        if i != expected {
            return Err(FoldError::MissingPart(expected));
        }
        acc = Some(match acc {
            None => crc,
            Some(a) => folder.combine(a, crc, len as u64),
        });
        expected = expected.saturating_add(1);
        last = Some((i, crc, len));
    }
    if expected != total {
        return Err(FoldError::MissingPart(expected));
    }
    acc.ok_or(FoldError::Empty)
}

/// Fold PAR2 IFSC slice CRCs (each over a `block_size` slice, the last one zero padded) into
/// the whole-file CRC-32. `None` when the slice count does not match `file_size / block_size`.
pub fn fold_ifsc_crcs(slice_crcs: &[u32], block_size: u64, file_size: u64) -> Option<u32> {
    if slice_crcs.len() >= Crc32Shift::MIN_PARTS {
        return fold_ifsc_crcs_with(&Crc32Shift::new(block_size), slice_crcs, file_size);
    }
    fold_ifsc_impl(slice_crcs, block_size, file_size, |a, c| {
        crc32_combine_u64(a, c, block_size)
    })
}

/// [`fold_ifsc_crcs`] with a prebuilt operator for the set's block size (`shift.byte_len()`), for
/// callers folding many files of one set: four lookups per slice instead of a multiply.
pub fn fold_ifsc_crcs_with(shift: &Crc32Shift, slice_crcs: &[u32], file_size: u64) -> Option<u32> {
    fold_ifsc_impl(slice_crcs, shift.byte_len(), file_size, |a, c| {
        shift.combine(a, c)
    })
}

/// Shared body of the IFSC folds; `combine_full(acc, crc)` appends one full `block_size` slice.
fn fold_ifsc_impl(
    slice_crcs: &[u32],
    block_size: u64,
    file_size: u64,
    combine_full: impl Fn(u32, u32) -> u32,
) -> Option<u32> {
    if block_size == 0 {
        return None;
    }
    let slices = file_size.div_ceil(block_size);
    if slices != slice_crcs.len() as u64 {
        return None;
    }
    if file_size == 0 {
        return Some(0);
    }
    let last_len = file_size - (slices - 1) * block_size; // 1..=block_size
    let pad = block_size - last_len;
    let (last, full) = slice_crcs.split_last()?;
    let last_crc = crc32_unzero_u64(*last, pad);
    let mut acc: Option<u32> = None;
    for &c in full {
        acc = Some(match acc {
            None => c,
            Some(a) => combine_full(a, c),
        });
    }
    Some(match acc {
        None => last_crc,
        Some(a) => crc32_combine_u64(a, last_crc, last_len),
    })
}

/// Fold PAR2 IFSC slice CRCs (each over `block_size` bytes, the last one zero padded) onto
/// `grid_size` intervals of the unpadded file: entry `k` is the CRC-32 of file bytes
/// `[k · grid_size, (k + 1) · grid_size)`, the last entry covering the tail. Compare it with
/// [`compute_interval_crcs`] of the file's articles on the same grid (`lcm_grid(&[article_size,
/// block_size])`) to see *which* stretch of a file disagrees with its PAR2 set.
///
/// `None` when `grid_size` is not a positive multiple of `block_size`, `block_size == 0`, or
/// the slice count does not fit `file_size`. A zero-length file has no intervals.
pub fn ifsc_interval_crcs(
    slice_crcs: &[u32],
    block_size: u64,
    file_size: u64,
    grid_size: u64,
) -> Option<Vec<u32>> {
    if block_size == 0 || grid_size == 0 || !grid_size.is_multiple_of(block_size) {
        return None;
    }
    let slices = file_size.div_ceil(block_size);
    if slices != slice_crcs.len() as u64 {
        return None;
    }
    if file_size == 0 {
        return Some(Vec::new());
    }
    let per_interval = usize::try_from(grid_size / block_size).ok()?;
    let last_len = file_size - (slices - 1) * block_size; // 1..=block_size
    let pad = block_size - last_len;
    let shift = (slice_crcs.len() >= Crc32Shift::MIN_PARTS).then(|| Crc32Shift::new(block_size));
    let combine_full = |a: u32, c: u32| match &shift {
        Some(s) => s.combine(a, c),
        None => crc32_combine_u64(a, c, block_size),
    };
    let (last, full) = slice_crcs.split_last()?;
    let last_crc = crc32_unzero_u64(*last, pad);
    let mut out = Vec::with_capacity(slice_crcs.len().div_ceil(per_interval));
    let mut acc: Option<u32> = None;
    let mut filled = 0usize;
    for &c in full {
        acc = Some(match acc {
            None => c,
            Some(a) => combine_full(a, c),
        });
        filled += 1;
        if filled == per_interval {
            out.push(acc.take().unwrap_or(0));
            filled = 0;
        }
    }
    out.push(match acc {
        None => last_crc,
        Some(a) => crc32_combine_u64(a, last_crc, last_len),
    });
    Some(out)
}

/// `O(1)`-per-byte sliding-window CRC-32 for a fixed window size.
///
/// For a window `W` of `n` bytes and raw register `r(W)`, appending `b_in` and dropping the
/// leading byte `b_out` gives `r(W') = step(r(W), b_in) ⊕ U[b_out] ⊕ C` with
/// `U[b] = b · x^(8(n+1))` and `C = I · x^(8n) · (x^8 ⊕ 1)` (`I` the initial register), all
/// precomputed once per window size.
#[derive(Clone, Debug)]
pub struct RollingCrc32 {
    window: u64,
    removal: [u32; 256],
    init_fix: u32,
}

impl RollingCrc32 {
    /// Table for windows of `window_size` bytes (`None` for an empty window).
    pub fn new(window_size: u64) -> Option<Self> {
        if window_size == 0 {
            return None;
        }
        let shift_n = xpow_bytes(window_size);
        let mut removal = [0u32; 256];
        for (b, slot) in removal.iter_mut().enumerate() {
            *slot = multmodp(shift_n, table(b as u8));
        }
        let i_n = multmodp(shift_n, 0xFFFF_FFFF);
        let i_n1 = multmodp(xpow_bytes(window_size.wrapping_add(1)), 0xFFFF_FFFF);
        Some(Self {
            window: window_size,
            removal,
            init_fix: i_n ^ i_n1,
        })
    }

    /// Window length in bytes.
    pub fn window_size(&self) -> u64 {
        self.window
    }

    /// CRC-32 of the initial window (`window` must be exactly `window_size` bytes).
    pub fn first(&self, window: &[u8]) -> Option<u32> {
        (window.len() as u64 == self.window).then(|| crc32(window))
    }

    /// CRC-32 of the window after dropping `out_byte` at its front and appending `in_byte`.
    pub fn roll(&self, crc: u32, out_byte: u8, in_byte: u8) -> u32 {
        let raw = crc ^ 0xFFFF_FFFF;
        let stepped = (raw >> 8) ^ table(((raw ^ in_byte as u32) & 0xFF) as u8);
        let removed = self.removal.get(out_byte as usize).copied().unwrap_or(0);
        (stepped ^ removed ^ self.init_fix) ^ 0xFFFF_FFFF
    }
}

/// Greatest common divisor.
pub fn gcd(a: u64, b: u64) -> u64 {
    let (mut a, mut b) = (a, b);
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// Least common multiple (`None` on overflow or zero input).
pub fn lcm(a: u64, b: u64) -> Option<u64> {
    if a == 0 || b == 0 {
        return None;
    }
    (a / gcd(a, b)).checked_mul(b)
}

/// LCM of several article sizes: the grid on which every size's article boundaries coincide
/// (e.g. `LCM(716_800, 768_000) = 10_752_000`, i.e. 15 articles of the first size and 14 of
/// the second).
pub fn lcm_grid(sizes: &[u64]) -> Option<u64> {
    let mut it = sizes.iter();
    let mut acc = *it.next()?;
    for &s in it {
        acc = lcm(acc, s)?;
    }
    (acc != 0).then_some(acc)
}

/// Fold consecutive part checksums `(crc32, length)` onto `grid_size` intervals: entry `k` is
/// the CRC-32 of file bytes `[k · grid, (k + 1) · grid)`, the last entry covering the tail.
/// `None` when a part straddles a grid boundary (its CRC cannot be split) or `grid_size == 0`.
pub fn compute_interval_crcs(parts: &[(u32, u64)], grid_size: u64) -> Option<Vec<u32>> {
    if grid_size == 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut acc: Option<u32> = None;
    let mut filled: u64 = 0;
    let mut folder = Folder::new(parts.len());
    for &(crc, len) in parts {
        if len == 0 {
            continue;
        }
        let remaining = grid_size - filled;
        if len > remaining {
            return None;
        }
        acc = Some(match acc {
            None => crc,
            Some(a) => folder.combine(a, crc, len),
        });
        filled += len;
        if filled == grid_size {
            out.push(acc.take().unwrap_or(0));
            filled = 0;
        }
    }
    if let Some(a) = acc {
        out.push(a);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(n: usize, seed: u32) -> Vec<u8> {
        (0..n as u32)
            .map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed) >> 13) as u8)
            .collect()
    }

    #[test]
    fn combine_zeros_unzero_and_uncombine_round_trip() {
        let a = data(1000, 1);
        let b = data(777, 2);
        let ab: Vec<u8> = a.iter().chain(&b).copied().collect();
        let (ca, cb, cab) = (crc32(&a), crc32(&b), crc32(&ab));
        assert_eq!(crc32_combine(ca, cb, b.len()), cab);
        assert_eq!(crc32_combine(ca, crc32(&[]), 0), ca);
        assert_eq!(crc32_combine(crc32(&[]), cb, b.len()), cb);
        assert_eq!(crc32_uncombine_suffix(cab, cb, b.len() as u64), ca);
        assert_eq!(crc32_uncombine_prefix(cab, ca, b.len() as u64), cb);
        for z in [0usize, 1, 3, 64, 1000, 70_000] {
            let zeros = vec![0u8; z];
            assert_eq!(crc32_zeros(z), crc32(&zeros), "zeros {z}");
            let mut padded = a.clone();
            padded.extend_from_slice(&zeros);
            assert_eq!(crc32_unzero(crc32(&padded), z), ca, "unzero {z}");
            assert_eq!(crc32_zero_unpad(crc32(&padded), z), ca);
        }
        assert_eq!(xpow(0), 1 << 31);
        assert_eq!(xpow(1), 1 << 30);
        assert_eq!(x2nmodp(3, 0), xpow(3));
        assert_eq!(x2nmodp(5, 3), xpow(40));
        assert_eq!(multmodp(0, 123), 0);
        assert_eq!(multmodp(1 << 31, 0xdead_beef), 0xdead_beef);
        // x has order 2^32 - 1.
        assert_eq!(xpow(GF2_ORDER), 1 << 31);
        assert_eq!(multmodp(xpow_bytes(123), xpow_bytes_inv(123)), 1 << 31);
        assert_eq!(xpow_bytes_inv(0), 1 << 31);
    }

    #[test]
    fn yenc_folding() {
        let file = data(10_000, 9);
        let sizes = [3000usize, 3000, 3000, 1000];
        let mut parts = Vec::new();
        let mut off = 0;
        for &s in &sizes {
            parts.push((crc32(&file[off..off + s]), s));
            off += s;
        }
        assert_eq!(fold_yenc_parts(&parts), Ok(crc32(&file)));
        assert_eq!(fold_yenc_parts(&[]), Err(FoldError::Empty));
        let indexed: Vec<(usize, u32, usize)> = parts
            .iter()
            .enumerate()
            .rev()
            .map(|(i, &(c, l))| (i, c, l))
            .collect();
        assert_eq!(fold_yenc_indexed_parts(4, &indexed), Ok(crc32(&file)));
        let mut dup = indexed.clone();
        dup.push(indexed[2]);
        assert_eq!(fold_yenc_indexed_parts(4, &dup), Ok(crc32(&file)));
        dup.push((2, 1, 3000));
        assert_eq!(
            fold_yenc_indexed_parts(4, &dup),
            Err(FoldError::CorruptPart(2))
        );
        assert_eq!(
            fold_yenc_indexed_parts(5, &indexed),
            Err(FoldError::MissingPart(4))
        );
        assert_eq!(
            fold_yenc_indexed_parts(4, &indexed[2..]),
            Err(FoldError::MissingPart(2))
        );
        assert_eq!(
            fold_yenc_indexed_parts(3, &indexed),
            Err(FoldError::LengthMismatch)
        );
        assert_eq!(fold_yenc_indexed_parts(0, &indexed), Err(FoldError::Empty));
        assert_eq!(fold_yenc_indexed_parts(4, &[]), Err(FoldError::Empty));
        assert_eq!(
            fold_yenc_indexed_parts(4, &[(1, 0, 1)]),
            Err(FoldError::MissingPart(0))
        );
        assert_eq!(FoldError::MissingPart(3).to_string(), "part 3 is missing");
    }

    #[test]
    fn ifsc_folding_and_grid_intervals() {
        let file = data(2_500_000, 4);
        let bs = 1_048_576u64;
        let mut crcs = Vec::new();
        for chunk in file.chunks(bs as usize) {
            let mut padded = chunk.to_vec();
            padded.resize(bs as usize, 0);
            crcs.push(crc32(&padded));
        }
        assert_eq!(
            fold_ifsc_crcs(&crcs, bs, file.len() as u64),
            Some(crc32(&file))
        );
        assert_eq!(fold_ifsc_crcs(&crcs[..2], bs, file.len() as u64), None);
        assert_eq!(fold_ifsc_crcs(&[], bs, 0), Some(0));
        assert_eq!(fold_ifsc_crcs(&crcs, 0, 1), None);
        // Exact multiple: no padding on the last slice.
        let exact = &file[..2 * bs as usize];
        assert_eq!(
            fold_ifsc_crcs(&crcs[..2], bs, exact.len() as u64),
            Some(crc32(exact))
        );

        assert_eq!(gcd(716_800, 768_000), 51_200);
        // 716_800 = 14 · 51_200 and 768_000 = 15 · 51_200, so the grid is 14 · 15 · 51_200.
        assert_eq!(lcm(716_800, 768_000), Some(10_752_000));
        assert_eq!(lcm_grid(&[716_800, 768_000, 716_800]), Some(10_752_000));
        assert_eq!(lcm_grid(&[]), None);
        assert_eq!(lcm(0, 5), None);
        assert_eq!(lcm(u64::MAX, 2), None);

        // Parts of 100 and 150 on a grid of 300.
        let f = data(1050, 7);
        let mut parts = Vec::new();
        let mut off = 0;
        for &l in &[100u64, 150, 50, 300, 150, 150, 150] {
            parts.push((crc32(&f[off..off + l as usize]), l));
            off += l as usize;
        }
        let grid = compute_interval_crcs(&parts, 300).unwrap();
        assert_eq!(grid.len(), 4);
        assert_eq!(grid[0], crc32(&f[..300]));
        assert_eq!(grid[1], crc32(&f[300..600]));
        assert_eq!(grid[2], crc32(&f[600..900]));
        assert_eq!(grid[3], crc32(&f[900..1050]));
        assert_eq!(compute_interval_crcs(&parts, 250), None);
        assert_eq!(compute_interval_crcs(&parts, 0), None);
        assert_eq!(compute_interval_crcs(&[], 300), Some(vec![]));
    }

    #[test]
    fn rolling_window_matches_direct_crc() {
        let buf = data(5000, 3);
        for n in [1u64, 2, 7, 64, 1000] {
            let r = RollingCrc32::new(n).unwrap();
            assert_eq!(r.window_size(), n);
            let n = n as usize;
            let mut c = r.first(&buf[..n]).unwrap();
            assert!(r.first(&buf[..n + 1]).is_none());
            for pos in 1..=buf.len() - n {
                c = r.roll(c, buf[pos - 1], buf[pos - 1 + n]);
                assert_eq!(c, crc32(&buf[pos..pos + n]), "window {n} pos {pos}");
            }
        }
        assert!(RollingCrc32::new(0).is_none());
    }
}
