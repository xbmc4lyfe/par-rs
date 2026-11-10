//! Scalar arithmetic in GF(2^16) with the PAR2 generator polynomial `0x1100B`.
//!
//! The field is represented with 16-bit little-endian words as they appear inside PAR2
//! slices. `alpha = 2` is a primitive element, so every non-zero value `v` has a discrete
//! logarithm `log(v)` with `v == exp(log(v))` and multiplication reduces to table lookups.
//!
//! Besides the basic operations this module provides:
//!
//! * [`input_constants`]—the per-input-slice constants mandated by the PAR2 specification
//!   (powers of two whose exponent is coprime with 65535),
//! * [`MulTables`]—two 256-entry tables that multiply any word by a fixed coefficient with
//!   two lookups (the scalar kernel used for tails and as the reference implementation),
//! * [`ShuffleTables`]—the eight 16-byte nibble tables consumed by the SIMD kernels in
//!   [`crate::gf16::simd`].

pub mod simd;

use std::sync::OnceLock;

/// The PAR2 generator polynomial `x^16 + x^15 + x^13 + x^4 + 1`.
pub const GENERATOR: u32 = 0x1100B;

/// Multiplicative group order (`2^16 - 1`).
pub const ORDER: u32 = 65535;

/// Primitive element used for the log/antilog tables.
pub const ALPHA: u16 = 2;

/// Log and antilog tables.
pub struct Tables {
    log: Box<[u16; 65536]>,
    /// `exp[i] = alpha^i` for `i in 0..2*ORDER` (doubled so that `log(a)+log(b)` needs no modulo).
    exp: Box<[u16; 131_070]>,
}

impl Tables {
    fn build() -> Self {
        let mut log = Box::new([0u16; 65536]);
        let mut exp = Box::new([0u16; 131_070]);
        let mut v: u32 = 1;
        for i in 0..ORDER as usize {
            exp[i] = v as u16;
            exp[i + ORDER as usize] = v as u16;
            log[v as usize] = i as u16;
            v <<= 1;
            if v & 0x10000 != 0 {
                v ^= GENERATOR;
            }
        }
        debug_assert_eq!(v, 1, "alpha must have order 65535");
        Self { log, exp }
    }

    /// `log(v)`; `log(0)` is undefined and returns 0.
    #[inline(always)]
    pub fn log(&self, v: u16) -> u16 {
        self.log[v as usize]
    }

    /// `alpha^e` for `e < 2 * ORDER`.
    #[inline(always)]
    pub fn exp(&self, e: u32) -> u16 {
        self.exp[e as usize]
    }
}

static TABLES: OnceLock<Tables> = OnceLock::new();

/// Shared log/antilog tables (built on first use).
#[inline]
pub fn tables() -> &'static Tables {
    TABLES.get_or_init(Tables::build)
}

/// Addition (and subtraction) in GF(2^16).
#[inline(always)]
pub const fn add(a: u16, b: u16) -> u16 {
    a ^ b
}

/// Multiplication via log tables.
#[inline]
pub fn mul(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp(t.log(a) as u32 + t.log(b) as u32)
}

/// Multiplication by shift-and-add; independent of the tables (used to validate them).
pub const fn mul_slow(mut a: u16, mut b: u16) -> u16 {
    let mut r: u32 = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a as u32;
        }
        b >>= 1;
        let mut a2 = (a as u32) << 1;
        if a2 & 0x10000 != 0 {
            a2 ^= GENERATOR;
        }
        a = a2 as u16;
    }
    r as u16
}

/// Multiplicative inverse. `inv(0)` is undefined and returns 0.
#[inline]
pub fn inv(a: u16) -> u16 {
    if a == 0 {
        return 0;
    }
    let t = tables();
    t.exp(ORDER - t.log(a) as u32)
}

/// Division `a / b`. Division by zero returns 0.
#[inline]
pub fn div(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp(t.log(a) as u32 + ORDER - t.log(b) as u32)
}

/// Exponentiation `a^e` (with `0^0 == 1`).
#[inline]
pub fn pow(a: u16, e: u32) -> u16 {
    if e == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }
    let t = tables();
    let l = (t.log(a) as u64 * e as u64) % ORDER as u64;
    t.exp(l as u32)
}

/// `alpha^e` for any `e`.
#[inline]
pub fn alpha_pow(e: u32) -> u16 {
    tables().exp(e % ORDER)
}

/// Returned by [`input_constants`] when a recovery set has more than 32768 input slices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooManyInputSlices;

impl std::fmt::Display for TooManyInputSlices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("too many input slices for the PAR2 Reed-Solomon code (maximum 32768)")
    }
}

impl std::error::Error for TooManyInputSlices {}

/// Whether `logbase` is a valid PAR2 input-constant exponent (coprime with 65535).
#[inline]
pub const fn is_valid_logbase(logbase: u32) -> bool {
    !logbase.is_multiple_of(3)
        && !logbase.is_multiple_of(5)
        && !logbase.is_multiple_of(17)
        && !logbase.is_multiple_of(257)
}

/// The logarithms (base `alpha`) of the first `count` input-slice constants.
pub fn input_constant_logs(count: usize) -> Result<Vec<u16>, TooManyInputSlices> {
    if count > 32768 {
        return Err(TooManyInputSlices);
    }
    let mut out = Vec::with_capacity(count);
    let mut logbase: u32 = 0;
    while out.len() < count {
        while !is_valid_logbase(logbase) {
            logbase += 1;
        }
        if logbase >= ORDER {
            return Err(TooManyInputSlices);
        }
        out.push(logbase as u16);
        logbase += 1;
    }
    Ok(out)
}

/// The constants assigned to the first `count` input slices of a PAR2 recovery set
/// (`2, 4, 16, 128, 256, 2048, 8192, 16384, ...`).
pub fn input_constants(count: usize) -> Result<Vec<u16>, TooManyInputSlices> {
    let logs = input_constant_logs(count)?;
    let t = tables();
    Ok(logs.into_iter().map(|l| t.exp(l as u32)).collect())
}

/// Coefficient of input slice with constant-log `logbase` in the recovery slice with
/// exponent `exponent`: `(alpha^logbase)^exponent`.
#[inline]
pub fn rs_coefficient(logbase: u16, exponent: u32) -> u16 {
    let l = (logbase as u64 * exponent as u64) % ORDER as u64;
    tables().exp(l as u32)
}

// ---------------------------------------------------------------------------------------------
// Tables for multiplication by a constant
// ---------------------------------------------------------------------------------------------

/// Byte-split multiplication tables for a fixed coefficient:
/// `mul(c, w) == lo[w & 0xFF] ^ hi[w >> 8]`.
#[derive(Clone)]
pub struct MulTables {
    /// Products of the coefficient with `0..256`.
    pub lo: [u16; 256],
    /// Products of the coefficient with `(0..256) << 8`.
    pub hi: [u16; 256],
    coeff: u16,
}

impl MulTables {
    /// Build the tables for `coeff`.
    pub fn new(coeff: u16) -> Self {
        let mut lo = [0u16; 256];
        let mut hi = [0u16; 256];
        if coeff != 0 {
            let t = tables();
            let lc = t.log(coeff) as u32;
            for i in 1..256u32 {
                lo[i as usize] = t.exp(lc + t.log(i as u16) as u32);
                hi[i as usize] = t.exp(lc + t.log((i << 8) as u16) as u32);
            }
        }
        Self { lo, hi, coeff }
    }

    /// The coefficient these tables multiply by.
    #[inline]
    pub fn coeff(&self) -> u16 {
        self.coeff
    }

    /// `coeff * w`.
    #[inline(always)]
    pub fn mul(&self, w: u16) -> u16 {
        self.lo[(w & 0xFF) as usize] ^ self.hi[(w >> 8) as usize]
    }

    /// `coeff * word(lo_byte, hi_byte)`.
    #[inline(always)]
    pub fn mul_bytes(&self, lo: u8, hi: u8) -> u16 {
        self.lo[lo as usize] ^ self.hi[hi as usize]
    }
}

/// Scalar `dst ^= coeff * src` on natural little-endian 16-bit layout.
/// Lengths must be equal; an odd trailing byte is treated as the low byte of a word whose
/// high byte is zero (only the low result byte is stored).
pub fn mul_acc_scalar(dst: &mut [u8], src: &[u8], tables: &MulTables) {
    assert_eq!(dst.len(), src.len(), "mul_acc: length mismatch");
    let (d, dr) = dst.as_chunks_mut::<2>();
    let (s, sr) = src.as_chunks::<2>();
    for (dw, sw) in d.iter_mut().zip(s) {
        let p = tables.mul_bytes(sw[0], sw[1]);
        dw[0] ^= p as u8;
        dw[1] ^= (p >> 8) as u8;
    }
    if let (Some(dl), Some(&sl)) = (dr.first_mut(), sr.first()) {
        *dl ^= tables.mul_bytes(sl, 0) as u8;
    }
}

/// Scalar `dst ^= coeff * src` on split (de-interleaved) planes.
pub fn mul_acc_split_scalar(
    dst_lo: &mut [u8],
    dst_hi: &mut [u8],
    src_lo: &[u8],
    src_hi: &[u8],
    tables: &MulTables,
) {
    let n = dst_lo.len();
    assert!(
        dst_hi.len() == n && src_lo.len() == n && src_hi.len() == n,
        "mul_acc_split: length mismatch"
    );
    for i in 0..n {
        let p = tables.mul_bytes(src_lo[i], src_hi[i]);
        dst_lo[i] ^= p as u8;
        dst_hi[i] ^= (p >> 8) as u8;
    }
}

/// Nibble shuffle tables for the SIMD kernels.
///
/// For nibble position `k` (0 = bits 0..4 of the low byte, 3 = bits 4..8 of the high byte)
/// and nibble value `v`, `lo[k][v]` / `hi[k][v]` are the low / high byte of
/// `coeff * (v << (4 * k))`. The product of a whole word is the XOR of its four nibble terms.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct ShuffleTables {
    /// Low result bytes, indexed `[nibble position][nibble value]`.
    pub lo: [[u8; 16]; 4],
    /// High result bytes, indexed `[nibble position][nibble value]`.
    pub hi: [[u8; 16]; 4],
    coeff: u16,
}

impl ShuffleTables {
    /// Build the tables for `coeff`.
    pub fn new(coeff: u16) -> Self {
        let mut lo = [[0u8; 16]; 4];
        let mut hi = [[0u8; 16]; 4];
        if coeff != 0 {
            let t = tables();
            let lc = t.log(coeff) as u32;
            for k in 0..4 {
                for v in 1..16u32 {
                    let word = (v << (4 * k)) as u16;
                    let p = t.exp(lc + t.log(word) as u32);
                    lo[k][v as usize] = p as u8;
                    hi[k][v as usize] = (p >> 8) as u8;
                }
            }
        }
        Self { lo, hi, coeff }
    }

    /// The coefficient these tables multiply by.
    #[inline]
    pub fn coeff(&self) -> u16 {
        self.coeff
    }

    /// Reference evaluation: `coeff * w` through the nibble tables.
    pub fn mul(&self, w: u16) -> u16 {
        let n = [
            (w & 0xF) as usize,
            ((w >> 4) & 0xF) as usize,
            ((w >> 8) & 0xF) as usize,
            (w >> 12) as usize,
        ];
        let mut lo = 0u8;
        let mut hi = 0u8;
        for (k, &nk) in n.iter().enumerate() {
            lo ^= self.lo[k][nk];
            hi ^= self.hi[k][nk];
        }
        lo as u16 | (hi as u16) << 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_match_slow_multiplication() {
        let samples: [u16; 9] = [0, 1, 2, 3, 0x1234, 0x8000, 0xFFFF, 0x1100 ^ 0xB, 0x7F7F];
        for &a in &samples {
            for &b in &samples {
                assert_eq!(mul(a, b), mul_slow(a, b), "{a:#x} * {b:#x}");
            }
        }
        // Exhaustive for one operand.
        for b in 0..=0xFFFFu32 {
            assert_eq!(mul(0xABCD, b as u16), mul_slow(0xABCD, b as u16));
        }
    }

    #[test]
    fn field_axioms() {
        for a in [1u16, 2, 0x1234, 0xFFFF, 0x8001] {
            assert_eq!(mul(a, inv(a)), 1);
            assert_eq!(div(a, a), 1);
            assert_eq!(div(mul(a, 0x4321), 0x4321), a);
            assert_eq!(pow(a, 0), 1);
            assert_eq!(pow(a, 1), a);
            assert_eq!(pow(a, 2), mul(a, a));
            assert_eq!(pow(a, 65535), 1);
            assert_eq!(pow(a, 65536), a);
        }
        assert_eq!(inv(0), 0);
        assert_eq!(div(5, 0), 0);
        assert_eq!(pow(0, 5), 0);
        assert_eq!(pow(0, 0), 1);
        assert_eq!(alpha_pow(0), 1);
        assert_eq!(alpha_pow(1), 2);
        assert_eq!(alpha_pow(65535), 1);
    }

    #[test]
    fn par2_input_constants() {
        // First 11 constants from the PAR2 specification: 2, 4, 16, 128, 256, 2048, 8192, 16384, 4107, 32856, 17132.
        let c = input_constants(11).unwrap();
        assert_eq!(
            c,
            vec![2, 4, 16, 128, 256, 2048, 8192, 16384, 4107, 32856, 17132]
        );
        let logs = input_constant_logs(5).unwrap();
        assert_eq!(logs, vec![1, 2, 4, 7, 8]);
        let all = input_constants(32768).unwrap();
        assert_eq!(all.len(), 32768);
        // All constants have full multiplicative order (distinct and primitive).
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 32768);
        assert_eq!(input_constants(32769), Err(TooManyInputSlices));
        assert_eq!(rs_coefficient(logs[3], 3), pow(128, 3));
        assert_eq!(rs_coefficient(logs[1], 70000), pow(4, 70000));
    }

    #[test]
    fn mul_tables_and_shuffle_tables() {
        for coeff in [0u16, 1, 2, 0x1234, 0xFFFF, 0x8000] {
            let mt = MulTables::new(coeff);
            let st = ShuffleTables::new(coeff);
            assert_eq!(mt.coeff(), coeff);
            assert_eq!(st.coeff(), coeff);
            for w in [0u16, 1, 0xFF, 0x100, 0x1234, 0xFFFF, 0xF0F0, 0x0F0F] {
                assert_eq!(mt.mul(w), mul(coeff, w));
                assert_eq!(st.mul(w), mul(coeff, w));
            }
        }
    }

    #[test]
    fn scalar_mul_acc_kernels() {
        let coeff = 0x3456u16;
        let mt = MulTables::new(coeff);
        let src: Vec<u8> = (0..=255u8).cycle().take(1001).collect();
        let mut dst: Vec<u8> = (0..1001).map(|i| (i * 7 % 251) as u8).collect();
        let orig = dst.clone();
        mul_acc_scalar(&mut dst, &src, &mt);
        for i in 0..500 {
            let s = u16::from_le_bytes([src[2 * i], src[2 * i + 1]]);
            let d = u16::from_le_bytes([orig[2 * i], orig[2 * i + 1]]);
            let got = u16::from_le_bytes([dst[2 * i], dst[2 * i + 1]]);
            assert_eq!(got, d ^ mul(coeff, s));
        }
        // Odd trailing byte: treated as low byte of a word with zero high byte.
        assert_eq!(dst[1000], orig[1000] ^ (mul(coeff, src[1000] as u16) as u8));

        // Split layout equivalence.
        let n = 500;
        let (slo, shi): (Vec<u8>, Vec<u8>) = (0..n).map(|i| (src[2 * i], src[2 * i + 1])).unzip();
        let (mut dlo, mut dhi): (Vec<u8>, Vec<u8>) =
            (0..n).map(|i| (orig[2 * i], orig[2 * i + 1])).unzip();
        mul_acc_split_scalar(&mut dlo, &mut dhi, &slo, &shi, &mt);
        for i in 0..n {
            assert_eq!(dlo[i], dst[2 * i]);
            assert_eq!(dhi[i], dst[2 * i + 1]);
        }
    }
}
