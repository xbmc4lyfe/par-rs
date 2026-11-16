//! IEEE 802.3 CRC-32 (reflected, polynomial `0xEDB88320`) as used by PAR2 and yEnc.
//!
//! This module provides:
//!
//! * A streaming [`Crc32`] hasher with hardware acceleration (`pclmulqdq` folding on
//!   `x86_64`; `pmull` folding on `AArch64`, or the `crc32x` instructions where the CPU has
//!   no `pmull`) and a slice-by-8 table fallback.
//! * GF(2) polynomial arithmetic on CRC registers: [`crc32_combine`], [`crc32_zeros`],
//!   [`crc32_of_zeros`] and [`crc32_shift_raw`], implemented via `x^n mod P(x)` exponentiation
//!   in `O(log n)` so that CRCs of concatenations and zero-extensions can be computed
//!   without touching the data.
//! * [`WindowTable`], the precomputed byte-removal table that lets a fixed-size window
//!   CRC be slid by one byte in `O(1)` (used by the sliding block scanner).
//!
//! Terminology: the *raw register* is the internal 32-bit shift register, which starts at
//! `0xFFFF_FFFF` and is complemented to produce the *final* CRC value. All `*_raw`
//! functions operate on the register; everything else uses final CRC values.

use std::sync::OnceLock;

/// Reflected IEEE CRC-32 generator polynomial.
pub const POLY: u32 = 0xEDB8_8320;

/// Initial register value and final XOR value.
pub const INIT: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------------------------
// Table generation (compile time)
// ---------------------------------------------------------------------------------------------

const fn make_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut k = 1;
    while k < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[k - 1][i];
            t[k][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            i += 1;
        }
        k += 1;
    }
    t
}

/// Slice-by-8 lookup tables. `TABLES[0]` is the classic byte-at-a-time table.
pub static TABLES: [[u32; 256]; 8] = make_tables();

// ---------------------------------------------------------------------------------------------
// Software kernels
// ---------------------------------------------------------------------------------------------

/// Process one byte through the raw register.
#[inline(always)]
#[must_use]
pub fn update_byte_raw(state: u32, byte: u8) -> u32 {
    (state >> 8) ^ TABLES[0][((state ^ u32::from(byte)) & 0xFF) as usize]
}

/// Slice-by-8 software update of the raw register.
#[must_use]
pub fn update_slice8_raw(mut crc: u32, data: &[u8]) -> u32 {
    let (chunks, remainder) = data.as_chunks::<8>();
    for c in chunks {
        let lo = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ crc;
        let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        crc = TABLES[7][(lo & 0xFF) as usize]
            ^ TABLES[6][((lo >> 8) & 0xFF) as usize]
            ^ TABLES[5][((lo >> 16) & 0xFF) as usize]
            ^ TABLES[4][(lo >> 24) as usize]
            ^ TABLES[3][(hi & 0xFF) as usize]
            ^ TABLES[2][((hi >> 8) & 0xFF) as usize]
            ^ TABLES[1][((hi >> 16) & 0xFF) as usize]
            ^ TABLES[0][(hi >> 24) as usize];
    }
    for &b in remainder {
        crc = update_byte_raw(crc, b);
    }
    crc
}

// ---------------------------------------------------------------------------------------------
// `GF(2)[x] / P(x)` arithmetic on reflected 32-bit registers
// ---------------------------------------------------------------------------------------------

/// Multiply two polynomials modulo P(x), both in reflected representation
/// (bit 31 is `x^0`, bit 0 is `x^31`). Equivalent to zlib's `multmodp`.
#[inline]
#[must_use]
pub const fn multmodp(a: u32, b: u32) -> u32 {
    let mut m: u32 = 1 << 31;
    let mut p: u32 = 0;
    let mut b = b;
    let mut i = 0;
    while i < 32 {
        if a & m != 0 {
            p ^= b;
        }
        m >>= 1;
        b = if b & 1 != 0 { (b >> 1) ^ POLY } else { b >> 1 };
        i += 1;
    }
    p
}

/// `x^(2^k) mod P(x)` for `k` in `0..32` (the sequence is periodic with period 32 because
/// `x` has multiplicative order `2^32 - 1`).
const fn make_x2n_table() -> [u32; 32] {
    let mut t = [0u32; 32];
    let mut p: u32 = 1 << 30; // x^1
    t[0] = p;
    let mut n = 1;
    while n < 32 {
        p = multmodp(p, p);
        t[n] = p;
        n += 1;
    }
    t
}

static X2N_TABLE: [u32; 32] = make_x2n_table();

/// `x^(n * 2^k) mod P(x)` in reflected representation. Equivalent to zlib's `x2nmodp`.
#[must_use]
pub fn x2nmodp(mut n: u64, mut k: u32) -> u32 {
    let mut p: u32 = 1 << 31; // x^0 == 1
    while n != 0 {
        if n & 1 != 0 {
            p = multmodp(X2N_TABLE[(k & 31) as usize], p);
        }
        n >>= 1;
        k += 1;
    }
    p
}

/// The linear operator that advances a raw register by `n_bytes` zero bytes, as a
/// polynomial (`x^(8 * n_bytes) mod P(x)`). Apply with [`multmodp`].
#[inline]
#[must_use]
pub fn zero_operator(n_bytes: u64) -> u32 {
    x2nmodp(n_bytes, 3)
}

/// Advance a raw register through `n_bytes` zero bytes: `L^n(state)`.
#[inline]
#[must_use]
pub fn crc32_shift_raw(state: u32, n_bytes: u64) -> u32 {
    multmodp(zero_operator(n_bytes), state)
}

/// Combine the CRC of `A` with the CRC of `B` to obtain the CRC of `A ‖ B`.
/// `len_b` is the length of `B` in bytes. Both inputs and the result are final CRC values.
#[inline]
#[must_use]
pub fn crc32_combine(crc_a: u32, crc_b: u32, len_b: u64) -> u32 {
    multmodp(zero_operator(len_b), crc_a) ^ crc_b
}

/// Precomputed combiner for repeatedly appending blocks of a fixed length
/// (for example, folding the IFSC per-slice CRCs of a whole file).
#[derive(Clone, Copy, Debug)]
pub struct Crc32Combiner {
    op: u32,
    len: u64,
}

impl Crc32Combiner {
    /// Create a combiner for blocks of `len_b` bytes.
    #[must_use]
    pub fn new(len_b: u64) -> Self {
        Self {
            op: zero_operator(len_b),
            len: len_b,
        }
    }

    /// Block length this combiner was built for.
    #[must_use]
    pub fn block_len(&self) -> u64 {
        self.len
    }

    /// CRC of `A ‖ B` given `crc(A)` and `crc(B)` where `|B| == block_len()`.
    #[inline]
    #[must_use]
    pub fn combine(&self, crc_a: u32, crc_b: u32) -> u32 {
        multmodp(self.op, crc_a) ^ crc_b
    }
}

/// CRC of `n` zero bytes.
#[must_use]
pub fn crc32_of_zeros(n: u64) -> u32 {
    crc32_shift_raw(INIT, n) ^ INIT
}

/// CRC of `data ‖ 0^n` given `crc = crc32(data)`.
#[must_use]
pub fn crc32_zeros(crc: u32, n: u64) -> u32 {
    crc32_shift_raw(crc ^ INIT, n) ^ INIT
}

/// Combine consecutive per-block CRCs (each block exactly `block_len` bytes) into the CRC
/// of the concatenation. Returns `0` for an empty slice (CRC of empty data).
#[must_use]
pub fn combine_block_crcs(crcs: &[u32], block_len: u64) -> u32 {
    let mut it = crcs.iter();
    let Some(&first) = it.next() else {
        return 0;
    };
    let comb = Crc32Combiner::new(block_len);
    it.fold(first, |acc, &c| comb.combine(acc, c))
}

// ---------------------------------------------------------------------------------------------
// Hardware kernels
// ---------------------------------------------------------------------------------------------

// Folding constants for reflected CRC-32 carry-less multiply folding (`pclmulqdq` on `x86_64`,
// `pmull` on `AArch64`; Intel white paper "Fast CRC Computation for Generic Polynomials Using
// PCLMULQDQ Instruction"). Each constant is `bitreverse(x^N mod P(x)) << 1`.

/// Carry-less 32x32 multiply reduced modulo the non-reflected polynomial `0x104C11DB7`.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const fn gf2_mulmod(a: u32, b: u32) -> u32 {
    let mut r: u64 = 0;
    let mut i = 0;
    while i < 32 {
        if (b >> i) & 1 == 1 {
            r ^= (a as u64) << i;
        }
        i += 1;
    }
    let mut bit = 63;
    while bit >= 32 {
        if (r >> bit) & 1 == 1 {
            r ^= 0x1_04C1_1DB7u64 << (bit - 32);
        }
        bit -= 1;
    }
    r as u32
}

/// `x^n mod P(x)` in non-reflected representation (bit 0 is `x^0`).
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const fn xpow_mod(n: u32) -> u32 {
    let mut result: u32 = 1;
    let mut base: u32 = 2;
    let mut e = n;
    while e > 0 {
        if e & 1 == 1 {
            result = gf2_mulmod(result, base);
        }
        base = gf2_mulmod(base, base);
        e >>= 1;
    }
    result
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const fn fold_constant(n: u32) -> u64 {
    (xpow_mod(n).reverse_bits() as u64) << 1
}

#[cfg(target_arch = "aarch64")]
mod hw {
    /// Combine three raw registers computed over consecutive segments `A ‖ B ‖ C`, where
    /// `a` started from the real state and `b`, `c` started from a zero register.
    #[inline]
    fn join3(a: u32, b: u32, c: u32, len_b: u64, len_c: u64) -> u32 {
        super::multmodp(super::zero_operator(len_b + len_c), a)
            ^ super::multmodp(super::zero_operator(len_c), b)
            ^ c
    }

    #[target_feature(enable = "crc")]
    unsafe fn crc32_stream(mut crc: u32, data: &[u8]) -> u32 {
        use core::arch::aarch64::{__crc32b, __crc32d};
        let (chunks, remainder) = data.as_chunks::<8>();
        for c in chunks {
            crc = __crc32d(crc, u64::from_le_bytes(*c));
        }
        for &b in remainder {
            crc = __crc32b(crc, b);
        }
        crc
    }

    /// Three interleaved `crc32x` streams to hide the 3-cycle latency of the instruction.
    #[target_feature(enable = "crc")]
    unsafe fn crc32_3way(state: u32, data: &[u8]) -> u32 {
        use core::arch::aarch64::__crc32d;
        let third = (data.len() / 24) * 8;
        let (p0, rest) = data.split_at(third);
        let (p1, rest) = rest.split_at(third);
        let (p2, tail) = rest.split_at(third);
        let (mut a, mut b, mut c) = (state, 0u32, 0u32);
        let n = third / 8;
        for i in 0..n {
            let o = i * 8;
            // SAFETY: `o + 8 <= third` for each of the three equal-length parts.
            let (w0, w1, w2) = unsafe {
                (
                    u64::from_le_bytes(p0.get_unchecked(o..o + 8).try_into().unwrap()),
                    u64::from_le_bytes(p1.get_unchecked(o..o + 8).try_into().unwrap()),
                    u64::from_le_bytes(p2.get_unchecked(o..o + 8).try_into().unwrap()),
                )
            };
            a = __crc32d(a, w0);
            b = __crc32d(b, w1);
            c = __crc32d(c, w2);
        }
        let joined = join3(a, b, c, third as u64, third as u64);
        // SAFETY: same feature requirement as this function.
        unsafe { crc32_stream(joined, tail) }
    }

    /// Fold constants for eight 128-bit accumulators (1024 bits apart) and for one.
    const K_FOLD8: [u64; 2] = [
        super::fold_constant(8 * 128 + 32),
        super::fold_constant(8 * 128 - 32),
    ];
    const K_FOLD1: [u64; 2] = [
        super::fold_constant(128 + 32),
        super::fold_constant(128 - 32),
    ];

    /// Shortest input [`crc32_pmull`] handles. On an Apple M4 it beats one `crc32x` stream from
    /// here up (40 vs 20 GB/s at 128 bytes, 57 vs 11 GB/s at 1 KiB) and the three-stream
    /// kernel at every size (about 60 vs 31 GB/s); see `examples/cpu_paths.rs`.
    pub(super) const PMULL_MIN: usize = 128;

    /// `x` folded forward by the distance `k` encodes, plus `next`.
    #[inline(always)]
    unsafe fn fold(
        x: core::arch::aarch64::uint64x2_t,
        k: core::arch::aarch64::poly64x2_t,
        next: core::arch::aarch64::uint64x2_t,
    ) -> core::arch::aarch64::uint64x2_t {
        use core::arch::aarch64::*;
        // SAFETY: the caller enables `aes` (which provides `pmull`).
        unsafe {
            let xp = vreinterpretq_p64_u64(x);
            let lo = vmull_p64(vgetq_lane_p64::<0>(xp), vgetq_lane_p64::<0>(k));
            let hi = vmull_high_p64(xp, k);
            veorq_u64(
                veorq_u64(vreinterpretq_u64_p128(lo), vreinterpretq_u64_p128(hi)),
                next,
            )
        }
    }

    /// Carry-less multiply folding over eight 128-bit accumulators (128 bytes per round),
    /// reduced to the register with two `crc32x` instructions. `data.len() >= 128`.
    #[target_feature(enable = "crc,aes")]
    unsafe fn crc32_pmull(state: u32, data: &[u8]) -> u32 {
        use core::arch::aarch64::*;
        debug_assert!(data.len() >= 128);
        let (blocks, tail) = data.as_chunks::<16>();
        // SAFETY: every load reads one complete 16-byte block of `data`; the caller enables
        // `crc` and `aes`.
        unsafe {
            let load = |b: &[u8; 16]| vreinterpretq_u64_u8(vld1q_u8(b.as_ptr()));
            let (head, rest) = blocks.split_at(8);
            let mut acc: [uint64x2_t; 8] = core::array::from_fn(|i| load(&head[i]));
            acc[0] = veorq_u64(
                acc[0],
                vsetq_lane_u64::<0>(u64::from(state), vdupq_n_u64(0)),
            );
            let k8 = vreinterpretq_p64_u64(vld1q_u64(K_FOLD8.as_ptr()));
            let (rounds, rest) = rest.as_chunks::<8>();
            for round in rounds {
                for (a, b) in acc.iter_mut().zip(round) {
                    *a = fold(*a, k8, load(b));
                }
            }
            let k1 = vreinterpretq_p64_u64(vld1q_u64(K_FOLD1.as_ptr()));
            let mut x = acc[0];
            for &a in &acc[1..] {
                x = fold(x, k1, a);
            }
            for b in rest {
                x = fold(x, k1, load(b));
            }
            let crc = __crc32d(0, vgetq_lane_u64::<0>(x));
            let crc = __crc32d(crc, vgetq_lane_u64::<1>(x));
            crc32_stream(crc, tail)
        }
    }

    pub fn available() -> bool {
        std::arch::is_aarch64_feature_detected!("crc")
    }

    /// Whether `pmull` (part of the `aes` extension) is available, detected once.
    pub(super) fn pmull_available() -> bool {
        static PMULL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *PMULL.get_or_init(|| std::arch::is_aarch64_feature_detected!("aes"))
    }

    pub fn update_raw(state: u32, data: &[u8]) -> u32 {
        // SAFETY: caller checked `available()`; `crc32_pmull` additionally needs `aes`.
        unsafe {
            if data.len() >= PMULL_MIN && pmull_available() {
                crc32_pmull(state, data)
            } else if data.len() >= 64 * 1024 {
                crc32_3way(state, data)
            } else {
                crc32_stream(state, data)
            }
        }
    }

    /// The three kernels, for tests that compare each against the reference.
    #[cfg(test)]
    pub(super) fn each_kernel(state: u32, data: &[u8]) -> Vec<(&'static str, u32)> {
        // SAFETY: `crc` is checked by the caller through `available()`; `aes` is checked here.
        unsafe {
            let mut out = vec![
                ("crc32x", crc32_stream(state, data)),
                ("crc32x 3-way", crc32_3way(state, data)),
            ];
            if data.len() >= 128 && pmull_available() {
                out.push(("pmull", crc32_pmull(state, data)));
            }
            out
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod hw {
    use super::fold_constant;

    pub(super) const K1: u64 = fold_constant(4 * 128 + 32);
    pub(super) const K2: u64 = fold_constant(4 * 128 - 32);
    pub(super) const K3: u64 = fold_constant(128 + 32);
    pub(super) const K4: u64 = fold_constant(128 - 32);
    pub(super) const K5: u64 = fold_constant(64);
    /// Reflected P(x) including the `x^32` term.
    pub(super) const PP: u64 = 0x1_DB71_0641;
    /// Barrett reduction constant `floor(x^64 / P(x))`, reflected.
    pub(super) const MU: u64 = 0x1_F701_1641;

    pub fn available() -> bool {
        std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("sse4.1")
    }

    #[target_feature(enable = "pclmulqdq,sse4.1,ssse3")]
    unsafe fn crc32_pclmul(crc: u32, data: &[u8]) -> u32 {
        use core::arch::x86_64::*;
        debug_assert!(data.len() >= 64);
        // SAFETY: caller guarantees the CPU features and `data.len() >= 64`; all pointer
        // arithmetic stays within `data`.
        unsafe {
            let mut p = data.as_ptr();
            let mut len = data.len();

            let k1k2 = _mm_set_epi64x(K2 as i64, K1 as i64);
            let k3k4 = _mm_set_epi64x(K4 as i64, K3 as i64);

            let mut x1 = _mm_loadu_si128(p as *const __m128i);
            let mut x2 = _mm_loadu_si128(p.add(16) as *const __m128i);
            let mut x3 = _mm_loadu_si128(p.add(32) as *const __m128i);
            let mut x4 = _mm_loadu_si128(p.add(48) as *const __m128i);
            x1 = _mm_xor_si128(x1, _mm_cvtsi32_si128(crc as i32));
            p = p.add(64);
            len -= 64;

            while len >= 64 {
                let x5 = _mm_clmulepi64_si128(x1, k1k2, 0x00);
                let x6 = _mm_clmulepi64_si128(x2, k1k2, 0x00);
                let x7 = _mm_clmulepi64_si128(x3, k1k2, 0x00);
                let x8 = _mm_clmulepi64_si128(x4, k1k2, 0x00);
                x1 = _mm_clmulepi64_si128(x1, k1k2, 0x11);
                x2 = _mm_clmulepi64_si128(x2, k1k2, 0x11);
                x3 = _mm_clmulepi64_si128(x3, k1k2, 0x11);
                x4 = _mm_clmulepi64_si128(x4, k1k2, 0x11);
                let y5 = _mm_loadu_si128(p as *const __m128i);
                let y6 = _mm_loadu_si128(p.add(16) as *const __m128i);
                let y7 = _mm_loadu_si128(p.add(32) as *const __m128i);
                let y8 = _mm_loadu_si128(p.add(48) as *const __m128i);
                x1 = _mm_xor_si128(_mm_xor_si128(x1, x5), y5);
                x2 = _mm_xor_si128(_mm_xor_si128(x2, x6), y6);
                x3 = _mm_xor_si128(_mm_xor_si128(x3, x7), y7);
                x4 = _mm_xor_si128(_mm_xor_si128(x4, x8), y8);
                p = p.add(64);
                len -= 64;
            }

            // Fold the four 128-bit lanes into one.
            let x5 = _mm_clmulepi64_si128(x1, k3k4, 0x00);
            x1 = _mm_clmulepi64_si128(x1, k3k4, 0x11);
            x1 = _mm_xor_si128(_mm_xor_si128(x1, x2), x5);
            let x5 = _mm_clmulepi64_si128(x1, k3k4, 0x00);
            x1 = _mm_clmulepi64_si128(x1, k3k4, 0x11);
            x1 = _mm_xor_si128(_mm_xor_si128(x1, x3), x5);
            let x5 = _mm_clmulepi64_si128(x1, k3k4, 0x00);
            x1 = _mm_clmulepi64_si128(x1, k3k4, 0x11);
            x1 = _mm_xor_si128(_mm_xor_si128(x1, x4), x5);

            finish(x1, p, len)
        }
    }

    /// Fold the remaining `len` bytes at `p` into the 128-bit remainder `x1`, reduce it to the
    /// register and run the last bytes through the table kernel.
    ///
    /// # Safety
    /// Only inlined into functions that enable `pclmulqdq,sse4.1,ssse3`; `p..p + len` must be
    /// readable.
    #[inline(always)]
    unsafe fn finish(mut x1: core::arch::x86_64::__m128i, mut p: *const u8, mut len: usize) -> u32 {
        use core::arch::x86_64::*;
        // SAFETY: as documented above.
        unsafe {
            let k3k4 = _mm_set_epi64x(K4 as i64, K3 as i64);
            let k5 = _mm_set_epi64x(0, K5 as i64);
            let poly = _mm_set_epi64x(MU as i64, PP as i64);
            let mask32 = _mm_set_epi32(0, -1, 0, -1);
            while len >= 16 {
                let y = _mm_loadu_si128(p as *const __m128i);
                let x5 = _mm_clmulepi64_si128(x1, k3k4, 0x00);
                x1 = _mm_clmulepi64_si128(x1, k3k4, 0x11);
                x1 = _mm_xor_si128(_mm_xor_si128(x1, y), x5);
                p = p.add(16);
                len -= 16;
            }

            // Fold 128 -> 64 bits.
            let x2 = _mm_clmulepi64_si128(x1, k3k4, 0x10);
            x1 = _mm_srli_si128(x1, 8);
            x1 = _mm_xor_si128(x1, x2);
            let x2 = _mm_srli_si128(x1, 4);
            x1 = _mm_and_si128(x1, mask32);
            x1 = _mm_clmulepi64_si128(x1, k5, 0x00);
            x1 = _mm_xor_si128(x1, x2);

            // Barrett reduction 64 -> 32 bits.
            let x2 = _mm_and_si128(x1, mask32);
            let x2 = _mm_clmulepi64_si128(x2, poly, 0x10);
            let x2 = _mm_and_si128(x2, mask32);
            let x2 = _mm_clmulepi64_si128(x2, poly, 0x00);
            x1 = _mm_xor_si128(x1, x2);
            let crc = _mm_extract_epi32(x1, 1) as u32;

            super::update_slice8_raw(crc, std::slice::from_raw_parts(p, len))
        }
    }

    /// `x` folded forward by the distance the per-128-bit-lane constants `k` encode, plus
    /// `next` (AVX-512, four lanes at once).
    #[inline(always)]
    unsafe fn fold512(
        x: core::arch::x86_64::__m512i,
        k: core::arch::x86_64::__m512i,
        next: core::arch::x86_64::__m512i,
    ) -> core::arch::x86_64::__m512i {
        use core::arch::x86_64::*;
        // SAFETY: only inlined into functions that enable `avx512f,vpclmulqdq`.
        unsafe {
            _mm512_ternarylogic_epi64::<0x96>(
                _mm512_clmulepi64_epi128::<0x00>(x, k),
                _mm512_clmulepi64_epi128::<0x11>(x, k),
                next,
            )
        }
    }

    /// As [`fold512`] for two 128-bit lanes (AVX2 with VPCLMULQDQ).
    #[inline(always)]
    unsafe fn fold256(
        x: core::arch::x86_64::__m256i,
        k: core::arch::x86_64::__m256i,
        next: core::arch::x86_64::__m256i,
    ) -> core::arch::x86_64::__m256i {
        use core::arch::x86_64::*;
        // SAFETY: only inlined into functions that enable `avx2,vpclmulqdq`.
        unsafe {
            _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_clmulepi64_epi128::<0x00>(x, k),
                    _mm256_clmulepi64_epi128::<0x11>(x, k),
                ),
                next,
            )
        }
    }

    /// As [`fold512`] for one 128-bit lane.
    #[inline(always)]
    unsafe fn fold128(
        x: core::arch::x86_64::__m128i,
        k: core::arch::x86_64::__m128i,
        next: core::arch::x86_64::__m128i,
    ) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::*;
        // SAFETY: only inlined into functions that enable `pclmulqdq`.
        unsafe {
            _mm_xor_si128(
                _mm_xor_si128(
                    _mm_clmulepi64_si128::<0x00>(x, k),
                    _mm_clmulepi64_si128::<0x11>(x, k),
                ),
                next,
            )
        }
    }

    /// The fold constants for a distance of `bits`, in one 128-bit lane.
    #[inline(always)]
    unsafe fn lane_constants(bits: u32) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::*;
        // SAFETY: SSE2 is a baseline x86_64 feature.
        unsafe {
            _mm_set_epi64x(
                fold_constant(bits - 32) as i64,
                fold_constant(bits + 32) as i64,
            )
        }
    }

    /// Carry-less multiply folding over four 512-bit accumulators (256 bytes per round).
    /// `data.len() >= 256`.
    #[target_feature(enable = "avx512f,vpclmulqdq,pclmulqdq,sse4.1,ssse3")]
    unsafe fn crc32_vpclmul512(crc: u32, data: &[u8]) -> u32 {
        use core::arch::x86_64::*;
        debug_assert!(data.len() >= 256);
        // SAFETY: the caller guarantees the CPU features and `data.len() >= 256`; every load
        // reads within `data`.
        unsafe {
            let mut p = data.as_ptr();
            let mut len = data.len();
            let load = |q: *const u8| _mm512_loadu_si512(q as *const __m512i);
            let mut x = [load(p), load(p.add(64)), load(p.add(128)), load(p.add(192))];
            x[0] = _mm512_xor_si512(x[0], _mm512_zextsi128_si512(_mm_cvtsi32_si128(crc as i32)));
            p = p.add(256);
            len -= 256;
            let k2048 = _mm512_broadcast_i32x4(lane_constants(2048));
            while len >= 256 {
                for (i, xi) in x.iter_mut().enumerate() {
                    *xi = fold512(*xi, k2048, load(p.add(64 * i)));
                }
                p = p.add(256);
                len -= 256;
            }
            let k512 = _mm512_broadcast_i32x4(lane_constants(512));
            let y = fold512(fold512(fold512(x[0], k512, x[1]), k512, x[2]), k512, x[3]);
            let k128 = lane_constants(128);
            let mut x1 = _mm512_extracti32x4_epi32::<0>(y);
            x1 = fold128(x1, k128, _mm512_extracti32x4_epi32::<1>(y));
            x1 = fold128(x1, k128, _mm512_extracti32x4_epi32::<2>(y));
            x1 = fold128(x1, k128, _mm512_extracti32x4_epi32::<3>(y));
            finish(x1, p, len)
        }
    }

    /// Carry-less multiply folding over four 256-bit accumulators (128 bytes per round).
    /// `data.len() >= 128`.
    #[target_feature(enable = "avx2,vpclmulqdq,pclmulqdq,sse4.1,ssse3")]
    unsafe fn crc32_vpclmul256(crc: u32, data: &[u8]) -> u32 {
        use core::arch::x86_64::*;
        debug_assert!(data.len() >= 128);
        // SAFETY: the caller guarantees the CPU features and `data.len() >= 128`; every load
        // reads within `data`.
        unsafe {
            let mut p = data.as_ptr();
            let mut len = data.len();
            let load = |q: *const u8| _mm256_loadu_si256(q as *const __m256i);
            let mut x = [load(p), load(p.add(32)), load(p.add(64)), load(p.add(96))];
            x[0] = _mm256_xor_si256(x[0], _mm256_zextsi128_si256(_mm_cvtsi32_si128(crc as i32)));
            p = p.add(128);
            len -= 128;
            let k1024 = _mm256_broadcastsi128_si256(lane_constants(1024));
            while len >= 128 {
                for (i, xi) in x.iter_mut().enumerate() {
                    *xi = fold256(*xi, k1024, load(p.add(32 * i)));
                }
                p = p.add(128);
                len -= 128;
            }
            let k256 = _mm256_broadcastsi128_si256(lane_constants(256));
            let y = fold256(fold256(fold256(x[0], k256, x[1]), k256, x[2]), k256, x[3]);
            let x1 = fold128(
                _mm256_extracti128_si256::<0>(y),
                lane_constants(128),
                _mm256_extracti128_si256::<1>(y),
            );
            finish(x1, p, len)
        }
    }

    /// Shortest input for [`crc32_vpclmul512`] and [`crc32_vpclmul256`]: below it the 128-bit
    /// kernel's shorter reduction wins.
    pub(super) const VPCLMUL512_MIN: usize = 512;
    pub(super) const VPCLMUL256_MIN: usize = 256;

    /// Widest carry-less multiply available, detected once: 2 = 512-bit, 1 = 256-bit, 0 = none.
    fn vpclmul_width() -> u8 {
        static WIDTH: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
        *WIDTH.get_or_init(|| {
            use std::arch::is_x86_feature_detected as has;
            if !has!("vpclmulqdq") {
                0
            } else if has!("avx512f") {
                2
            } else if has!("avx2") {
                1
            } else {
                0
            }
        })
    }

    pub fn update_raw(state: u32, data: &[u8]) -> u32 {
        if data.len() < 64 {
            return super::update_slice8_raw(state, data);
        }
        // SAFETY: caller checked `available()` (`pclmulqdq`, `sse4.1`); the wider kernels are
        // only called when `vpclmul_width` found their features.
        unsafe {
            match vpclmul_width() {
                2 if data.len() >= VPCLMUL512_MIN => crc32_vpclmul512(state, data),
                1 | 2 if data.len() >= VPCLMUL256_MIN && is_avx2() => crc32_vpclmul256(state, data),
                _ => crc32_pclmul(state, data),
            }
        }
    }

    fn is_avx2() -> bool {
        std::arch::is_x86_feature_detected!("avx2")
    }

    /// Every kernel the CPU has, for tests that compare each against the reference.
    #[cfg(test)]
    pub(super) fn each_kernel(state: u32, data: &[u8]) -> Vec<(&'static str, u32)> {
        let mut out = Vec::new();
        // SAFETY: each kernel runs only when its features were detected and the input is long
        // enough for it.
        unsafe {
            if data.len() >= 64 {
                out.push(("pclmul", crc32_pclmul(state, data)));
            }
            if vpclmul_width() >= 1 && is_avx2() && data.len() >= 128 {
                out.push(("vpclmul256", crc32_vpclmul256(state, data)));
            }
            if vpclmul_width() == 2 && data.len() >= 256 {
                out.push(("vpclmul512", crc32_vpclmul512(state, data)));
            }
        }
        out
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
mod hw {
    pub fn available() -> bool {
        false
    }
    pub fn update_raw(state: u32, data: &[u8]) -> u32 {
        super::update_slice8_raw(state, data)
    }
}

/// Which CRC kernel is in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrcKernel {
    /// Slice-by-8 table lookup.
    Software,
    /// `pclmulqdq` folding (`x86_64`), or `pmull` folding with `crc32x` instructions
    /// (`AArch64`; `crc32x` alone when the CPU has no `pmull`).
    Hardware,
}

static KERNEL: OnceLock<CrcKernel> = OnceLock::new();

/// The CRC kernel selected for this process (detected once; the table kernel when
/// [`crate::cpu::SIMD_ENV`] turns the CPU-specific paths off).
pub fn kernel() -> CrcKernel {
    *KERNEL.get_or_init(|| {
        if crate::cpu::simd_enabled() && hw::available() {
            CrcKernel::Hardware
        } else {
            CrcKernel::Software
        }
    })
}

/// Update a raw register with `data` using the fastest available kernel.
#[inline]
#[must_use]
pub fn update_raw(state: u32, data: &[u8]) -> u32 {
    match kernel() {
        CrcKernel::Hardware => hw::update_raw(state, data),
        CrcKernel::Software => update_slice8_raw(state, data),
    }
}

/// CRC-32 of `data`.
#[inline]
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    update_raw(INIT, data) ^ INIT
}

/// Streaming CRC-32 hasher.
#[derive(Clone, Copy, Debug)]
pub struct Crc32 {
    state: u32,
    len: u64,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// New hasher (empty input).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INIT,
            len: 0,
        }
    }

    /// Resume from a previously finished CRC value (the CRC of the data seen so far).
    #[must_use]
    pub const fn from_crc(crc: u32, len: u64) -> Self {
        Self {
            state: crc ^ INIT,
            len,
        }
    }

    /// Feed data.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.state = update_raw(self.state, data);
        self.len += data.len() as u64;
    }

    /// Feed `n` zero bytes without materialising them.
    pub fn update_zeros(&mut self, n: u64) {
        self.state = crc32_shift_raw(self.state, n);
        self.len += n;
    }

    /// Current CRC value (does not consume the hasher).
    #[inline]
    #[must_use]
    pub const fn finish(&self) -> u32 {
        self.state ^ INIT
    }

    /// Raw register value.
    #[must_use]
    pub const fn raw(&self) -> u32 {
        self.state
    }

    /// Number of bytes processed.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether no data has been processed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------------------------
// Sliding window
// ---------------------------------------------------------------------------------------------

/// Precomputed table for sliding a fixed-length window CRC by one byte.
///
/// If `r` is the raw register after processing bytes `w[0..n]`, then
/// `slide_raw(r, w[n], w[0])` is the raw register after processing `w[1..=n]`.
#[derive(Clone)]
pub struct WindowTable {
    window: u64,
    table: Box<[u32; 256]>,
}

impl WindowTable {
    /// Build the removal table for windows of `window` bytes (must be `>= 1`).
    #[must_use]
    pub fn new(window: u64) -> Self {
        assert!(window >= 1, "window must be at least one byte");
        let xn = zero_operator(window);
        // L^n(L(I) ^ I): the init-dependent correction term.
        let c = multmodp(xn, update_byte_raw(INIT, 0) ^ INIT);
        let mut table = Box::new([0u32; 256]);
        for (b, slot) in table.iter_mut().enumerate() {
            *slot = multmodp(xn, TABLES[0][b]) ^ c;
        }
        Self { window, table }
    }

    /// Window length in bytes.
    #[must_use]
    pub fn window(&self) -> u64 {
        self.window
    }

    /// Slide the raw register: append `new_byte`, remove `old_byte` (the byte that was
    /// exactly `window` bytes before `new_byte`).
    #[inline(always)]
    #[must_use]
    pub fn slide_raw(&self, state: u32, new_byte: u8, old_byte: u8) -> u32 {
        update_byte_raw(state, new_byte) ^ self.table[old_byte as usize]
    }

    /// Slide a final CRC value instead of a raw register.
    #[inline(always)]
    #[must_use]
    pub fn slide(&self, crc: u32, new_byte: u8, old_byte: u8) -> u32 {
        self.slide_raw(crc ^ INIT, new_byte, old_byte) ^ INIT
    }
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bitwise_crc(data: &[u8]) -> u32 {
        let mut c = INIT;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            }
        }
        c ^ INIT
    }

    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn kernels_agree_with_bitwise_reference() {
        for len in [
            0usize, 1, 7, 8, 15, 16, 63, 64, 65, 127, 128, 129, 143, 144, 255, 256, 257, 271, 383,
            384, 511, 512, 513, 527, 767, 768, 1000, 1023, 1024, 1025, 4096, 70_000, 200_001,
        ] {
            let data = pseudo_random(len, len as u64 + 1);
            let expect = bitwise_crc(&data);
            assert_eq!(
                update_slice8_raw(INIT, &data) ^ INIT,
                expect,
                "slice8 len={len}"
            );
            assert_eq!(crc32(&data), expect, "dispatch len={len}");
            if hw::available() {
                assert_eq!(hw::update_raw(INIT, &data) ^ INIT, expect, "hw len={len}");
                #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
                for (name, got) in hw::each_kernel(INIT, &data) {
                    assert_eq!(got ^ INIT, expect, "{name} len={len}");
                }
            }
            // Unaligned start.
            if len > 3 {
                assert_eq!(
                    crc32(&data[3..]),
                    bitwise_crc(&data[3..]),
                    "unaligned len={len}"
                );
            }
        }
    }

    /// Every hardware kernel the CPU reports actually runs, from every alignment and from a
    /// register other than the initial one.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn every_hardware_kernel_runs_from_any_alignment_and_state() {
        if !hw::available() {
            return;
        }
        let mut expected: Vec<&str> = Vec::new();
        #[cfg(target_arch = "aarch64")]
        {
            expected.extend(["crc32x", "crc32x 3-way"]);
            if std::arch::is_aarch64_feature_detected!("aes") {
                expected.push("pmull");
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::is_x86_feature_detected as has;
            expected.push("pclmul");
            if has!("vpclmulqdq") && has!("avx2") {
                expected.push("vpclmul256");
            }
            if has!("vpclmulqdq") && has!("avx512f") {
                expected.push("vpclmul512");
            }
        }
        let data = pseudo_random(5000, 99);
        for off in 0..16 {
            let slice = &data[off..];
            for state in [INIT, 0, 0x1234_5678] {
                let want = update_slice8_raw(state, slice);
                let got = hw::each_kernel(state, slice);
                let names: Vec<&str> = got.iter().map(|(n, _)| *n).collect();
                assert_eq!(names, expected, "kernels run");
                for (name, crc) in got {
                    assert_eq!(crc, want, "{name} offset {off} state {state:#x}");
                }
            }
        }
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data = pseudo_random(100_000, 7);
        let mut h = Crc32::new();
        let mut off = 0;
        for step in [1usize, 3, 64, 1000, 13, 4096, 90_000] {
            let end = (off + step).min(data.len());
            h.update(&data[off..end]);
            off = end;
        }
        h.update(&data[off..]);
        assert_eq!(h.finish(), crc32(&data));
        assert_eq!(h.len(), data.len() as u64);
    }

    #[test]
    fn combine_and_zeros() {
        let a = pseudo_random(1234, 1);
        let b = pseudo_random(4321, 2);
        let mut ab = a.clone();
        ab.extend_from_slice(&b);
        assert_eq!(
            crc32_combine(crc32(&a), crc32(&b), b.len() as u64),
            crc32(&ab)
        );
        assert_eq!(crc32_combine(crc32(&a), crc32(&[]), 0), crc32(&a));
        assert_eq!(crc32_combine(0, crc32(&b), b.len() as u64), crc32(&b));

        for n in [0u64, 1, 2, 3, 100, 65_536, 1_000_003] {
            let zeros = vec![0u8; n as usize];
            assert_eq!(crc32_of_zeros(n), crc32(&zeros), "zeros n={n}");
            let mut az = a.clone();
            az.extend_from_slice(&zeros);
            assert_eq!(crc32_zeros(crc32(&a), n), crc32(&az), "a+zeros n={n}");
            let mut h = Crc32::new();
            h.update(&a);
            h.update_zeros(n);
            assert_eq!(h.finish(), crc32(&az));
        }
        // Very large zero runs must not overflow or loop excessively.
        let _ = crc32_of_zeros(u64::MAX);
        let _ = crc32_zeros(0x1234_5678, 1 << 62);
    }

    #[test]
    fn block_crc_folding() {
        let data = pseudo_random(10 * 777, 9);
        let crcs: Vec<u32> = data.chunks(777).map(crc32).collect();
        assert_eq!(combine_block_crcs(&crcs, 777), crc32(&data));
        assert_eq!(combine_block_crcs(&[], 777), 0);
        assert_eq!(combine_block_crcs(&crcs[..1], 777), crcs[0]);
        let comb = Crc32Combiner::new(777);
        assert_eq!(comb.block_len(), 777);
        assert_eq!(comb.combine(crcs[0], crcs[1]), crc32(&data[..1554]));
    }

    #[test]
    fn sliding_window_matches_direct() {
        let data = pseudo_random(5000, 42);
        for window in [1usize, 2, 7, 16, 100, 1024] {
            let wt = WindowTable::new(window as u64);
            assert_eq!(wt.window(), window as u64);
            let mut raw = update_raw(INIT, &data[..window]);
            for start in 1..=(data.len() - window) {
                raw = wt.slide_raw(raw, data[start + window - 1], data[start - 1]);
                assert_eq!(
                    raw ^ INIT,
                    crc32(&data[start..start + window]),
                    "window={window} start={start}"
                );
            }
            // Final-value variant.
            let c = crc32(&data[..window]);
            assert_eq!(
                wt.slide(c, data[window], data[0]),
                crc32(&data[1..window + 1])
            );
        }
    }

    #[test]
    fn sliding_into_virtual_zero_padding() {
        // Sliding past the end with zero bytes must equal CRC of the zero-padded tail.
        let data = pseudo_random(300, 5);
        let window = 100usize;
        let wt = WindowTable::new(window as u64);
        let mut raw = update_raw(INIT, &data[200..300]);
        for k in 1..=window {
            let old = data[200 + k - 1];
            raw = wt.slide_raw(raw, 0, old);
            let mut padded = data[200 + k..].to_vec();
            padded.resize(window, 0);
            assert_eq!(raw ^ INIT, crc32(&padded));
        }
    }

    #[test]
    fn multmodp_identities() {
        let one = 1u32 << 31;
        for v in [0u32, 1, 0xDEAD_BEEF, 0x8000_0000, 0xFFFF_FFFF] {
            assert_eq!(multmodp(one, v), v);
            assert_eq!(multmodp(v, one), v);
            assert_eq!(multmodp(0, v), 0);
        }
        // x^(8*n) applied to INIT equals processing n zero bytes.
        for n in [1u64, 5, 31, 32, 33, 1000] {
            let mut s = INIT;
            for _ in 0..n {
                s = update_byte_raw(s, 0);
            }
            assert_eq!(crc32_shift_raw(INIT, n), s);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn pclmul_constants_match_intel_white_paper() {
        assert_eq!(hw::K1, 0x1_5444_2BD4);
        assert_eq!(hw::K2, 0x1_C6E4_1596);
        assert_eq!(hw::K3, 0x1_7519_97D0);
        assert_eq!(hw::K4, 0x0_CCAA_009E);
        assert_eq!(hw::K5, 0x1_63CD_6124);
        assert_eq!(fold_constant(32), (POLY as u64) << 1);
    }

    #[test]
    fn kernel_reports_something() {
        let k = kernel();
        assert!(matches!(k, CrcKernel::Hardware | CrcKernel::Software));
    }

    #[test]
    fn streaming_hasher_accessors_and_resume() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 31 + 7) as u8).collect();
        let mut h = Crc32::default();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert_eq!(h.raw(), INIT);
        h.update(&data[..4000]);
        let mid = h.finish();
        // Resuming from the finished CRC of the first part continues the same stream.
        let mut resumed = Crc32::from_crc(mid, 4000);
        assert_eq!(resumed.len(), 4000);
        assert!(!resumed.is_empty());
        resumed.update(&data[4000..]);
        h.update(&data[4000..]);
        assert_eq!(resumed.finish(), h.finish());
        assert_eq!(h.finish(), crc32(&data));
        assert_eq!(h.len(), data.len() as u64);
        assert_eq!(h.raw() ^ INIT, h.finish());
        // The software kernel agrees with the selected one.
        assert_eq!(update_slice8_raw(INIT, &data) ^ INIT, crc32(&data));
        assert!(matches!(
            kernel(),
            CrcKernel::Hardware | CrcKernel::Software
        ));
    }
}
