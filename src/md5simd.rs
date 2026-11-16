//! Multi-message MD5: many independent messages hashed in lockstep, one 32-bit SIMD lane per
//! message.
//!
//! MD5 is a serial dependency chain (~5 cycles per step on one core, about 1 GB/s), but PAR2
//! has to hash every slice separately: the per-slice IFSC digests are independent messages, so
//! they can share one vector instruction stream. Each vector carries one message per 32-bit
//! lane (four in 128 bits, eight in 256) and several vectors are interleaved so the chain
//! latency of one group is hidden by the others.
//! Equal-length messages (every PAR2 slice is zero padded to `slice_size`) run in perfect
//! lockstep; mixed lengths are sorted and lanes idle once their message is finished.
//!
//! Results are bit-identical to the scalar `md5` implementation ([`md5_many`] is checked
//! against it in the tests). Kernels:
//!
//! - `AArch64`: NEON, [`GROUPS`] interleaved 4-lane vectors (eight fit the 32 vector registers);
//! - `x86_64`: AVX2 when the CPU has it (detected at runtime), two interleaved 8-lane vectors;
//!   otherwise SSE2, four interleaved 4-lane vectors (both fill the 16 vector registers);
//! - elsewhere: a portable lane array.

/// Interleaved 4-lane groups per kernel invocation (NEON, SSE2 and portable kernels).
///
/// On an Apple M4 one core hashes 4.7 GB/s with four groups, 5.9 GB/s with six and 6.1 GB/s
/// with eight (`examples/cpu_paths.rs`): four groups leave the NEON pipes waiting on the
/// MD5 dependency chain.
#[cfg(target_arch = "aarch64")]
pub const GROUPS: usize = 8;
/// Interleaved 4-lane groups per kernel invocation (NEON, SSE2 and portable kernels).
#[cfg(not(target_arch = "aarch64"))]
pub const GROUPS: usize = 4;
/// Messages hashed per kernel pass; callers batching work should use multiples of this.
pub const LANES: usize = 4 * GROUPS;

/// Widest vector in 32-bit lanes.
const MAX_W: usize = 8;

/// A vector of `W` 32-bit lanes.
trait Lanes: Copy {
    /// Lanes per vector (at most [`MAX_W`]).
    const W: usize;
    fn splat(x: u32) -> Self;
    /// Vector from `w[..W]`.
    fn from_words(w: &[u32]) -> Self;
    /// Word in lane `l`.
    fn lane(self, l: usize) -> u32;
    fn add(self, o: Self) -> Self;
    fn xor(self, o: Self) -> Self;
    fn or(self, o: Self) -> Self;
    fn and(self, o: Self) -> Self;
    fn not(self) -> Self;
    /// Rotate left by `S` (`R` must equal `32 - S`).
    fn rotl<const S: i32, const R: i32>(self) -> Self;
    /// `(b & c) | (!b & d)`
    #[inline(always)]
    fn f(b: Self, c: Self, d: Self) -> Self {
        b.and(c).or(b.not().and(d))
    }
    /// `(b & d) | (c & !d)`
    #[inline(always)]
    fn g(b: Self, c: Self, d: Self) -> Self {
        b.and(d).or(c.and(d.not()))
    }
    /// `b ^ c ^ d`
    #[inline(always)]
    fn h(b: Self, c: Self, d: Self) -> Self {
        b.xor(c).xor(d)
    }
    /// `c ^ (b | !d)`
    #[inline(always)]
    fn i(b: Self, c: Self, d: Self) -> Self {
        c.xor(b.or(d.not()))
    }
    /// Transpose `W` lanes' 16 message words (`w.len() == W`) into 16 lane vectors.
    #[inline(always)]
    fn transpose(w: &[[u32; 16]]) -> [Self; 16] {
        let mut out = [Self::splat(0); 16];
        for (i, o) in out.iter_mut().enumerate() {
            let column: [u32; MAX_W] = std::array::from_fn(|l| w.get(l).map_or(0, |r| r[i]));
            *o = Self::from_words(&column);
        }
        out
    }
}

impl Lanes for [u32; 4] {
    const W: usize = 4;
    #[inline(always)]
    fn splat(x: u32) -> Self {
        [x; 4]
    }
    #[inline(always)]
    fn from_words(w: &[u32]) -> Self {
        [w[0], w[1], w[2], w[3]]
    }
    #[inline(always)]
    fn lane(self, l: usize) -> u32 {
        self[l]
    }
    #[inline(always)]
    fn add(self, o: Self) -> Self {
        [
            self[0].wrapping_add(o[0]),
            self[1].wrapping_add(o[1]),
            self[2].wrapping_add(o[2]),
            self[3].wrapping_add(o[3]),
        ]
    }
    #[inline(always)]
    fn xor(self, o: Self) -> Self {
        [
            self[0] ^ o[0],
            self[1] ^ o[1],
            self[2] ^ o[2],
            self[3] ^ o[3],
        ]
    }
    #[inline(always)]
    fn or(self, o: Self) -> Self {
        [
            self[0] | o[0],
            self[1] | o[1],
            self[2] | o[2],
            self[3] | o[3],
        ]
    }
    #[inline(always)]
    fn and(self, o: Self) -> Self {
        [
            self[0] & o[0],
            self[1] & o[1],
            self[2] & o[2],
            self[3] & o[3],
        ]
    }
    #[inline(always)]
    fn not(self) -> Self {
        [!self[0], !self[1], !self[2], !self[3]]
    }
    #[inline(always)]
    fn rotl<const S: i32, const R: i32>(self) -> Self {
        [
            self[0].rotate_left(S as u32),
            self[1].rotate_left(S as u32),
            self[2].rotate_left(S as u32),
            self[3].rotate_left(S as u32),
        ]
    }
}

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::Lanes;
    use std::arch::aarch64::*;

    #[derive(Clone, Copy)]
    pub struct V(pub uint32x4_t);

    impl Lanes for V {
        const W: usize = 4;
        #[inline(always)]
        fn splat(x: u32) -> Self {
            // SAFETY: `NEON` is a baseline AArch64 feature.
            V(unsafe { vdupq_n_u32(x) })
        }
        #[inline(always)]
        fn from_words(w: &[u32]) -> Self {
            let w = &w[..4];
            // SAFETY: `w` has exactly four words.
            V(unsafe { vld1q_u32(w.as_ptr()) })
        }
        #[inline(always)]
        fn lane(self, l: usize) -> u32 {
            let mut out = [0u32; 4];
            // SAFETY: `out` has exactly four words.
            unsafe { vst1q_u32(out.as_mut_ptr(), self.0) };
            out[l]
        }
        #[inline(always)]
        fn add(self, o: Self) -> Self {
            // SAFETY: plain NEON arithmetic.
            V(unsafe { vaddq_u32(self.0, o.0) })
        }
        #[inline(always)]
        fn xor(self, o: Self) -> Self {
            // SAFETY: plain NEON arithmetic.
            V(unsafe { veorq_u32(self.0, o.0) })
        }
        #[inline(always)]
        fn or(self, o: Self) -> Self {
            // SAFETY: plain NEON arithmetic.
            V(unsafe { vorrq_u32(self.0, o.0) })
        }
        #[inline(always)]
        fn and(self, o: Self) -> Self {
            // SAFETY: plain NEON arithmetic.
            V(unsafe { vandq_u32(self.0, o.0) })
        }
        #[inline(always)]
        fn not(self) -> Self {
            // SAFETY: plain NEON arithmetic.
            V(unsafe { vmvnq_u32(self.0) })
        }
        #[inline(always)]
        fn rotl<const S: i32, const R: i32>(self) -> Self {
            // SAFETY: plain NEON arithmetic; `S` is 1..=31 and `R == 32 - S` at every call site.
            V(unsafe { vsriq_n_u32::<R>(vshlq_n_u32::<S>(self.0), self.0) })
        }
        #[inline(always)]
        fn f(b: Self, c: Self, d: Self) -> Self {
            // SAFETY: bit select: (b & c) | (!b & d).
            V(unsafe { vbslq_u32(b.0, c.0, d.0) })
        }
        #[inline(always)]
        fn g(b: Self, c: Self, d: Self) -> Self {
            // SAFETY: bit select: (d & b) | (!d & c).
            V(unsafe { vbslq_u32(d.0, b.0, c.0) })
        }
        #[inline(always)]
        fn i(b: Self, c: Self, d: Self) -> Self {
            // SAFETY: plain NEON arithmetic (`vorn` = b | !d).
            V(unsafe { veorq_u32(c.0, vornq_u32(b.0, d.0)) })
        }
        #[inline(always)]
        fn transpose(w: &[[u32; 16]]) -> [Self; 16] {
            let w = &w[..4];
            let mut out = [Self::splat(0); 16];
            for q in 0..4 {
                // SAFETY: each row has 16 words; `q * 4 + 3 < 16`.
                unsafe {
                    let r0 = vld1q_u32(w[0].as_ptr().add(q * 4));
                    let r1 = vld1q_u32(w[1].as_ptr().add(q * 4));
                    let r2 = vld1q_u32(w[2].as_ptr().add(q * 4));
                    let r3 = vld1q_u32(w[3].as_ptr().add(q * 4));
                    let t0 = vtrn1q_u32(r0, r1);
                    let t1 = vtrn2q_u32(r0, r1);
                    let t2 = vtrn1q_u32(r2, r3);
                    let t3 = vtrn2q_u32(r2, r3);
                    out[q * 4] = V(vreinterpretq_u32_u64(vtrn1q_u64(
                        vreinterpretq_u64_u32(t0),
                        vreinterpretq_u64_u32(t2),
                    )));
                    out[q * 4 + 1] = V(vreinterpretq_u32_u64(vtrn1q_u64(
                        vreinterpretq_u64_u32(t1),
                        vreinterpretq_u64_u32(t3),
                    )));
                    out[q * 4 + 2] = V(vreinterpretq_u32_u64(vtrn2q_u64(
                        vreinterpretq_u64_u32(t0),
                        vreinterpretq_u64_u32(t2),
                    )));
                    out[q * 4 + 3] = V(vreinterpretq_u32_u64(vtrn2q_u64(
                        vreinterpretq_u64_u32(t1),
                        vreinterpretq_u64_u32(t3),
                    )));
                }
            }
            out
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod sse2 {
    use super::Lanes;
    use std::arch::x86_64::*;

    #[derive(Clone, Copy)]
    pub struct V(pub __m128i);

    impl Lanes for V {
        const W: usize = 4;
        #[inline(always)]
        fn splat(x: u32) -> Self {
            // SAFETY: `SSE2` is a baseline x86_64 feature.
            V(unsafe { _mm_set1_epi32(x as i32) })
        }
        #[inline(always)]
        fn from_words(w: &[u32]) -> Self {
            let w = &w[..4];
            // SAFETY: unaligned load of 16 bytes from a 16-byte slice.
            V(unsafe { _mm_loadu_si128(w.as_ptr() as *const __m128i) })
        }
        #[inline(always)]
        fn lane(self, l: usize) -> u32 {
            let mut out = [0u32; 4];
            // SAFETY: unaligned store of 16 bytes into a 16-byte array.
            unsafe { _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, self.0) };
            out[l]
        }
        #[inline(always)]
        fn add(self, o: Self) -> Self {
            // SAFETY: plain SSE2 arithmetic.
            V(unsafe { _mm_add_epi32(self.0, o.0) })
        }
        #[inline(always)]
        fn xor(self, o: Self) -> Self {
            // SAFETY: plain SSE2 arithmetic.
            V(unsafe { _mm_xor_si128(self.0, o.0) })
        }
        #[inline(always)]
        fn or(self, o: Self) -> Self {
            // SAFETY: plain SSE2 arithmetic.
            V(unsafe { _mm_or_si128(self.0, o.0) })
        }
        #[inline(always)]
        fn and(self, o: Self) -> Self {
            // SAFETY: plain SSE2 arithmetic.
            V(unsafe { _mm_and_si128(self.0, o.0) })
        }
        #[inline(always)]
        fn not(self) -> Self {
            // SAFETY: plain SSE2 arithmetic.
            V(unsafe { _mm_xor_si128(self.0, _mm_set1_epi32(-1)) })
        }
        #[inline(always)]
        fn rotl<const S: i32, const R: i32>(self) -> Self {
            // SAFETY: plain SSE2 arithmetic; `S` is 1..=31 and `R == 32 - S` at every call site.
            V(unsafe { _mm_or_si128(_mm_slli_epi32::<S>(self.0), _mm_srli_epi32::<R>(self.0)) })
        }
        #[inline(always)]
        fn f(b: Self, c: Self, d: Self) -> Self {
            // SAFETY: plain SSE2 arithmetic (`andnot(b, d)` = !b & d).
            V(unsafe { _mm_or_si128(_mm_and_si128(b.0, c.0), _mm_andnot_si128(b.0, d.0)) })
        }
        #[inline(always)]
        fn g(b: Self, c: Self, d: Self) -> Self {
            // SAFETY: plain SSE2 arithmetic (`andnot(d, c)` = !d & c).
            V(unsafe { _mm_or_si128(_mm_and_si128(b.0, d.0), _mm_andnot_si128(d.0, c.0)) })
        }
        #[inline(always)]
        fn transpose(w: &[[u32; 16]]) -> [Self; 16] {
            let w = &w[..4];
            let mut out = [Self::splat(0); 16];
            for q in 0..4 {
                // SAFETY: each row has 16 words; `q * 4 + 3 < 16`.
                unsafe {
                    let r0 = _mm_loadu_si128(w[0].as_ptr().add(q * 4) as *const __m128i);
                    let r1 = _mm_loadu_si128(w[1].as_ptr().add(q * 4) as *const __m128i);
                    let r2 = _mm_loadu_si128(w[2].as_ptr().add(q * 4) as *const __m128i);
                    let r3 = _mm_loadu_si128(w[3].as_ptr().add(q * 4) as *const __m128i);
                    let t0 = _mm_unpacklo_epi32(r0, r1);
                    let t1 = _mm_unpackhi_epi32(r0, r1);
                    let t2 = _mm_unpacklo_epi32(r2, r3);
                    let t3 = _mm_unpackhi_epi32(r2, r3);
                    out[q * 4] = V(_mm_unpacklo_epi64(t0, t2));
                    out[q * 4 + 1] = V(_mm_unpackhi_epi64(t0, t2));
                    out[q * 4 + 2] = V(_mm_unpacklo_epi64(t1, t3));
                    out[q * 4 + 3] = V(_mm_unpackhi_epi64(t1, t3));
                }
            }
            out
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    //! Eight 32-bit lanes. These methods use AVX2 intrinsics and are only ever inlined into
    //! the `#[target_feature(enable = "avx2")]` entry points below `run`.
    use super::Lanes;
    use std::arch::x86_64::*;

    #[derive(Clone, Copy)]
    pub struct V(pub __m256i);

    impl Lanes for V {
        const W: usize = 8;
        #[inline(always)]
        fn splat(x: u32) -> Self {
            // SAFETY: only reached from `avx2` target-feature functions.
            V(unsafe { _mm256_set1_epi32(x as i32) })
        }
        #[inline(always)]
        fn from_words(w: &[u32]) -> Self {
            let w = &w[..8];
            // SAFETY: unaligned load of 32 bytes from a 32-byte slice; AVX2 as above.
            V(unsafe { _mm256_loadu_si256(w.as_ptr() as *const __m256i) })
        }
        #[inline(always)]
        fn lane(self, l: usize) -> u32 {
            let mut out = [0u32; 8];
            // SAFETY: unaligned store of 32 bytes into a 32-byte array; AVX2 as above.
            unsafe { _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, self.0) };
            out[l]
        }
        #[inline(always)]
        fn add(self, o: Self) -> Self {
            // SAFETY: AVX2 arithmetic, as above.
            V(unsafe { _mm256_add_epi32(self.0, o.0) })
        }
        #[inline(always)]
        fn xor(self, o: Self) -> Self {
            // SAFETY: AVX2 arithmetic, as above.
            V(unsafe { _mm256_xor_si256(self.0, o.0) })
        }
        #[inline(always)]
        fn or(self, o: Self) -> Self {
            // SAFETY: AVX2 arithmetic, as above.
            V(unsafe { _mm256_or_si256(self.0, o.0) })
        }
        #[inline(always)]
        fn and(self, o: Self) -> Self {
            // SAFETY: AVX2 arithmetic, as above.
            V(unsafe { _mm256_and_si256(self.0, o.0) })
        }
        #[inline(always)]
        fn not(self) -> Self {
            // SAFETY: AVX2 arithmetic, as above.
            V(unsafe { _mm256_xor_si256(self.0, _mm256_set1_epi32(-1)) })
        }
        #[inline(always)]
        fn rotl<const S: i32, const R: i32>(self) -> Self {
            // SAFETY: AVX2 arithmetic, as above; `S` is 1..=31 and `R == 32 - S`.
            V(unsafe {
                _mm256_or_si256(
                    _mm256_slli_epi32::<S>(self.0),
                    _mm256_srli_epi32::<R>(self.0),
                )
            })
        }
        #[inline(always)]
        fn f(b: Self, c: Self, d: Self) -> Self {
            // SAFETY: AVX2 arithmetic, as above (`andnot(b, d)` = !b & d).
            V(
                unsafe {
                    _mm256_or_si256(_mm256_and_si256(b.0, c.0), _mm256_andnot_si256(b.0, d.0))
                },
            )
        }
        #[inline(always)]
        fn g(b: Self, c: Self, d: Self) -> Self {
            // SAFETY: AVX2 arithmetic, as above (`andnot(d, c)` = !d & c).
            V(
                unsafe {
                    _mm256_or_si256(_mm256_and_si256(b.0, d.0), _mm256_andnot_si256(d.0, c.0))
                },
            )
        }
        #[inline(always)]
        fn transpose(w: &[[u32; 16]]) -> [Self; 16] {
            let w = &w[..8];
            let mut out = [Self::splat(0); 16];
            for q in 0..2 {
                // SAFETY: each row has 16 words and `q * 8 + 8 <= 16`; AVX2 as above.
                unsafe {
                    let r: [__m256i; 8] = std::array::from_fn(|l| {
                        _mm256_loadu_si256(w[l].as_ptr().add(q * 8) as *const __m256i)
                    });
                    let t0 = _mm256_unpacklo_epi32(r[0], r[1]);
                    let t1 = _mm256_unpackhi_epi32(r[0], r[1]);
                    let t2 = _mm256_unpacklo_epi32(r[2], r[3]);
                    let t3 = _mm256_unpackhi_epi32(r[2], r[3]);
                    let t4 = _mm256_unpacklo_epi32(r[4], r[5]);
                    let t5 = _mm256_unpackhi_epi32(r[4], r[5]);
                    let t6 = _mm256_unpacklo_epi32(r[6], r[7]);
                    let t7 = _mm256_unpackhi_epi32(r[6], r[7]);
                    // Per 128-bit half: u0 = words 0 / 4, u1 = 1 / 5, u2 = 2 / 6, u3 = 3 / 7
                    // of rows 0..4 (u4..u7: rows 4..8).
                    let u0 = _mm256_unpacklo_epi64(t0, t2);
                    let u1 = _mm256_unpackhi_epi64(t0, t2);
                    let u2 = _mm256_unpacklo_epi64(t1, t3);
                    let u3 = _mm256_unpackhi_epi64(t1, t3);
                    let u4 = _mm256_unpacklo_epi64(t4, t6);
                    let u5 = _mm256_unpackhi_epi64(t4, t6);
                    let u6 = _mm256_unpacklo_epi64(t5, t7);
                    let u7 = _mm256_unpackhi_epi64(t5, t7);
                    let o = q * 8;
                    out[o] = V(_mm256_permute2x128_si256::<0x20>(u0, u4));
                    out[o + 1] = V(_mm256_permute2x128_si256::<0x20>(u1, u5));
                    out[o + 2] = V(_mm256_permute2x128_si256::<0x20>(u2, u6));
                    out[o + 3] = V(_mm256_permute2x128_si256::<0x20>(u3, u7));
                    out[o + 4] = V(_mm256_permute2x128_si256::<0x31>(u0, u4));
                    out[o + 5] = V(_mm256_permute2x128_si256::<0x31>(u1, u5));
                    out[o + 6] = V(_mm256_permute2x128_si256::<0x31>(u2, u6));
                    out[o + 7] = V(_mm256_permute2x128_si256::<0x31>(u3, u7));
                }
            }
            out
        }
    }
}

pub(crate) const INIT: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// One MD5 compression of `G` interleaved lane groups.
#[inline(always)]
fn compress<L: Lanes, const G: usize>(st: &mut [[L; 4]; G], m: &[[L; 16]; G]) {
    let mut a = [L::splat(0); G];
    let mut b = [L::splat(0); G];
    let mut c = [L::splat(0); G];
    let mut d = [L::splat(0); G];
    for g in 0..G {
        a[g] = st[g][0];
        b[g] = st[g][1];
        c[g] = st[g][2];
        d[g] = st[g][3];
    }
    macro_rules! step {
        ($fun:ident, $a:ident, $b:ident, $c:ident, $d:ident, $k:literal, $s:literal, $mi:literal) => {
            for g in 0..G {
                let t = $a[g]
                    .add(L::$fun($b[g], $c[g], $d[g]))
                    .add(L::splat($k))
                    .add(m[g][$mi]);
                $a[g] = $b[g].add(t.rotl::<$s, { 32 - $s }>());
            }
        };
    }
    step!(f, a, b, c, d, 0xd76aa478, 7, 0);
    step!(f, d, a, b, c, 0xe8c7b756, 12, 1);
    step!(f, c, d, a, b, 0x242070db, 17, 2);
    step!(f, b, c, d, a, 0xc1bdceee, 22, 3);
    step!(f, a, b, c, d, 0xf57c0faf, 7, 4);
    step!(f, d, a, b, c, 0x4787c62a, 12, 5);
    step!(f, c, d, a, b, 0xa8304613, 17, 6);
    step!(f, b, c, d, a, 0xfd469501, 22, 7);
    step!(f, a, b, c, d, 0x698098d8, 7, 8);
    step!(f, d, a, b, c, 0x8b44f7af, 12, 9);
    step!(f, c, d, a, b, 0xffff5bb1, 17, 10);
    step!(f, b, c, d, a, 0x895cd7be, 22, 11);
    step!(f, a, b, c, d, 0x6b901122, 7, 12);
    step!(f, d, a, b, c, 0xfd987193, 12, 13);
    step!(f, c, d, a, b, 0xa679438e, 17, 14);
    step!(f, b, c, d, a, 0x49b40821, 22, 15);
    step!(g, a, b, c, d, 0xf61e2562, 5, 1);
    step!(g, d, a, b, c, 0xc040b340, 9, 6);
    step!(g, c, d, a, b, 0x265e5a51, 14, 11);
    step!(g, b, c, d, a, 0xe9b6c7aa, 20, 0);
    step!(g, a, b, c, d, 0xd62f105d, 5, 5);
    step!(g, d, a, b, c, 0x02441453, 9, 10);
    step!(g, c, d, a, b, 0xd8a1e681, 14, 15);
    step!(g, b, c, d, a, 0xe7d3fbc8, 20, 4);
    step!(g, a, b, c, d, 0x21e1cde6, 5, 9);
    step!(g, d, a, b, c, 0xc33707d6, 9, 14);
    step!(g, c, d, a, b, 0xf4d50d87, 14, 3);
    step!(g, b, c, d, a, 0x455a14ed, 20, 8);
    step!(g, a, b, c, d, 0xa9e3e905, 5, 13);
    step!(g, d, a, b, c, 0xfcefa3f8, 9, 2);
    step!(g, c, d, a, b, 0x676f02d9, 14, 7);
    step!(g, b, c, d, a, 0x8d2a4c8a, 20, 12);
    step!(h, a, b, c, d, 0xfffa3942, 4, 5);
    step!(h, d, a, b, c, 0x8771f681, 11, 8);
    step!(h, c, d, a, b, 0x6d9d6122, 16, 11);
    step!(h, b, c, d, a, 0xfde5380c, 23, 14);
    step!(h, a, b, c, d, 0xa4beea44, 4, 1);
    step!(h, d, a, b, c, 0x4bdecfa9, 11, 4);
    step!(h, c, d, a, b, 0xf6bb4b60, 16, 7);
    step!(h, b, c, d, a, 0xbebfbc70, 23, 10);
    step!(h, a, b, c, d, 0x289b7ec6, 4, 13);
    step!(h, d, a, b, c, 0xeaa127fa, 11, 0);
    step!(h, c, d, a, b, 0xd4ef3085, 16, 3);
    step!(h, b, c, d, a, 0x04881d05, 23, 6);
    step!(h, a, b, c, d, 0xd9d4d039, 4, 9);
    step!(h, d, a, b, c, 0xe6db99e5, 11, 12);
    step!(h, c, d, a, b, 0x1fa27cf8, 16, 15);
    step!(h, b, c, d, a, 0xc4ac5665, 23, 2);
    step!(i, a, b, c, d, 0xf4292244, 6, 0);
    step!(i, d, a, b, c, 0x432aff97, 10, 7);
    step!(i, c, d, a, b, 0xab9423a7, 15, 14);
    step!(i, b, c, d, a, 0xfc93a039, 21, 5);
    step!(i, a, b, c, d, 0x655b59c3, 6, 12);
    step!(i, d, a, b, c, 0x8f0ccc92, 10, 3);
    step!(i, c, d, a, b, 0xffeff47d, 15, 10);
    step!(i, b, c, d, a, 0x85845dd1, 21, 1);
    step!(i, a, b, c, d, 0x6fa87e4f, 6, 8);
    step!(i, d, a, b, c, 0xfe2ce6e0, 10, 15);
    step!(i, c, d, a, b, 0xa3014314, 15, 6);
    step!(i, b, c, d, a, 0x4e0811a1, 21, 13);
    step!(i, a, b, c, d, 0xf7537e82, 6, 4);
    step!(i, d, a, b, c, 0xbd3af235, 10, 11);
    step!(i, c, d, a, b, 0x2ad7d2bb, 15, 2);
    step!(i, b, c, d, a, 0xeb86d391, 21, 9);
    for g in 0..G {
        st[g][0] = st[g][0].add(a[g]);
        st[g][1] = st[g][1].add(b[g]);
        st[g][2] = st[g][2].add(c[g]);
        st[g][3] = st[g][3].add(d[g]);
    }
}

/// Number of 64-byte blocks in the padded message.
#[inline]
fn block_count(len: usize) -> usize {
    len / 64 + if len % 64 < 56 { 1 } else { 2 }
}

/// Words of padded block `t` of `msg` (`t < block_count(msg.len())`; larger `t` yield zeros).
#[inline(always)]
fn block_words(msg: &[u8], t: usize, nblocks: usize, out: &mut [u32; 16]) {
    let len = msg.len();
    let start = t * 64;
    if start + 64 <= len {
        let blk = &msg[start..start + 64];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u32::from_le_bytes([blk[4 * i], blk[4 * i + 1], blk[4 * i + 2], blk[4 * i + 3]]);
        }
        return;
    }
    let mut tmp = [0u8; 64];
    if t < nblocks {
        if start <= len {
            let n = len - start;
            tmp[..n].copy_from_slice(&msg[start..]);
            tmp[n] = 0x80;
        }
        if t + 1 == nblocks {
            tmp[56..].copy_from_slice(&((len as u64).wrapping_mul(8)).to_le_bytes());
        }
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = u32::from_le_bytes([tmp[4 * i], tmp[4 * i + 1], tmp[4 * i + 2], tmp[4 * i + 3]]);
    }
}

/// Smallest instantiated group count whose `w`-lane vectors hold `messages` (at most
/// [`GROUPS`]; callers never pass more messages than their kernel's lanes).
fn groups_for(messages: usize, w: usize) -> usize {
    match messages.div_ceil(w) {
        0 | 1 => 1,
        2 => 2,
        3 | 4 => 4,
        5 | 6 if GROUPS > 4 => 6,
        _ => GROUPS,
    }
}

// `run`, `run_batch`, `stream_dispatch` and `stream_blocks` are `inline(always)` so that the
// AVX2 entry points compile them, and the intrinsics they reach, with AVX2 enabled.
#[inline(always)]
fn run<L: Lanes, const G: usize>(msgs: &[&[u8]], out: &mut [[u8; 16]]) {
    // Longest first so lockstep batches waste as little lane time as possible.
    let mut order: Vec<usize> = (0..msgs.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(msgs[i].len()));
    for batch in order.chunks(L::W * G) {
        match groups_for(batch.len(), L::W) {
            1 => run_batch::<L, 1>(msgs, batch, out),
            2 => run_batch::<L, 2>(msgs, batch, out),
            4 => run_batch::<L, 4>(msgs, batch, out),
            6 => run_batch::<L, 6>(msgs, batch, out),
            _ => run_batch::<L, G>(msgs, batch, out),
        }
    }
}

/// Hash the messages `batch` indexes (at most `W * G`) in lockstep.
#[inline(always)]
fn run_batch<L: Lanes, const G: usize>(msgs: &[&[u8]], batch: &[usize], out: &mut [[u8; 16]]) {
    let w = L::W;
    let lanes = w * G;
    let mut rows = [[0u32; 16]; MAX_W];
    let words = &mut rows[..w];
    {
        let mut st = [[L::splat(0); 4]; G];
        for group in &mut st {
            for (j, s) in group.iter_mut().enumerate() {
                *s = L::splat(INIT[j]);
            }
        }
        let nblocks: Vec<usize> = (0..lanes)
            .map(|l| batch.get(l).map_or(0, |&i| block_count(msgs[i].len())))
            .collect();
        let max_blocks = nblocks.iter().copied().max().unwrap_or(0);
        let mut m = [[L::splat(0); 16]; G];
        for t in 0..max_blocks {
            for (g, mg) in m.iter_mut().enumerate() {
                for (l, row) in words.iter_mut().enumerate() {
                    let lane = g * w + l;
                    match batch.get(lane) {
                        Some(&i) => block_words(msgs[i], t, nblocks[lane], row),
                        None => *row = [0; 16],
                    }
                }
                *mg = L::transpose(words);
            }
            compress::<L, G>(&mut st, &m);
            for (lane, &nb) in nblocks.iter().enumerate() {
                if nb == t + 1 {
                    let g = lane / w;
                    let l = lane % w;
                    let mut digest = [0u8; 16];
                    for (j, s) in st[g].iter().enumerate() {
                        digest[4 * j..4 * j + 4].copy_from_slice(&s.lane(l).to_le_bytes());
                    }
                    out[batch[lane]] = digest;
                }
            }
        }
    }
}

/// Compress complete blocks into independently resumable message states.
/// The caller supplies the MD5 padding in the final blocks.
pub(crate) fn compress_blocks(states: &mut [[u32; 4]], blocks: &[&[u8]]) {
    assert_eq!(states.len(), blocks.len());
    assert!(states.len() <= LANES);
    assert!(blocks.iter().all(|b| b.len().is_multiple_of(64)));
    Kernel::best().stream(states, blocks);
}

#[inline(always)]
fn stream_dispatch<L: Lanes, const G: usize>(states: &mut [[u32; 4]], blocks: &[&[u8]]) {
    if states.is_empty() {
        return;
    }
    for (states, blocks) in states.chunks_mut(L::W * G).zip(blocks.chunks(L::W * G)) {
        match groups_for(states.len(), L::W) {
            1 => stream_blocks::<L, 1>(states, blocks),
            2 => stream_blocks::<L, 2>(states, blocks),
            4 => stream_blocks::<L, 4>(states, blocks),
            6 => stream_blocks::<L, 6>(states, blocks),
            _ => stream_blocks::<L, G>(states, blocks),
        }
    }
}

#[inline(always)]
fn stream_blocks<L: Lanes, const G: usize>(states: &mut [[u32; 4]], blocks: &[&[u8]]) {
    let w = L::W;
    let mut st = [[L::splat(0); 4]; G];
    for (g, group) in st.iter_mut().enumerate() {
        for (word, state) in group.iter_mut().enumerate() {
            let lanes: [u32; MAX_W] = std::array::from_fn(|lane| {
                states.get(g * w + lane).map_or(INIT[word], |s| s[word])
            });
            *state = L::from_words(&lanes);
        }
    }
    let count = blocks.iter().map(|b| b.len() / 64).max().unwrap_or(0);
    let mut rows = [[0u32; 16]; MAX_W];
    let words = &mut rows[..w];
    let mut messages = [[L::splat(0); 16]; G];
    for block in 0..count {
        for (g, message) in messages.iter_mut().enumerate() {
            for (lane, row) in words.iter_mut().enumerate() {
                block_words(
                    blocks.get(g * w + lane).copied().unwrap_or(&[]),
                    block,
                    0,
                    row,
                );
            }
            *message = L::transpose(words);
        }
        compress::<L, G>(&mut st, &messages);
        for (lane, bytes) in blocks.iter().enumerate() {
            if bytes.len() / 64 == block + 1 {
                for (word, state) in st[lane / w].iter().enumerate() {
                    states[lane][word] = state.lane(lane % w);
                }
            }
        }
    }
}

/// A multi-lane MD5 implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kernel {
    /// Lane arrays, no SIMD.
    Portable,
    /// `AArch64` NEON.
    #[cfg(target_arch = "aarch64")]
    Neon,
    /// `x86_64` SSE2.
    #[cfg(target_arch = "x86_64")]
    Sse2,
    /// `x86_64` AVX2 (runtime detected).
    #[cfg(target_arch = "x86_64")]
    Avx2,
}

impl Kernel {
    /// Every kernel this CPU can run, fastest first.
    #[cfg(test)]
    pub(crate) fn available() -> Vec<Kernel> {
        #[cfg(target_arch = "aarch64")]
        let out = vec![Kernel::Neon, Kernel::Portable];
        #[cfg(target_arch = "x86_64")]
        let out = if std::arch::is_x86_feature_detected!("avx2") {
            vec![Kernel::Avx2, Kernel::Sse2, Kernel::Portable]
        } else {
            vec![Kernel::Sse2, Kernel::Portable]
        };
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let out = vec![Kernel::Portable];
        out
    }

    /// The fastest kernel this CPU can run (the portable one when [`crate::cpu::SIMD_ENV`]
    /// turns the CPU-specific paths off).
    pub(crate) fn best() -> Kernel {
        if !crate::cpu::simd_enabled() {
            return Kernel::Portable;
        }
        #[cfg(target_arch = "aarch64")]
        return Kernel::Neon;
        #[cfg(target_arch = "x86_64")]
        return if std::arch::is_x86_feature_detected!("avx2") {
            Kernel::Avx2
        } else {
            Kernel::Sse2
        };
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        return Kernel::Portable;
    }

    /// [`md5_many_into`] with this kernel (more than one message).
    fn run(self, msgs: &[&[u8]], out: &mut [[u8; 16]]) {
        match self {
            Kernel::Portable => run::<[u32; 4], GROUPS>(msgs, out),
            #[cfg(target_arch = "aarch64")]
            Kernel::Neon => run::<neon::V, GROUPS>(msgs, out),
            #[cfg(target_arch = "x86_64")]
            Kernel::Sse2 => run::<sse2::V, GROUPS>(msgs, out),
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx2 => {
                assert!(std::arch::is_x86_feature_detected!("avx2"));
                // SAFETY: checked just above (a cached atomic load).
                unsafe { run_avx2(msgs, out) }
            }
        }
    }

    /// [`compress_blocks`] with this kernel.
    fn stream(self, states: &mut [[u32; 4]], blocks: &[&[u8]]) {
        match self {
            Kernel::Portable => stream_dispatch::<[u32; 4], GROUPS>(states, blocks),
            #[cfg(target_arch = "aarch64")]
            Kernel::Neon => stream_dispatch::<neon::V, GROUPS>(states, blocks),
            #[cfg(target_arch = "x86_64")]
            Kernel::Sse2 => stream_dispatch::<sse2::V, GROUPS>(states, blocks),
            #[cfg(target_arch = "x86_64")]
            Kernel::Avx2 => {
                assert!(std::arch::is_x86_feature_detected!("avx2"));
                // SAFETY: checked just above (a cached atomic load).
                unsafe { stream_avx2(states, blocks) }
            }
        }
    }
}

/// Two interleaved 8-lane vectors: 16 lanes, the same [`LANES`] as SSE2.
#[cfg(target_arch = "x86_64")]
const AVX2_GROUPS: usize = 2;

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn run_avx2(msgs: &[&[u8]], out: &mut [[u8; 16]]) {
    run::<avx2::V, AVX2_GROUPS>(msgs, out);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn stream_avx2(states: &mut [[u32; 4]], blocks: &[&[u8]]) {
    stream_dispatch::<avx2::V, AVX2_GROUPS>(states, blocks);
}

/// MD5 of every message, in input order.
#[must_use]
pub fn md5_many(msgs: &[&[u8]]) -> Vec<[u8; 16]> {
    let mut out = vec![[0u8; 16]; msgs.len()];
    md5_many_into(msgs, &mut out);
    out
}

/// MD5 of every message into `out` (same length as `msgs`).
pub fn md5_many_into(msgs: &[&[u8]], out: &mut [[u8; 16]]) {
    assert_eq!(msgs.len(), out.len(), "one output per message");
    if msgs.is_empty() {
        return;
    }
    if msgs.len() == 1 {
        out[0] = crate::hasher::md5(msgs[0]);
        return;
    }
    Kernel::best().run(msgs, out);
}

/// Portable reference (lane arrays, no SIMD); exposed for tests and self-checks.
#[must_use]
pub fn md5_many_portable(msgs: &[&[u8]]) -> Vec<[u8; 16]> {
    let mut out = vec![[0u8; 16]; msgs.len()];
    Kernel::Portable.run(msgs, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::md5;

    fn data(n: usize, seed: u32) -> Vec<u8> {
        (0..n as u32)
            .map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed) >> 13) as u8)
            .collect()
    }

    #[test]
    fn matches_scalar_for_all_lengths_near_block_boundaries() {
        let lens: Vec<usize> = (0..200)
            .chain([
                255,
                256,
                319,
                320,
                511,
                512,
                1000,
                4095,
                4096,
                70_000,
                1 << 20,
            ])
            .collect();
        let bufs: Vec<Vec<u8>> = lens
            .iter()
            .enumerate()
            .map(|(i, &n)| data(n, i as u32))
            .collect();
        let msgs: Vec<&[u8]> = bufs.iter().map(|b| b.as_slice()).collect();
        let got = md5_many(&msgs);
        let portable = md5_many_portable(&msgs);
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(got[i], md5(m), "len {}", m.len());
            assert_eq!(portable[i], md5(m), "portable len {}", m.len());
        }
    }

    #[test]
    fn every_kernel_matches_scalar() {
        let bufs: Vec<Vec<u8>> = (0..2 * LANES + 3)
            .map(|i| data((i * 53) % 700 + i / 7 * 64, i as u32))
            .collect();
        let expect: Vec<[u8; 16]> = bufs.iter().map(|b| md5(b)).collect();
        let kernels = Kernel::available();
        if crate::cpu::simd_enabled() {
            assert_eq!(kernels[0], Kernel::best());
        } else {
            assert_eq!(Kernel::best(), Kernel::Portable);
        }
        for kernel in kernels {
            // Every batch size, so each group count and partial group runs.
            for count in 2..=bufs.len() {
                let msgs: Vec<&[u8]> = bufs[..count].iter().map(Vec::as_slice).collect();
                let mut got = vec![[0u8; 16]; count];
                kernel.run(&msgs, &mut got);
                assert_eq!(got, expect[..count], "{kernel:?} count {count}");
            }
            // The resumable block API, fed in two steps.
            for count in 1..=LANES {
                let blocks: Vec<Vec<u8>> = (0..count)
                    .map(|i| data(64 * (i % 5 + 1) * 2, 99 + i as u32))
                    .collect();
                let mut states = vec![INIT; count];
                let halves: Vec<&[u8]> = blocks.iter().map(|b| &b[..b.len() / 2]).collect();
                kernel.stream(&mut states, &halves);
                let rest: Vec<&[u8]> = blocks.iter().map(|b| &b[b.len() / 2..]).collect();
                kernel.stream(&mut states, &rest);
                let mut reference = vec![INIT; count];
                let all: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
                Kernel::Portable.stream(&mut reference, &all);
                assert_eq!(states, reference, "{kernel:?} stream count {count}");
            }
        }
    }

    #[test]
    fn mixed_lengths_lockstep_and_small_batches() {
        for count in 1..=(2 * LANES + 1) {
            let bufs: Vec<Vec<u8>> = (0..count).map(|i| data((i * 37) % 300, i as u32)).collect();
            let msgs: Vec<&[u8]> = bufs.iter().map(|b| b.as_slice()).collect();
            let got = md5_many(&msgs);
            for (i, m) in msgs.iter().enumerate() {
                assert_eq!(got[i], md5(m), "count {count} index {i}");
            }
        }
        assert!(md5_many(&[]).is_empty());
        assert_eq!(block_count(0), 1);
        assert_eq!(block_count(55), 1);
        assert_eq!(block_count(56), 2);
        assert_eq!(block_count(64), 2);
        assert_eq!(block_count(119), 2);
        assert_eq!(block_count(120), 3);
    }
}
