//! Multi-message MD5: many independent messages hashed in lockstep, one 32-bit SIMD lane per
//! message.
//!
//! MD5 is a serial dependency chain (~5 cycles per step on one core, about 1 GB/s), but PAR2
//! has to hash every slice separately: the per-slice IFSC digests are independent messages, so
//! they can share one vector instruction stream. Each 128-bit vector carries four messages and
//! [`GROUPS`] vectors are interleaved so the chain latency of one group is hidden by the others.
//! Equal-length messages (every PAR2 slice is zero padded to `slice_size`) run in perfect
//! lockstep; mixed lengths are sorted and lanes idle once their message is finished.
//!
//! Results are bit-identical to the scalar `md5` implementation ([`md5_many`] is checked
//! against it in the tests). NEON is used on AArch64, SSE2 on x86_64, a portable lane array
//! elsewhere.

/// Interleaved 4-lane groups per kernel invocation.
pub const GROUPS: usize = 4;
/// Messages hashed per kernel pass; callers batching work should use multiples of this.
pub const LANES: usize = 4 * GROUPS;

/// Four 32-bit lanes.
trait Lanes: Copy {
    fn splat(x: u32) -> Self;
    fn from_words(w: &[u32; 4]) -> Self;
    fn to_words(self) -> [u32; 4];
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
    /// Transpose four lanes' 16 message words into 16 lane vectors.
    #[inline(always)]
    fn transpose(w: &[[u32; 16]; 4]) -> [Self; 16] {
        let mut out = [Self::splat(0); 16];
        for (i, o) in out.iter_mut().enumerate() {
            *o = Self::from_words(&[w[0][i], w[1][i], w[2][i], w[3][i]]);
        }
        out
    }
}

impl Lanes for [u32; 4] {
    #[inline(always)]
    fn splat(x: u32) -> Self {
        [x; 4]
    }
    #[inline(always)]
    fn from_words(w: &[u32; 4]) -> Self {
        *w
    }
    #[inline(always)]
    fn to_words(self) -> [u32; 4] {
        self
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
        #[inline(always)]
        fn splat(x: u32) -> Self {
            // SAFETY: `NEON` is a baseline AArch64 feature.
            V(unsafe { vdupq_n_u32(x) })
        }
        #[inline(always)]
        fn from_words(w: &[u32; 4]) -> Self {
            // SAFETY: `w` has exactly four words.
            V(unsafe { vld1q_u32(w.as_ptr()) })
        }
        #[inline(always)]
        fn to_words(self) -> [u32; 4] {
            let mut out = [0u32; 4];
            // SAFETY: `out` has exactly four words.
            unsafe { vst1q_u32(out.as_mut_ptr(), self.0) };
            out
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
        fn transpose(w: &[[u32; 16]; 4]) -> [Self; 16] {
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
        #[inline(always)]
        fn splat(x: u32) -> Self {
            // SAFETY: `SSE2` is a baseline x86_64 feature.
            V(unsafe { _mm_set1_epi32(x as i32) })
        }
        #[inline(always)]
        fn from_words(w: &[u32; 4]) -> Self {
            // SAFETY: unaligned load of 16 bytes from a 16-byte array.
            V(unsafe { _mm_loadu_si128(w.as_ptr() as *const __m128i) })
        }
        #[inline(always)]
        fn to_words(self) -> [u32; 4] {
            let mut out = [0u32; 4];
            // SAFETY: unaligned store of 16 bytes into a 16-byte array.
            unsafe { _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, self.0) };
            out
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
        fn transpose(w: &[[u32; 16]; 4]) -> [Self; 16] {
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

fn run<L: Lanes, const G: usize>(msgs: &[&[u8]], out: &mut [[u8; 16]]) {
    let lanes = 4 * G;
    // Longest first so lockstep batches waste as little lane time as possible.
    let mut order: Vec<usize> = (0..msgs.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(msgs[i].len()));
    let mut words = [[0u32; 16]; 4];
    for batch in order.chunks(lanes) {
        let mut st = [[L::splat(0); 4]; G];
        for group in st.iter_mut() {
            for (j, s) in group.iter_mut().enumerate() {
                *s = L::splat(INIT[j]);
            }
        }
        let nblocks: Vec<usize> = (0..lanes)
            .map(|l| {
                batch
                    .get(l)
                    .map(|&i| block_count(msgs[i].len()))
                    .unwrap_or(0)
            })
            .collect();
        let max_blocks = nblocks.iter().copied().max().unwrap_or(0);
        let mut m = [[L::splat(0); 16]; G];
        for t in 0..max_blocks {
            for (g, mg) in m.iter_mut().enumerate() {
                for (l, w) in words.iter_mut().enumerate() {
                    let lane = g * 4 + l;
                    match batch.get(lane) {
                        Some(&i) => block_words(msgs[i], t, nblocks[lane], w),
                        None => *w = [0; 16],
                    }
                }
                *mg = L::transpose(&words);
            }
            compress::<L, G>(&mut st, &m);
            for (lane, &nb) in nblocks.iter().enumerate() {
                if nb == t + 1 {
                    let g = lane / 4;
                    let l = lane % 4;
                    let mut digest = [0u8; 16];
                    for (j, s) in st[g].iter().enumerate() {
                        digest[4 * j..4 * j + 4].copy_from_slice(&s.to_words()[l].to_le_bytes());
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
    #[cfg(target_arch = "aarch64")]
    stream_dispatch::<neon::V>(states, blocks);
    #[cfg(target_arch = "x86_64")]
    stream_dispatch::<sse2::V>(states, blocks);
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    stream_dispatch::<[u32; 4]>(states, blocks);
}

fn stream_dispatch<L: Lanes>(states: &mut [[u32; 4]], blocks: &[&[u8]]) {
    match states.len() {
        0 => {}
        1..=4 => stream_blocks::<L, 1>(states, blocks),
        5..=8 => stream_blocks::<L, 2>(states, blocks),
        _ => stream_blocks::<L, GROUPS>(states, blocks),
    }
}

fn stream_blocks<L: Lanes, const G: usize>(states: &mut [[u32; 4]], blocks: &[&[u8]]) {
    let mut st = [[L::splat(0); 4]; G];
    for (g, group) in st.iter_mut().enumerate() {
        for (word, state) in group.iter_mut().enumerate() {
            let lanes = std::array::from_fn(|lane| {
                states.get(g * 4 + lane).map_or(INIT[word], |s| s[word])
            });
            *state = L::from_words(&lanes);
        }
    }
    let count = blocks.iter().map(|b| b.len() / 64).max().unwrap_or(0);
    let mut words = [[0u32; 16]; 4];
    let mut messages = [[L::splat(0); 16]; G];
    for block in 0..count {
        for (g, message) in messages.iter_mut().enumerate() {
            for (lane, words) in words.iter_mut().enumerate() {
                block_words(
                    blocks.get(g * 4 + lane).copied().unwrap_or(&[]),
                    block,
                    0,
                    words,
                );
            }
            *message = L::transpose(&words);
        }
        compress::<L, G>(&mut st, &messages);
        for (lane, bytes) in blocks.iter().enumerate() {
            if bytes.len() / 64 == block + 1 {
                for (word, state) in st[lane / 4].iter().enumerate() {
                    states[lane][word] = state.to_words()[lane % 4];
                }
            }
        }
    }
}

/// MD5 of every message, in input order.
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
    #[cfg(target_arch = "aarch64")]
    {
        run::<neon::V, GROUPS>(msgs, out)
    }
    #[cfg(target_arch = "x86_64")]
    {
        run::<sse2::V, GROUPS>(msgs, out)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        run::<[u32; 4], GROUPS>(msgs, out)
    }
}

/// Portable reference (lane arrays, no SIMD); exposed for tests and self-checks.
pub fn md5_many_portable(msgs: &[&[u8]]) -> Vec<[u8; 16]> {
    let mut out = vec![[0u8; 16]; msgs.len()];
    run::<[u32; 4], 2>(msgs, &mut out);
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
