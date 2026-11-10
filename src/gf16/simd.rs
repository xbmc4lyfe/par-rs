//! SIMD kernels that multiply and accumulate GF(2^16) regions.
//!
//! # Layouts
//!
//! The fast kernels work on **split planes**: a region of `2n` bytes (n 16-bit words) is
//! stored as a *low plane* (`n` low bytes) and a *high plane* (`n` high bytes). In that layout
//! every byte lane of a SIMD register carries a useful nibble index, so a 16-word product
//! costs eight 16-entry table shuffles (`pshufb` / `vpshufb` / `tbl`): four for the low result
//! byte and four for the high result byte.
//!
//! [`Kernel::deinterleave`] and [`Kernel::interleave`] convert between natural little-endian
//! word layout and split planes; the Reed-Solomon engine keeps its accumulation buffers split
//! and converts once per chunk, which is `O(1)` per byte versus `O(outputs)` multiplies.
//!
//! Natural-layout convenience entry points ([`Kernel::mul_acc`], [`Kernel::mul_acc_multi`])
//! transform tiles through small stack buffers.
//!
//! # Dispatch
//!
//! [`Kernel::detect`] picks the widest instruction set the CPU supports and **self-tests it
//! against the scalar reference** before accepting it, falling back to the next candidate on
//! any mismatch. The scalar kernel is always available.

use crate::gf16::{MulTables, ShuffleTables, mul_acc_scalar, mul_acc_split_scalar};

/// Instruction set used by a [`Kernel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Isa {
    /// Portable table-lookup implementation.
    Scalar,
    /// AArch64 Advanced SIMD (`tbl`).
    Neon,
    /// x86 SSSE3 (`pshufb`, 128-bit).
    Ssse3,
    /// x86 AVX2 (`vpshufb`, 256-bit).
    Avx2,
    /// x86 AVX-512BW (`vpshufb`, 512-bit).
    Avx512bw,
}

impl Isa {
    /// Candidate instruction sets in preference order for this target.
    pub fn candidates() -> &'static [Isa] {
        #[cfg(target_arch = "x86_64")]
        {
            &[Isa::Avx512bw, Isa::Avx2, Isa::Ssse3, Isa::Scalar]
        }
        #[cfg(target_arch = "aarch64")]
        {
            &[Isa::Neon, Isa::Scalar]
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            &[Isa::Scalar]
        }
    }

    /// Whether the running CPU supports this instruction set.
    pub fn is_supported(self) -> bool {
        match self {
            Isa::Scalar => true,
            #[cfg(target_arch = "aarch64")]
            Isa::Neon => std::arch::is_aarch64_feature_detected!("neon"),
            #[cfg(target_arch = "x86_64")]
            Isa::Ssse3 => std::arch::is_x86_feature_detected!("ssse3"),
            #[cfg(target_arch = "x86_64")]
            Isa::Avx2 => std::arch::is_x86_feature_detected!("avx2"),
            #[cfg(target_arch = "x86_64")]
            Isa::Avx512bw => {
                std::arch::is_x86_feature_detected!("avx512f")
                    && std::arch::is_x86_feature_detected!("avx512bw")
            }
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Vector width in bytes (per plane) processed per iteration.
    pub const fn vector_bytes(self) -> usize {
        match self {
            Isa::Scalar => 1,
            Isa::Neon | Isa::Ssse3 => 16,
            Isa::Avx2 => 32,
            Isa::Avx512bw => 64,
        }
    }
}

impl std::fmt::Display for Isa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Isa::Scalar => "scalar",
            Isa::Neon => "neon",
            Isa::Ssse3 => "ssse3",
            Isa::Avx2 => "avx2",
            Isa::Avx512bw => "avx512bw",
        })
    }
}

/// Read-only split planes.
#[derive(Clone, Copy)]
pub struct Plane<'a> {
    /// Low bytes of each word.
    pub lo: &'a [u8],
    /// High bytes of each word.
    pub hi: &'a [u8],
}

impl<'a> Plane<'a> {
    /// Split a buffer whose first half is the low plane and second half the high plane.
    pub fn from_halves(buf: &'a [u8]) -> Self {
        let (lo, hi) = buf.split_at(buf.len() / 2);
        Self { lo, hi }
    }

    /// Words in the plane.
    pub fn len(&self) -> usize {
        self.lo.len()
    }

    /// Whether the plane is empty.
    pub fn is_empty(&self) -> bool {
        self.lo.is_empty()
    }

    /// Sub-range `[start, end)` of words.
    pub fn slice(&self, start: usize, end: usize) -> Plane<'a> {
        Plane {
            lo: &self.lo[start..end],
            hi: &self.hi[start..end],
        }
    }
}

/// Mutable split planes.
pub struct PlaneMut<'a> {
    /// Low bytes of each word.
    pub lo: &'a mut [u8],
    /// High bytes of each word.
    pub hi: &'a mut [u8],
}

impl<'a> PlaneMut<'a> {
    /// Split a buffer whose first half is the low plane and second half the high plane.
    pub fn from_halves(buf: &'a mut [u8]) -> Self {
        let mid = buf.len() / 2;
        let (lo, hi) = buf.split_at_mut(mid);
        Self { lo, hi }
    }

    /// Words in the plane.
    pub fn len(&self) -> usize {
        self.lo.len()
    }

    /// Whether the plane is empty.
    pub fn is_empty(&self) -> bool {
        self.lo.is_empty()
    }

    /// Reborrow as read-only planes.
    pub fn as_plane(&self) -> Plane<'_> {
        Plane {
            lo: self.lo,
            hi: self.hi,
        }
    }

    /// Reborrow a sub-range `[start, end)` of words mutably.
    pub fn slice_mut(&mut self, start: usize, end: usize) -> PlaneMut<'_> {
        PlaneMut {
            lo: &mut self.lo[start..end],
            hi: &mut self.hi[start..end],
        }
    }
}

/// Maximum number of destinations a single multi-output call processes per source pass.
pub const MAX_MULTI: usize = 8;

/// Dispatching GF(2^16) kernel.
#[derive(Clone, Copy, Debug)]
pub struct Kernel {
    isa: Isa,
}

impl Default for Kernel {
    fn default() -> Self {
        Self::detect()
    }
}

impl Kernel {
    /// Pick the best supported and self-verified instruction set.
    pub fn detect() -> Self {
        for &isa in Isa::candidates() {
            if let Some(k) = Self::with_isa(isa) {
                return k;
            }
        }
        Self { isa: Isa::Scalar }
    }

    /// Kernel for a specific instruction set, if supported by the CPU and passing the
    /// self-test. `Isa::Scalar` always succeeds.
    pub fn with_isa(isa: Isa) -> Option<Self> {
        if !isa.is_supported() {
            return None;
        }
        let k = Self { isa };
        if isa == Isa::Scalar || k.self_test() {
            Some(k)
        } else {
            None
        }
    }

    /// Scalar reference kernel.
    pub const fn scalar() -> Self {
        Self { isa: Isa::Scalar }
    }

    /// Instruction set in use.
    pub fn isa(&self) -> Isa {
        self.isa
    }

    /// Verify this kernel against the scalar reference on pseudo-random data.
    fn self_test(&self) -> bool {
        let n = 1000usize;
        let mut seed = 0x1234_5678_9ABC_DEF1u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let src: Vec<u8> = (0..2 * n).map(|_| rnd() as u8).collect();
        let (mut slo, mut shi) = (vec![0u8; n], vec![0u8; n]);
        self.deinterleave(&src, &mut slo, &mut shi);
        for i in 0..n {
            if slo[i] != src[2 * i] || shi[i] != src[2 * i + 1] {
                return false;
            }
        }
        let mut back = vec![0u8; 2 * n];
        self.interleave(&slo, &shi, &mut back);
        if back != src {
            return false;
        }
        for count in 1..=MAX_MULTI {
            let coeffs: Vec<u16> = (0..count).map(|_| rnd() as u16).collect();
            let init: Vec<Vec<u8>> = (0..count)
                .map(|_| (0..2 * n).map(|_| rnd() as u8).collect())
                .collect();
            let mut expect = init.clone();
            for (d, &c) in expect.iter_mut().zip(&coeffs) {
                mul_acc_scalar(d, &src, &MulTables::new(c));
            }
            // Split-plane path.
            let mut bufs = init.clone();
            {
                let mut planes: Vec<PlaneMut> = Vec::with_capacity(count);
                for b in bufs.iter_mut() {
                    let (mut lo, mut hi) = (vec![0u8; n], vec![0u8; n]);
                    Kernel::scalar().deinterleave(b, &mut lo, &mut hi);
                    b[..n].copy_from_slice(&lo);
                    b[n..].copy_from_slice(&hi);
                }
                for b in bufs.iter_mut() {
                    planes.push(PlaneMut::from_halves(b));
                }
                self.mul_acc_multi_split(&mut planes, Plane { lo: &slo, hi: &shi }, &coeffs);
            }
            for (b, e) in bufs.iter().zip(&expect) {
                let mut nat = vec![0u8; 2 * n];
                Kernel::scalar().interleave(&b[..n], &b[n..], &mut nat);
                if &nat != e {
                    return false;
                }
            }
            // Natural-layout path.
            let mut bufs = init.clone();
            {
                let mut refs: Vec<&mut [u8]> = bufs.iter_mut().map(|b| b.as_mut_slice()).collect();
                self.mul_acc_multi(&mut refs, &src, &coeffs);
            }
            if bufs != expect {
                return false;
            }
        }
        true
    }

    // -----------------------------------------------------------------------------------------
    // Split-plane API
    // -----------------------------------------------------------------------------------------

    /// `dst ^= coeff * src` on split planes.
    pub fn mul_acc_split(&self, dst: &mut PlaneMut, src: Plane, coeff: u16) {
        let mut one = [PlaneMut {
            lo: dst.lo,
            hi: dst.hi,
        }];
        self.mul_acc_multi_split(&mut one, src, &[coeff]);
    }

    /// `dsts[i] ^= coeffs[i] * src` for every destination, loading `src` once per group of
    /// up to [`MAX_MULTI`] destinations.
    pub fn mul_acc_multi_split(&self, dsts: &mut [PlaneMut], src: Plane, coeffs: &[u16]) {
        assert_eq!(
            dsts.len(),
            coeffs.len(),
            "mul_acc_multi_split: one coefficient per destination"
        );
        let n = src.lo.len();
        assert_eq!(
            src.hi.len(),
            n,
            "mul_acc_multi_split: source planes differ in length"
        );
        for d in dsts.iter() {
            assert!(
                d.lo.len() == n && d.hi.len() == n,
                "mul_acc_multi_split: destination length mismatch"
            );
        }
        if n == 0 || dsts.is_empty() {
            return;
        }
        let mut dsts = dsts;
        let mut coeffs = coeffs;
        while !dsts.is_empty() {
            let take = dsts.len().min(MAX_MULTI);
            let (head, rest) = dsts.split_at_mut(take);
            let (ch, cr) = coeffs.split_at(take);
            self.dispatch_group(head, src, ch);
            dsts = rest;
            coeffs = cr;
        }
    }

    fn dispatch_group(&self, dsts: &mut [PlaneMut], src: Plane, coeffs: &[u16]) {
        if coeffs.iter().all(|&c| c == 0) {
            return;
        }
        match self.isa {
            Isa::Scalar => {
                for (d, &c) in dsts.iter_mut().zip(coeffs) {
                    if c != 0 {
                        mul_acc_split_scalar(d.lo, d.hi, src.lo, src.hi, &MulTables::new(c));
                    }
                }
            }
            #[cfg(target_arch = "aarch64")]
            Isa::Neon => {
                let tables = shuffle_tables(coeffs);
                // SAFETY: `Isa::Neon` is only constructed when the CPU supports NEON.
                unsafe { arch::neon_group(dsts, src, &tables[..coeffs.len()]) }
            }
            #[cfg(target_arch = "x86_64")]
            Isa::Ssse3 => {
                let tables = shuffle_tables(coeffs);
                // SAFETY: feature checked at construction.
                unsafe { arch::ssse3_group(dsts, src, &tables[..coeffs.len()]) }
            }
            #[cfg(target_arch = "x86_64")]
            Isa::Avx2 => {
                let tables = shuffle_tables(coeffs);
                // SAFETY: feature checked at construction.
                unsafe { arch::avx2_group(dsts, src, &tables[..coeffs.len()]) }
            }
            #[cfg(target_arch = "x86_64")]
            Isa::Avx512bw => {
                let tables = shuffle_tables(coeffs);
                // SAFETY: feature checked at construction.
                unsafe { arch::avx512_group(dsts, src, &tables[..coeffs.len()]) }
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("unsupported ISA constructed"),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Natural-layout API
    // -----------------------------------------------------------------------------------------

    /// `dst ^= coeff * src` on natural little-endian 16-bit words.
    pub fn mul_acc(&self, dst: &mut [u8], src: &[u8], coeff: u16) {
        let mut one = [dst];
        self.mul_acc_multi(&mut one, src, &[coeff]);
    }

    /// `dsts[i] ^= coeffs[i] * src` on natural layout.
    ///
    /// Buffers must all have the same length. An odd trailing byte is handled as by
    /// [`mul_acc_scalar`].
    pub fn mul_acc_multi(&self, dsts: &mut [&mut [u8]], src: &[u8], coeffs: &[u16]) {
        assert_eq!(
            dsts.len(),
            coeffs.len(),
            "mul_acc_multi: one coefficient per destination"
        );
        for d in dsts.iter() {
            assert_eq!(
                d.len(),
                src.len(),
                "mul_acc_multi: destination length mismatch"
            );
        }
        if dsts.is_empty() || src.is_empty() {
            return;
        }
        if self.isa == Isa::Scalar {
            for (d, &c) in dsts.iter_mut().zip(coeffs) {
                if c != 0 {
                    mul_acc_scalar(d, src, &MulTables::new(c));
                }
            }
            return;
        }
        const TILE_WORDS: usize = 4096; // 8 KiB natural, fits L1 together with the destinations.
        let words = src.len() / 2;
        let mut slo = [0u8; TILE_WORDS];
        let mut shi = [0u8; TILE_WORDS];
        let mut dlo = [[0u8; TILE_WORDS]; 1];
        let mut dhi = [[0u8; TILE_WORDS]; 1];
        let mut start = 0usize;
        while start < words {
            let end = (start + TILE_WORDS).min(words);
            let n = end - start;
            self.deinterleave(&src[2 * start..2 * end], &mut slo[..n], &mut shi[..n]);
            let srcp = Plane {
                lo: &slo[..n],
                hi: &shi[..n],
            };
            for (d, &c) in dsts.iter_mut().zip(coeffs) {
                if c == 0 {
                    continue;
                }
                let tile = &mut d[2 * start..2 * end];
                self.deinterleave(tile, &mut dlo[0][..n], &mut dhi[0][..n]);
                let mut p = PlaneMut {
                    lo: &mut dlo[0][..n],
                    hi: &mut dhi[0][..n],
                };
                self.mul_acc_split(&mut p, srcp, c);
                self.interleave(&dlo[0][..n], &dhi[0][..n], tile);
            }
            start = end;
        }
        if src.len() % 2 == 1 {
            let last = src.len() - 1;
            for (d, &c) in dsts.iter_mut().zip(coeffs) {
                if c != 0 {
                    d[last] ^= crate::gf16::mul(c, src[last] as u16) as u8;
                }
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Layout conversion
    // -----------------------------------------------------------------------------------------

    /// Split natural layout `src` (even length) into `lo`/`hi` planes of `src.len() / 2`.
    pub fn deinterleave(&self, src: &[u8], lo: &mut [u8], hi: &mut [u8]) {
        let n = src.len() / 2;
        assert!(
            lo.len() == n && hi.len() == n && src.len().is_multiple_of(2),
            "deinterleave: length mismatch"
        );
        match self.isa {
            Isa::Scalar => deinterleave_scalar(src, lo, hi),
            #[cfg(target_arch = "aarch64")]
            Isa::Neon => unsafe { arch::neon_deinterleave(src, lo, hi) },
            #[cfg(target_arch = "x86_64")]
            Isa::Ssse3 => unsafe { arch::ssse3_deinterleave(src, lo, hi) },
            #[cfg(target_arch = "x86_64")]
            Isa::Avx2 | Isa::Avx512bw => unsafe { arch::avx2_deinterleave(src, lo, hi) },
            #[allow(unreachable_patterns)]
            _ => unreachable!("unsupported ISA constructed"),
        }
    }

    /// Merge `lo`/`hi` planes into natural layout `dst` of `2 * lo.len()`.
    pub fn interleave(&self, lo: &[u8], hi: &[u8], dst: &mut [u8]) {
        let n = lo.len();
        assert!(
            hi.len() == n && dst.len() == 2 * n,
            "interleave: length mismatch"
        );
        match self.isa {
            Isa::Scalar => interleave_scalar(lo, hi, dst),
            #[cfg(target_arch = "aarch64")]
            Isa::Neon => unsafe { arch::neon_interleave(lo, hi, dst) },
            #[cfg(target_arch = "x86_64")]
            Isa::Ssse3 => unsafe { arch::sse2_interleave(lo, hi, dst) },
            #[cfg(target_arch = "x86_64")]
            Isa::Avx2 | Isa::Avx512bw => unsafe { arch::avx2_interleave(lo, hi, dst) },
            #[allow(unreachable_patterns)]
            _ => unreachable!("unsupported ISA constructed"),
        }
    }
}

fn shuffle_tables(coeffs: &[u16]) -> [ShuffleTables; MAX_MULTI] {
    let mut t = [ShuffleTables::new(0); MAX_MULTI];
    for (slot, &c) in t.iter_mut().zip(coeffs) {
        *slot = ShuffleTables::new(c);
    }
    t
}

/// Scalar de-interleave.
pub fn deinterleave_scalar(src: &[u8], lo: &mut [u8], hi: &mut [u8]) {
    for (i, w) in src.as_chunks::<2>().0.iter().enumerate() {
        lo[i] = w[0];
        hi[i] = w[1];
    }
}

/// Scalar interleave.
pub fn interleave_scalar(lo: &[u8], hi: &[u8], dst: &mut [u8]) {
    for (i, w) in dst.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        w[0] = lo[i];
        w[1] = hi[i];
    }
}

/// Scalar tail processing shared by all SIMD kernels: words `[from, n)`.
#[inline(always)]
fn scalar_tail(dsts: &mut [PlaneMut], src: Plane, tables: &[ShuffleTables], from: usize) {
    let n = src.lo.len();
    if from >= n {
        return;
    }
    for (d, t) in dsts.iter_mut().zip(tables) {
        let c = t.coeff();
        if c == 0 {
            continue;
        }
        let mt = MulTables::new(c);
        mul_acc_split_scalar(
            &mut d.lo[from..n],
            &mut d.hi[from..n],
            &src.lo[from..n],
            &src.hi[from..n],
            &mt,
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Generic SIMD body shared by all ISAs
// ---------------------------------------------------------------------------------------------

/// Abstraction over one SIMD register width. All methods are `unsafe` because they call
/// target-specific intrinsics; they are only ever inlined into `#[target_feature]` wrappers.
#[allow(dead_code)]
trait Simd: Copy {
    const WIDTH: usize;
    /// Destinations per unrolled inner loop: chosen so that all `8 * UNROLL` table registers
    /// plus indices stay resident in the architectural register file (no spills).
    const UNROLL: usize;
    type V: Copy;
    unsafe fn load(p: *const u8) -> Self::V;
    unsafe fn store(p: *mut u8, v: Self::V);
    unsafe fn xor(a: Self::V, b: Self::V) -> Self::V;
    unsafe fn low_nibbles(v: Self::V) -> Self::V;
    unsafe fn high_nibbles(v: Self::V) -> Self::V;
    unsafe fn shuffle(table: Self::V, idx: Self::V) -> Self::V;
    unsafe fn table(t: &[u8; 16]) -> Self::V;
}

/// `dst ^= coeff * src` for `N` destinations using register type `S`.
#[allow(dead_code)]
#[inline(always)]
unsafe fn simd_group<S: Simd, const N: usize>(
    dsts: &mut [PlaneMut],
    src: Plane,
    tables: &[ShuffleTables],
) {
    debug_assert!(dsts.len() == N && tables.len() == N);
    let n = src.lo.len();
    let vec_end = n - n % S::WIDTH;

    // Preload the 8 tables per destination.
    let mut t: [[S::V; 8]; N] = [[unsafe { S::table(&[0u8; 16]) }; 8]; N];
    for (k, tab) in tables.iter().enumerate() {
        for j in 0..4 {
            t[k][j] = unsafe { S::table(&tab.lo[j]) };
            t[k][4 + j] = unsafe { S::table(&tab.hi[j]) };
        }
    }
    let mut dlo = [std::ptr::null_mut::<u8>(); N];
    let mut dhi = [std::ptr::null_mut::<u8>(); N];
    for k in 0..N {
        dlo[k] = dsts[k].lo.as_mut_ptr();
        dhi[k] = dsts[k].hi.as_mut_ptr();
    }
    let slo = src.lo.as_ptr();
    let shi = src.hi.as_ptr();

    let mut i = 0usize;
    while i < vec_end {
        // SAFETY: `i + S::WIDTH <= vec_end <= n` and all planes have `n` bytes.
        unsafe {
            let lo = S::load(slo.add(i));
            let hi = S::load(shi.add(i));
            let i0 = S::low_nibbles(lo);
            let i1 = S::high_nibbles(lo);
            let i2 = S::low_nibbles(hi);
            let i3 = S::high_nibbles(hi);
            for k in 0..N {
                let rl = S::xor(
                    S::xor(S::shuffle(t[k][0], i0), S::shuffle(t[k][1], i1)),
                    S::xor(S::shuffle(t[k][2], i2), S::shuffle(t[k][3], i3)),
                );
                let rh = S::xor(
                    S::xor(S::shuffle(t[k][4], i0), S::shuffle(t[k][5], i1)),
                    S::xor(S::shuffle(t[k][6], i2), S::shuffle(t[k][7], i3)),
                );
                let pl = dlo[k].add(i);
                let ph = dhi[k].add(i);
                S::store(pl, S::xor(S::load(pl), rl));
                S::store(ph, S::xor(S::load(ph), rh));
            }
        }
        i += S::WIDTH;
    }
    scalar_tail(dsts, src, tables, vec_end);
}

/// Dispatch on the destination count so that the inner loop is fully unrolled with at most
/// `S::UNROLL` destinations per pass (the source tile is L1-resident, so re-reading it per
/// pass is far cheaper than spilling table registers).
#[allow(dead_code)]
#[inline(always)]
unsafe fn simd_group_dyn<S: Simd>(dsts: &mut [PlaneMut], src: Plane, tables: &[ShuffleTables]) {
    let mut dsts = dsts;
    let mut tables = tables;
    while !dsts.is_empty() {
        let take = dsts.len().min(S::UNROLL).max(1);
        let (d, rest) = dsts.split_at_mut(take);
        let (t, trest) = tables.split_at(take);
        // SAFETY: forwarded from a `#[target_feature]` wrapper with the right features.
        unsafe {
            match take {
                1 => simd_group::<S, 1>(d, src, t),
                2 => simd_group::<S, 2>(d, src, t),
                3 => simd_group::<S, 3>(d, src, t),
                _ => simd_group::<S, 4>(d, src, t),
            }
        }
        dsts = rest;
        tables = trest;
    }
}

// ---------------------------------------------------------------------------------------------
// `AArch64 NEON`
// ---------------------------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::*;
    use core::arch::aarch64::*;

    #[derive(Clone, Copy)]
    struct Neon;

    impl Simd for Neon {
        const WIDTH: usize = 16;
        const UNROLL: usize = 2; // 32 NEON registers: 16 tables + 4 indices + temporaries
        type V = uint8x16_t;
        #[inline(always)]
        unsafe fn load(p: *const u8) -> uint8x16_t {
            unsafe { vld1q_u8(p) }
        }
        #[inline(always)]
        unsafe fn store(p: *mut u8, v: uint8x16_t) {
            unsafe { vst1q_u8(p, v) }
        }
        #[inline(always)]
        unsafe fn xor(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
            unsafe { veorq_u8(a, b) }
        }
        #[inline(always)]
        unsafe fn low_nibbles(v: uint8x16_t) -> uint8x16_t {
            unsafe { vandq_u8(v, vdupq_n_u8(0x0F)) }
        }
        #[inline(always)]
        unsafe fn high_nibbles(v: uint8x16_t) -> uint8x16_t {
            unsafe { vshrq_n_u8::<4>(v) }
        }
        #[inline(always)]
        unsafe fn shuffle(table: uint8x16_t, idx: uint8x16_t) -> uint8x16_t {
            unsafe { vqtbl1q_u8(table, idx) }
        }
        #[inline(always)]
        unsafe fn table(t: &[u8; 16]) -> uint8x16_t {
            unsafe { vld1q_u8(t.as_ptr()) }
        }
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn neon_group(dsts: &mut [PlaneMut], src: Plane, tables: &[ShuffleTables]) {
        unsafe { simd_group_dyn::<Neon>(dsts, src, tables) }
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn neon_deinterleave(src: &[u8], lo: &mut [u8], hi: &mut [u8]) {
        let n = lo.len();
        let vec_end = n - n % 16;
        let mut i = 0;
        while i < vec_end {
            // SAFETY: 32 source bytes and 16 bytes per plane are in bounds.
            unsafe {
                let v = vld2q_u8(src.as_ptr().add(2 * i));
                vst1q_u8(lo.as_mut_ptr().add(i), v.0);
                vst1q_u8(hi.as_mut_ptr().add(i), v.1);
            }
            i += 16;
        }
        deinterleave_scalar(&src[2 * vec_end..], &mut lo[vec_end..], &mut hi[vec_end..]);
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn neon_interleave(lo: &[u8], hi: &[u8], dst: &mut [u8]) {
        let n = lo.len();
        let vec_end = n - n % 16;
        let mut i = 0;
        while i < vec_end {
            // SAFETY: 16 bytes per plane and 32 destination bytes are in bounds.
            unsafe {
                let a = vld1q_u8(lo.as_ptr().add(i));
                let b = vld1q_u8(hi.as_ptr().add(i));
                vst2q_u8(dst.as_mut_ptr().add(2 * i), uint8x16x2_t(a, b));
            }
            i += 16;
        }
        interleave_scalar(&lo[vec_end..], &hi[vec_end..], &mut dst[2 * vec_end..]);
    }
}

// ---------------------------------------------------------------------------------------------
// `x86_64 SSSE3 / AVX2 / AVX-512BW`
// ---------------------------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod arch {
    use super::*;
    use core::arch::x86_64::*;

    #[derive(Clone, Copy)]
    struct Sse;

    impl Simd for Sse {
        const WIDTH: usize = 16;
        const UNROLL: usize = 1; // 16 XMM registers: 8 tables + 4 indices + temporaries
        type V = __m128i;
        #[inline(always)]
        unsafe fn load(p: *const u8) -> __m128i {
            unsafe { _mm_loadu_si128(p as *const __m128i) }
        }
        #[inline(always)]
        unsafe fn store(p: *mut u8, v: __m128i) {
            unsafe { _mm_storeu_si128(p as *mut __m128i, v) }
        }
        #[inline(always)]
        unsafe fn xor(a: __m128i, b: __m128i) -> __m128i {
            unsafe { _mm_xor_si128(a, b) }
        }
        #[inline(always)]
        unsafe fn low_nibbles(v: __m128i) -> __m128i {
            unsafe { _mm_and_si128(v, _mm_set1_epi8(0x0F)) }
        }
        #[inline(always)]
        unsafe fn high_nibbles(v: __m128i) -> __m128i {
            unsafe { _mm_and_si128(_mm_srli_epi16::<4>(v), _mm_set1_epi8(0x0F)) }
        }
        #[inline(always)]
        unsafe fn shuffle(table: __m128i, idx: __m128i) -> __m128i {
            unsafe { _mm_shuffle_epi8(table, idx) }
        }
        #[inline(always)]
        unsafe fn table(t: &[u8; 16]) -> __m128i {
            unsafe { _mm_loadu_si128(t.as_ptr() as *const __m128i) }
        }
    }

    #[derive(Clone, Copy)]
    struct Avx2;

    impl Simd for Avx2 {
        const WIDTH: usize = 32;
        const UNROLL: usize = 1; // 16 YMM registers
        type V = __m256i;
        #[inline(always)]
        unsafe fn load(p: *const u8) -> __m256i {
            unsafe { _mm256_loadu_si256(p as *const __m256i) }
        }
        #[inline(always)]
        unsafe fn store(p: *mut u8, v: __m256i) {
            unsafe { _mm256_storeu_si256(p as *mut __m256i, v) }
        }
        #[inline(always)]
        unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
            unsafe { _mm256_xor_si256(a, b) }
        }
        #[inline(always)]
        unsafe fn low_nibbles(v: __m256i) -> __m256i {
            unsafe { _mm256_and_si256(v, _mm256_set1_epi8(0x0F)) }
        }
        #[inline(always)]
        unsafe fn high_nibbles(v: __m256i) -> __m256i {
            unsafe { _mm256_and_si256(_mm256_srli_epi16::<4>(v), _mm256_set1_epi8(0x0F)) }
        }
        #[inline(always)]
        unsafe fn shuffle(table: __m256i, idx: __m256i) -> __m256i {
            unsafe { _mm256_shuffle_epi8(table, idx) }
        }
        #[inline(always)]
        unsafe fn table(t: &[u8; 16]) -> __m256i {
            unsafe { _mm256_broadcastsi128_si256(_mm_loadu_si128(t.as_ptr() as *const __m128i)) }
        }
    }

    #[derive(Clone, Copy)]
    struct Avx512;

    impl Simd for Avx512 {
        const WIDTH: usize = 64;
        const UNROLL: usize = 2; // 32 ZMM registers
        type V = __m512i;
        #[inline(always)]
        unsafe fn load(p: *const u8) -> __m512i {
            unsafe { _mm512_loadu_si512(p as *const __m512i) }
        }
        #[inline(always)]
        unsafe fn store(p: *mut u8, v: __m512i) {
            unsafe { _mm512_storeu_si512(p as *mut __m512i, v) }
        }
        #[inline(always)]
        unsafe fn xor(a: __m512i, b: __m512i) -> __m512i {
            unsafe { _mm512_xor_si512(a, b) }
        }
        #[inline(always)]
        unsafe fn low_nibbles(v: __m512i) -> __m512i {
            unsafe { _mm512_and_si512(v, _mm512_set1_epi8(0x0F)) }
        }
        #[inline(always)]
        unsafe fn high_nibbles(v: __m512i) -> __m512i {
            unsafe { _mm512_and_si512(_mm512_srli_epi16::<4>(v), _mm512_set1_epi8(0x0F)) }
        }
        #[inline(always)]
        unsafe fn shuffle(table: __m512i, idx: __m512i) -> __m512i {
            unsafe { _mm512_shuffle_epi8(table, idx) }
        }
        #[inline(always)]
        unsafe fn table(t: &[u8; 16]) -> __m512i {
            unsafe { _mm512_broadcast_i32x4(_mm_loadu_si128(t.as_ptr() as *const __m128i)) }
        }
    }

    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn ssse3_group(dsts: &mut [PlaneMut], src: Plane, tables: &[ShuffleTables]) {
        unsafe { simd_group_dyn::<Sse>(dsts, src, tables) }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn avx2_group(dsts: &mut [PlaneMut], src: Plane, tables: &[ShuffleTables]) {
        unsafe { simd_group_dyn::<Avx2>(dsts, src, tables) }
    }

    #[target_feature(enable = "avx512f,avx512bw")]
    pub(super) unsafe fn avx512_group(dsts: &mut [PlaneMut], src: Plane, tables: &[ShuffleTables]) {
        unsafe { simd_group_dyn::<Avx512>(dsts, src, tables) }
    }

    /// Byte permutation gathering even bytes into the low qword and odd bytes into the high.
    const EVEN_ODD: [i8; 16] = [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15];

    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn ssse3_deinterleave(src: &[u8], lo: &mut [u8], hi: &mut [u8]) {
        let n = lo.len();
        let vec_end = n - n % 16;
        let mask = unsafe { _mm_loadu_si128(EVEN_ODD.as_ptr() as *const __m128i) };
        let mut i = 0;
        while i < vec_end {
            // SAFETY: 32 source bytes / 16 plane bytes in bounds.
            unsafe {
                let a = _mm_shuffle_epi8(
                    _mm_loadu_si128(src.as_ptr().add(2 * i) as *const __m128i),
                    mask,
                );
                let b = _mm_shuffle_epi8(
                    _mm_loadu_si128(src.as_ptr().add(2 * i + 16) as *const __m128i),
                    mask,
                );
                _mm_storeu_si128(
                    lo.as_mut_ptr().add(i) as *mut __m128i,
                    _mm_unpacklo_epi64(a, b),
                );
                _mm_storeu_si128(
                    hi.as_mut_ptr().add(i) as *mut __m128i,
                    _mm_unpackhi_epi64(a, b),
                );
            }
            i += 16;
        }
        deinterleave_scalar(&src[2 * vec_end..], &mut lo[vec_end..], &mut hi[vec_end..]);
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn sse2_interleave(lo: &[u8], hi: &[u8], dst: &mut [u8]) {
        let n = lo.len();
        let vec_end = n - n % 16;
        let mut i = 0;
        while i < vec_end {
            // SAFETY: 16 bytes per plane and 32 destination bytes are in bounds.
            unsafe {
                let a = _mm_loadu_si128(lo.as_ptr().add(i) as *const __m128i);
                let b = _mm_loadu_si128(hi.as_ptr().add(i) as *const __m128i);
                _mm_storeu_si128(
                    dst.as_mut_ptr().add(2 * i) as *mut __m128i,
                    _mm_unpacklo_epi8(a, b),
                );
                _mm_storeu_si128(
                    dst.as_mut_ptr().add(2 * i + 16) as *mut __m128i,
                    _mm_unpackhi_epi8(a, b),
                );
            }
            i += 16;
        }
        interleave_scalar(&lo[vec_end..], &hi[vec_end..], &mut dst[2 * vec_end..]);
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn avx2_deinterleave(src: &[u8], lo: &mut [u8], hi: &mut [u8]) {
        let n = lo.len();
        let vec_end = n - n % 32;
        let mask = unsafe {
            _mm256_broadcastsi128_si256(_mm_loadu_si128(EVEN_ODD.as_ptr() as *const __m128i))
        };
        let mut i = 0;
        while i < vec_end {
            // SAFETY: 64 source bytes / 32 plane bytes in bounds.
            unsafe {
                let a = _mm256_shuffle_epi8(
                    _mm256_loadu_si256(src.as_ptr().add(2 * i) as *const __m256i),
                    mask,
                );
                let b = _mm256_shuffle_epi8(
                    _mm256_loadu_si256(src.as_ptr().add(2 * i + 32) as *const __m256i),
                    mask,
                );
                // Per 128-bit lane: [a_lane lows | b_lane lows]; fix the qword order to
                // [a0 a1 b0 b1] with a cross-lane qword permute (0,2,1,3).
                let l = _mm256_permute4x64_epi64::<0b11_01_10_00>(_mm256_unpacklo_epi64(a, b));
                let h = _mm256_permute4x64_epi64::<0b11_01_10_00>(_mm256_unpackhi_epi64(a, b));
                _mm256_storeu_si256(lo.as_mut_ptr().add(i) as *mut __m256i, l);
                _mm256_storeu_si256(hi.as_mut_ptr().add(i) as *mut __m256i, h);
            }
            i += 32;
        }
        unsafe { ssse3_deinterleave(&src[2 * vec_end..], &mut lo[vec_end..], &mut hi[vec_end..]) }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn avx2_interleave(lo: &[u8], hi: &[u8], dst: &mut [u8]) {
        let n = lo.len();
        let vec_end = n - n % 32;
        let mut i = 0;
        while i < vec_end {
            // SAFETY: 32 bytes per plane and 64 destination bytes are in bounds.
            unsafe {
                // Reorder qwords (0,2,1,3) so that each 128-bit lane holds consecutive words.
                let a = _mm256_permute4x64_epi64::<0b11_01_10_00>(_mm256_loadu_si256(
                    lo.as_ptr().add(i) as *const __m256i,
                ));
                let b = _mm256_permute4x64_epi64::<0b11_01_10_00>(_mm256_loadu_si256(
                    hi.as_ptr().add(i) as *const __m256i,
                ));
                _mm256_storeu_si256(
                    dst.as_mut_ptr().add(2 * i) as *mut __m256i,
                    _mm256_unpacklo_epi8(a, b),
                );
                _mm256_storeu_si256(
                    dst.as_mut_ptr().add(2 * i + 32) as *mut __m256i,
                    _mm256_unpackhi_epi8(a, b),
                );
            }
            i += 32;
        }
        unsafe { sse2_interleave(&lo[vec_end..], &hi[vec_end..], &mut dst[2 * vec_end..]) }
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
mod arch {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf16::mul;

    fn rnd_bytes(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 11) as u8
            })
            .collect()
    }

    fn all_kernels() -> Vec<Kernel> {
        let mut v = vec![Kernel::scalar()];
        for &isa in Isa::candidates() {
            if isa != Isa::Scalar
                && let Some(k) = Kernel::with_isa(isa)
            {
                v.push(k);
            }
        }
        v
    }

    #[test]
    fn detect_returns_supported_kernel() {
        let k = Kernel::detect();
        assert!(k.isa().is_supported());
        assert!(k.isa().vector_bytes() >= 1);
        let _ = format!("{}", k.isa());
        let d = Kernel::default();
        assert_eq!(d.isa(), k.isa());
        #[cfg(target_arch = "aarch64")]
        assert_eq!(k.isa(), Isa::Neon);
    }

    #[test]
    fn natural_layout_matches_reference_for_all_kernels() {
        for k in all_kernels() {
            for len in [
                0usize, 1, 2, 3, 31, 32, 33, 64, 127, 128, 1000, 1001, 8192, 8193, 20_000,
            ] {
                let src = rnd_bytes(len, 1);
                let coeffs = [0u16, 1, 0x1234, 0xFFFF, 0x8001, 7];
                let mut bufs: Vec<Vec<u8>> = (0..coeffs.len())
                    .map(|i| rnd_bytes(len, 100 + i as u64))
                    .collect();
                let orig = bufs.clone();
                {
                    let mut refs: Vec<&mut [u8]> =
                        bufs.iter_mut().map(|b| b.as_mut_slice()).collect();
                    k.mul_acc_multi(&mut refs, &src, &coeffs);
                }
                for (j, &c) in coeffs.iter().enumerate() {
                    let mut expect = orig[j].clone();
                    mul_acc_scalar(&mut expect, &src, &MulTables::new(c));
                    assert_eq!(bufs[j], expect, "isa={} len={len} coeff={c:#x}", k.isa());
                }
                // Single-destination convenience.
                let mut single = orig[2].clone();
                k.mul_acc(&mut single, &src, coeffs[2]);
                assert_eq!(single, bufs[2]);
            }
        }
    }

    #[test]
    fn split_layout_matches_reference_for_all_kernels() {
        for k in all_kernels() {
            for n in [0usize, 1, 15, 16, 17, 63, 64, 65, 500, 4096 + 3] {
                let slo = rnd_bytes(n, 3);
                let shi = rnd_bytes(n, 4);
                let coeffs: Vec<u16> = (0..(MAX_MULTI + 3) as u16)
                    .map(|i| i.wrapping_mul(0x9E37).wrapping_add(1))
                    .collect();
                let mut dl: Vec<Vec<u8>> = (0..coeffs.len())
                    .map(|i| rnd_bytes(n, 50 + i as u64))
                    .collect();
                let mut dh: Vec<Vec<u8>> = (0..coeffs.len())
                    .map(|i| rnd_bytes(n, 80 + i as u64))
                    .collect();
                let (ol, oh) = (dl.clone(), dh.clone());
                {
                    let mut planes: Vec<PlaneMut> = dl
                        .iter_mut()
                        .zip(dh.iter_mut())
                        .map(|(l, h)| PlaneMut { lo: l, hi: h })
                        .collect();
                    k.mul_acc_multi_split(&mut planes, Plane { lo: &slo, hi: &shi }, &coeffs);
                }
                for (j, &c) in coeffs.iter().enumerate() {
                    for i in 0..n {
                        let s = slo[i] as u16 | (shi[i] as u16) << 8;
                        let d = ol[j][i] as u16 | (oh[j][i] as u16) << 8;
                        let got = dl[j][i] as u16 | (dh[j][i] as u16) << 8;
                        assert_eq!(got, d ^ mul(c, s), "isa={} n={n} dst={j} i={i}", k.isa());
                    }
                }
            }
        }
    }

    #[test]
    fn interleave_roundtrip_all_kernels() {
        for k in all_kernels() {
            for n in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000] {
                let src = rnd_bytes(2 * n, 9);
                let (mut lo, mut hi) = (vec![0u8; n], vec![0u8; n]);
                k.deinterleave(&src, &mut lo, &mut hi);
                for i in 0..n {
                    assert_eq!(lo[i], src[2 * i], "isa={}", k.isa());
                    assert_eq!(hi[i], src[2 * i + 1], "isa={}", k.isa());
                }
                let mut back = vec![0u8; 2 * n];
                k.interleave(&lo, &hi, &mut back);
                assert_eq!(back, src, "isa={} n={n}", k.isa());
            }
        }
    }

    #[test]
    fn plane_helpers() {
        let mut buf: Vec<u8> = (0..20).collect();
        let p = Plane::from_halves(&buf);
        assert_eq!(p.len(), 10);
        assert!(!p.is_empty());
        assert_eq!(p.slice(2, 4).lo, &[2, 3]);
        assert_eq!(p.slice(2, 4).hi, &[12, 13]);
        let mut pm = PlaneMut::from_halves(&mut buf);
        assert_eq!(pm.len(), 10);
        assert!(!pm.is_empty());
        pm.slice_mut(0, 1).lo[0] = 99;
        assert_eq!(pm.as_plane().lo[0], 99);
        assert!(Plane { lo: &[], hi: &[] }.is_empty());
    }

    #[test]
    #[should_panic(expected = "length mismatch")]
    fn mismatched_lengths_panic() {
        let k = Kernel::scalar();
        let mut d = vec![0u8; 10];
        k.mul_acc(&mut d, &[0u8; 8], 3);
    }
}
