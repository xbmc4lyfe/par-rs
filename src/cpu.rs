//! CPU-specific code paths: the process-wide switch that turns them off, and which GF(2^16)
//! kernel is in use and how fast it runs ([`gf_kernel_benchmark`], for sizing thread counts and
//! buffers).
//!
//! Each accelerated path (the GF(2^16) kernels in [`crate::gf16::simd`], hardware CRC-32 in
//! [`crate::crc`] and multi-lane MD5 in [`crate::md5simd`]) is chosen at runtime. Each one checks
//! the CPU and falls back to portable code. Setting the environment variable
//! [`SIMD_ENV`] (`PAR_RS_SIMD`) to `off` (or `0`, `false`, `no`, `scalar`) before the first
//! use makes every one of them pick that portable fallback instead. Use it to test the
//! fallbacks on a CPU that has the fast paths, or to rule the fast paths out while debugging.
//! The variable is read once per process.

use crate::gf16::simd::{Isa, Kernel, Plane, PlaneMut};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Name of the environment variable that turns the CPU-specific paths off.
pub const SIMD_ENV: &str = "PAR_RS_SIMD";

/// Whether the CPU-specific paths may be used (`false` when [`SIMD_ENV`] turns them off).
#[must_use]
pub fn simd_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var(SIMD_ENV).map_or(true, |value| !turns_off(&value)))
}

/// The GF(2^16) multiply kernel par-rs uses by default (what [`Kernel::detect`] picks, and
/// what [`crate::RepairOptions::default`] and the create paths use).
#[must_use]
pub fn gf_kernel() -> Isa {
    Kernel::detect().isa()
}

/// Which GF(2^16) kernel par-rs uses and how fast it runs, from [`gf_kernel_benchmark`].
#[derive(Clone, Debug, PartialEq)]
pub struct GfKernelReport {
    /// The kernel in use ([`gf_kernel`]).
    pub isa: Isa,
    /// Every kernel this CPU supports that passes its self-test, fastest first (the scalar
    /// kernel is always last). Independent of [`SIMD_ENV`].
    pub supported: Vec<Isa>,
    /// Throughput of `isa` multiplying and accumulating on one thread, in MB/s (10^6 bytes): bytes of
    /// source data multiplied into one recovery or repaired slice per second. A repair of `m`
    /// slices from `n` inputs of `s` bytes does about `n * m * s` bytes of this work, so
    /// `n * m * s / (mb_per_sec_per_thread * 1e6 * threads)` estimates its compute time. The
    /// buffers stay in the L2 cache, so reads from disk and main memory come on top, and it is
    /// the best of several short windows (a peak, not an average).
    pub mb_per_sec_per_thread: f64,
}

/// Source buffer of the benchmark: 16 Ki 16-bit words. With the four destinations that is
/// 160 KiB, which stays in the L2 cache of every supported CPU (256 KiB and up).
const BENCH_BYTES: usize = 32 << 10;

/// Length of one timed window; the best window is reported.
const BENCH_WINDOW: Duration = Duration::from_millis(10);

/// Pick-and-measure call for resource sizing: reports [`gf_kernel`], the supported kernels,
/// and the single-thread throughput of the kernel in use. It measures for about `budget` in
/// 10 ms windows and reports the best one, so a window the scheduler spent on a slower
/// (efficiency) core or interrupted does not lower the figure; at least one pass is always
/// timed. 100 ms or more gives a repeatable figure.
#[must_use]
pub fn gf_kernel_benchmark(budget: Duration) -> GfKernelReport {
    let kernel = Kernel::detect();
    let supported = Isa::candidates()
        .iter()
        .copied()
        .filter(|&isa| Kernel::with_isa(isa).is_some())
        .collect();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let src: Vec<u8> = (0..BENCH_BYTES)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect();
    let mut dsts: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; BENCH_BYTES]).collect();
    let coeffs = [0x1234u16, 0x5678, 0x9ABC, 0xDEF1];
    let pass = |dsts: &mut [Vec<u8>]| {
        let mut planes: Vec<PlaneMut> = dsts.iter_mut().map(|d| PlaneMut::from_halves(d)).collect();
        kernel.mul_acc_multi_split(&mut planes, Plane::from_halves(&src), &coeffs);
    };
    // One untimed pass warms the caches and the tables.
    pass(&mut dsts);
    let pass_bytes = (coeffs.len() * BENCH_BYTES) as f64;
    let start = Instant::now();
    let mut best = 0f64;
    loop {
        let window = Instant::now();
        let mut passes = 0u64;
        loop {
            pass(&mut dsts);
            passes += 1;
            if window.elapsed() >= BENCH_WINDOW.min(budget) {
                break;
            }
        }
        let secs = window.elapsed().as_secs_f64().max(1e-9);
        best = best.max(passes as f64 * pass_bytes / secs / 1e6);
        if start.elapsed() >= budget {
            break;
        }
    }
    std::hint::black_box(&dsts);
    GfKernelReport {
        isa: kernel.isa(),
        supported,
        mb_per_sec_per_thread: best,
    }
}

/// Whether `value` of [`SIMD_ENV`] turns the CPU-specific paths off.
fn turns_off(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "off" | "0" | "false" | "no" | "scalar"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_that_turn_simd_off() {
        for v in ["off", "OFF", " 0 ", "false", "No", "scalar"] {
            assert!(turns_off(v), "{v:?}");
        }
        for v in ["", "on", "1", "true", "auto", "avx2"] {
            assert!(!turns_off(v), "{v:?}");
        }
    }

    #[test]
    fn gf_kernel_benchmark_reports_the_kernel_in_use() {
        let r = gf_kernel_benchmark(Duration::from_millis(5));
        assert_eq!(r.isa, gf_kernel());
        assert!(r.supported.contains(&r.isa));
        assert_eq!(r.supported.last(), Some(&Isa::Scalar));
        assert!(r.mb_per_sec_per_thread > 0.0 && r.mb_per_sec_per_thread.is_finite());
        // A zero budget still measures one pass.
        assert!(gf_kernel_benchmark(Duration::ZERO).mb_per_sec_per_thread > 0.0);
    }

    /// Set in the child process that `simd_off_selects_every_fallback` starts.
    const CHILD: &str = "PAR_RS_CPU_TEST_CHILD";

    /// The switch is read once per process, so the check runs in a child test process.
    #[test]
    fn simd_off_selects_every_fallback() {
        if std::env::var_os(CHILD).is_some() {
            assert!(!simd_enabled());
            assert_eq!(
                crate::gf16::simd::Kernel::detect().isa(),
                crate::gf16::simd::Isa::Scalar
            );
            assert_eq!(gf_kernel(), Isa::Scalar);
            assert_eq!(crate::crc::kernel(), crate::crc::CrcKernel::Software);
            assert_eq!(
                crate::md5simd::Kernel::best(),
                crate::md5simd::Kernel::Portable
            );
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["cpu::tests::simd_off_selects_every_fallback", "--exact"])
            .env(SIMD_ENV, "off")
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("1 passed"), "{stdout}");
    }
}
