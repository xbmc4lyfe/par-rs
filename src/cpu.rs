//! Process-wide switch for the CPU-specific code paths.
//!
//! Every accelerated path is chosen at runtime: GF(2^16) kernels ([`crate::gf16::simd`]),
//! hardware CRC-32 ([`crate::crc`]) and multi-lane MD5 ([`crate::md5simd`]). Each one checks
//! the CPU and falls back to portable code. Setting the environment variable
//! [`SIMD_ENV`] (`PAR_RS_SIMD`) to `off` (or `0`, `false`, `no`, `scalar`) before the first
//! use makes every one of them pick that portable fallback instead. Use it to test the
//! fallbacks on a CPU that has the fast paths, or to rule the fast paths out while debugging.
//! The variable is read once per process.

use std::sync::OnceLock;

/// Name of the environment variable that turns the CPU-specific paths off.
pub const SIMD_ENV: &str = "PAR_RS_SIMD";

/// Whether the CPU-specific paths may be used (`false` when [`SIMD_ENV`] turns them off).
#[must_use]
pub fn simd_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var(SIMD_ENV).map_or(true, |value| !turns_off(&value)))
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
