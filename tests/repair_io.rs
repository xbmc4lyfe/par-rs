// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! Repair I/O options: page-cache hints on recovery volumes and copy-on-write backups.
use par_rs::{
    Level, Par2Repairer, RepairObserver, RepairOptions, RepairResult, SetOptions, build_set,
};
use std::path::{Path, PathBuf};

fn data(n: usize, seed: u32) -> Vec<u8> {
    let mut s = seed.wrapping_mul(2_654_435_761) | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s as u8
        })
        .collect()
}

/// A two-file set with three damaged slices in `a.bin`.
fn fixture(tag: &str) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("par-rs-repair-io-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a = data(200_000, 1);
    let b = data(70_000, 2);
    build_set(
        "set",
        &[("a.bin", &a), ("b.bin", &b)],
        &SetOptions {
            slice_size: 4096,
            recovery_blocks: 8,
            ..Default::default()
        },
    )
    .unwrap()
    .write_to(&dir, "set")
    .unwrap();
    let mut damaged = a.clone();
    for off in [5000, 50_000, 150_000] {
        damaged[off] ^= 0xFF;
    }
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();
    std::fs::write(dir.join("b.bin"), &b).unwrap();
    (dir, a, damaged)
}

#[derive(Default)]
struct Messages(Vec<String>);
impl RepairObserver for Messages {
    fn message(&mut self, _level: Level, text: &str) {
        self.0.push(text.to_string());
    }
}

fn repair(dir: &Path, uncached: bool) -> (RepairResult, Vec<String>) {
    let mut r = Par2Repairer::new(dir, RepairOptions::default());
    r.set_uncached_recovery_reads(uncached);
    r.load_par2_set(&dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    let mut log = Messages::default();
    r.verify(None, &mut log).unwrap();
    let result = r.repair(&mut log).unwrap();
    (result, log.0)
}

#[test]
fn uncached_recovery_reads_repair_the_same() {
    let (dir, a, damaged) = fixture("uncached");
    let (result, log) = repair(&dir, true);
    assert!(
        matches!(
            result,
            RepairResult::Repaired {
                blocks_recovered: 3,
                ..
            }
        ),
        "{result:?}"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    // The backup keeps the damaged bytes; on APFS it is a clone.
    assert_eq!(std::fs::read(dir.join("a.bin.1")).unwrap(), damaged);
    let kept = log
        .iter()
        .find(|m| m.starts_with("Kept damaged file"))
        .expect("backup message");
    if cfg!(target_vendor = "apple") {
        assert!(kept.ends_with("(copy-on-write clone)"), "{kept}");
    } else {
        assert!(
            kept.ends_with("(copy-on-write clone)") || kept.ends_with("(copy)"),
            "{kept}"
        );
    }
    // Recovery volumes are still readable afterwards (the hints only affect caching).
    let (again, _) = repair(&dir, false);
    assert_eq!(again, RepairResult::NotNeeded);
    std::fs::remove_dir_all(&dir).unwrap();
}
