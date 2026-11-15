// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! `RepairOptions::skip_leeway` (par2cmdline `-N` / `-S<n>`) through the public API.
use par_rs::{
    NullObserver, Par2Repairer, RepairOptions, RepairResult, SetOptions, VerifyResult, build_set,
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

fn fixture(tag: &str) -> (PathBuf, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("par-rs-skip-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a = data(64 * 1024, 7);
    build_set(
        "set",
        &[("a.bin", &a)],
        &SetOptions {
            slice_size: 4096,
            recovery_blocks: 4,
            ..Default::default()
        },
    )
    .unwrap()
    .write_to(&dir, "set")
    .unwrap();
    // Three bytes inserted inside slice 5: slice 5 is damaged, slices 6.. sit 3 bytes late.
    let mut damaged = a[..5 * 4096 + 100].to_vec();
    damaged.extend_from_slice(b"xyz");
    damaged.extend_from_slice(&a[5 * 4096 + 100..]);
    std::fs::write(dir.join("a.bin"), damaged).unwrap();
    (dir, a)
}

fn verify(dir: &Path, skip_leeway: Option<u64>) -> (Par2Repairer, VerifyResult) {
    let mut r = Par2Repairer::new(
        dir,
        RepairOptions {
            skip_leeway,
            ..RepairOptions::default()
        },
    );
    r.load_par2_set(&dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    let v = r.verify(None, &mut NullObserver).unwrap();
    (r, v)
}

#[test]
fn leeway_covering_the_shift_matches_the_full_scan() {
    let (dir, a) = fixture("cover");
    let (_, full) = verify(&dir, None);
    assert_eq!(full.missing_blocks, 1, "{full:?}");
    let (mut r, skip) = verify(&dir, Some(16));
    assert_eq!(skip, full);
    assert!(matches!(
        r.repair(&mut NullObserver).unwrap(),
        RepairResult::Repaired { .. }
    ));
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn leeway_smaller_than_the_shift_misses_displaced_slices() {
    let (dir, _) = fixture("tight");
    let (_, tight) = verify(&dir, Some(2));
    // Slices 0..5 are found in place; the shifted tail (slices 6..16) is not.
    assert_eq!(tight.missing_blocks, 11, "{tight:?}");
    assert!(!tight.repair_possible);
    std::fs::remove_dir_all(&dir).unwrap();
}
