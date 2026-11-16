// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! `Par2Repairer::quick_verify_file`: verify files one by one as their downloads complete,
//! and let the final verify skip the ones that passed.
use par_rs::{
    FileStatus, NullObserver, Par2Repairer, QuickInfo, RepairOptions, RepairResult, Segment,
    SetOptions, build_set, crc::crc32, hasher::md5,
};
use std::path::PathBuf;

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

struct Fixture {
    dir: PathBuf,
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
}

fn fixture(tag: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("par-rs-incr-quick-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (a, b, c) = (data(50_000, 1), data(33_333, 2), data(12_000, 3));
    build_set(
        "set",
        &[("a.bin", &a), ("b.bin", &b), ("c.bin", &c)],
        &SetOptions {
            slice_size: 4096,
            recovery_blocks: 6,
            ..Default::default()
        },
    )
    .unwrap()
    .write_to(&dir, "set")
    .unwrap();
    for (name, bytes) in [("a.bin", &a), ("b.bin", &b), ("c.bin", &c)] {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    Fixture { dir, a, b, c }
}

fn repairer(f: &Fixture) -> Par2Repairer {
    let mut r = Par2Repairer::new(&f.dir, RepairOptions::default());
    r.load_par2_set(&f.dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    r
}

fn status(r: &Par2Repairer, name: &str) -> FileStatus {
    r.source_files()
        .iter()
        .find(|f| f.target_filename == name)
        .unwrap()
        .status
        .clone()
}

#[test]
fn passed_files_are_skipped_by_the_final_verify() {
    let f = fixture("skip");
    let mut r = repairer(&f);
    // The whole-file CRC from the articles proves a.bin, and the MD5 computed while
    // writing proves b.bin.
    let ok_a = QuickInfo::Success { crc: crc32(&f.a) };
    assert!(
        r.quick_verify_file("a.bin", &ok_a, None, &mut NullObserver)
            .unwrap()
    );
    assert!(
        r.quick_verify_file(
            "b.bin",
            &QuickInfo::Failure,
            Some(md5(&f.b)),
            &mut NullObserver
        )
        .unwrap()
    );
    assert_eq!(status(&r, "a.bin"), FileStatus::Complete);
    assert_eq!(status(&r, "c.bin"), FileStatus::Unknown);
    // Asking again is cheap and still true.
    assert!(
        r.quick_verify_file("a.bin", &ok_a, None, &mut NullObserver)
            .unwrap()
    );

    // Damage a.bin and c.bin on disk afterwards: the final verify trusts the earlier pass for
    // a.bin (it is not read again) and finds the damage in c.bin.
    let mut bad_a = f.a.clone();
    bad_a[100] ^= 1;
    std::fs::write(f.dir.join("a.bin"), &bad_a).unwrap();
    let mut bad_c = f.c.clone();
    bad_c[5000] ^= 1;
    std::fs::write(f.dir.join("c.bin"), &bad_c).unwrap();
    let v = r.verify(None, &mut NullObserver).unwrap();
    assert_eq!(v.quick_verified_files, 2);
    assert_eq!(v.missing_blocks, 1, "{v:?}");
    assert_eq!(status(&r, "a.bin"), FileStatus::Complete);
    assert_eq!(status(&r, "c.bin"), FileStatus::Damaged);
    // The repair reads a.bin's slices as trusted inputs, so it must really be intact
    // (with the damage left in, the post-repair check fails the repair).
    std::fs::write(f.dir.join("a.bin"), &f.a).unwrap();
    assert!(matches!(
        r.repair(&mut NullObserver).unwrap(),
        RepairResult::Repaired { .. }
    ));
    assert_eq!(std::fs::read(f.dir.join("c.bin")).unwrap(), f.c);
    std::fs::remove_dir_all(&f.dir).unwrap();
}

#[test]
fn files_that_do_not_pass_are_left_for_the_final_verify() {
    let f = fixture("fail");
    let mut r = repairer(&f);
    let mut o = NullObserver;
    // Wrong whole-file CRC, wrong MD5, a short file, an unknown name, and Failure.
    assert!(
        !r.quick_verify_file(
            "a.bin",
            &QuickInfo::Success {
                crc: crc32(&f.a) ^ 1
            },
            None,
            &mut o
        )
        .unwrap()
    );
    assert!(
        !r.quick_verify_file(
            "b.bin",
            &QuickInfo::Success { crc: crc32(&f.b) },
            Some([0; 16]),
            &mut o
        )
        .unwrap()
    );
    std::fs::write(f.dir.join("c.bin"), &f.c[..1000]).unwrap();
    assert!(
        !r.quick_verify_file(
            "c.bin",
            &QuickInfo::Success { crc: crc32(&f.c) },
            None,
            &mut o
        )
        .unwrap()
    );
    assert!(
        !r.quick_verify_file("nope.bin", &QuickInfo::Failure, None, &mut o)
            .unwrap()
    );
    assert!(
        !r.quick_verify_file("a.bin", &QuickInfo::Failure, None, &mut o)
            .unwrap()
    );
    for name in ["a.bin", "b.bin", "c.bin"] {
        assert_eq!(status(&r, name), FileStatus::Unknown, "{name}");
    }
    // The final verify checks them in full: a and b are intact, c is short.
    let v = r.verify(None, &mut o).unwrap();
    assert_eq!(v.quick_verified_files, 0);
    assert_eq!(status(&r, "a.bin"), FileStatus::Complete);
    assert_eq!(status(&r, "b.bin"), FileStatus::Complete);
    assert_eq!(status(&r, "c.bin"), FileStatus::Damaged);
    std::fs::remove_dir_all(&f.dir).unwrap();
}

#[test]
fn needs_finalize_and_never_makes_purge_safe() {
    let f = fixture("purge");
    let mut r = Par2Repairer::new(&f.dir, RepairOptions::default());
    assert!(
        r.quick_verify_file("a.bin", &QuickInfo::Failure, None, &mut NullObserver)
            .is_err()
    );
    let mut r = repairer(&f);
    for (name, bytes) in [("a.bin", &f.a), ("b.bin", &f.b), ("c.bin", &f.c)] {
        assert!(
            r.quick_verify_file(
                name,
                &QuickInfo::Failure,
                Some(md5(bytes)),
                &mut NullObserver
            )
            .unwrap()
        );
    }
    assert!(r.verify(None, &mut NullObserver).unwrap().all_complete);
    let report = r.purge(&mut NullObserver);
    assert!(!report.entries.is_empty() && report.removed().next().is_none());
    std::fs::remove_dir_all(&f.dir).unwrap();
}

#[test]
fn a_pass_after_a_full_verify_still_blocks_purge() {
    // A full verify while a.bin is missing and c.bin damaged; a.bin then arrives and passes
    // on its download CRC alone. Nothing hashed a.bin, so purge must keep everything.
    let f = fixture("after-verify");
    std::fs::remove_file(f.dir.join("a.bin")).unwrap();
    let mut bad_c = f.c.clone();
    bad_c[10] ^= 1;
    std::fs::write(f.dir.join("c.bin"), &bad_c).unwrap();
    let mut r = repairer(&f);
    r.verify(None, &mut NullObserver).unwrap();
    std::fs::write(f.dir.join("a.bin"), &f.a).unwrap();
    let ok = QuickInfo::Success { crc: crc32(&f.a) };
    assert!(
        r.quick_verify_file("a.bin", &ok, None, &mut NullObserver)
            .unwrap()
    );
    assert!(matches!(
        r.repair(&mut NullObserver).unwrap(),
        RepairResult::Repaired { .. }
    ));
    assert_eq!(std::fs::read(f.dir.join("c.bin")).unwrap(), f.c);
    let report = r.purge(&mut NullObserver);
    assert!(report.removed().next().is_none(), "{report:?}");
    assert!(f.dir.join("set.par2").exists());
    std::fs::remove_dir_all(&f.dir).unwrap();
}

fn segments(bytes: &[u8], failed: &[usize]) -> Vec<Segment> {
    bytes
        .chunks(4096)
        .enumerate()
        .map(|(i, chunk)| Segment {
            offset: (i * 4096) as i64,
            size: chunk.len() as i64,
            crc: crc32(chunk),
            success: !failed.contains(&i),
        })
        .collect()
}

#[test]
fn partial_passes_once_every_slice_is_intact_and_counts_once() {
    let f = fixture("partial");
    let mut r = repairer(&f);
    // A verify with download info where one article of a.bin failed: quick-verified damaged.
    let mut bad_a = f.a.clone();
    bad_a[4096 * 3 + 7] ^= 1;
    std::fs::write(f.dir.join("a.bin"), &bad_a).unwrap();
    let failed = segments(&bad_a, &[3]);
    let mut quick = |name: &str| -> Option<QuickInfo> {
        (name == "a.bin").then(|| QuickInfo::Partial {
            segments: failed.clone(),
        })
    };
    let v = r.verify(Some(&mut quick), &mut NullObserver).unwrap();
    assert_eq!(v.quick_verified_files, 1);
    assert_eq!(status(&r, "a.bin"), FileStatus::Damaged);
    // Still one failed article: no pass.
    let info = QuickInfo::Partial {
        segments: failed.clone(),
    };
    assert!(
        !r.quick_verify_file("a.bin", &info, None, &mut NullObserver)
            .unwrap()
    );
    // The article is downloaded again: every slice is intact now, and it passes.
    std::fs::write(f.dir.join("a.bin"), &f.a).unwrap();
    let info = QuickInfo::Partial {
        segments: segments(&f.a, &[]),
    };
    assert!(
        r.quick_verify_file("a.bin", &info, None, &mut NullObserver)
            .unwrap()
    );
    assert_eq!(status(&r, "a.bin"), FileStatus::Complete);
    let v = r.verify(None, &mut NullObserver).unwrap();
    assert_eq!(v.quick_verified_files, 1, "counted once");
    assert!(v.all_complete);
    std::fs::remove_dir_all(&f.dir).unwrap();
}
