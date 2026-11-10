//! Differential tests against `par2cmdline` (`par2` binary). Skipped when `par2` is not on
//! `PATH`.
//!
//! * Sets created by this crate must verify and repair with `par2`.
//! * Sets created by `par2 create` must be parsed, verified and repaired by this crate,
//!   including recovery data produced by `par2cmdline`'s own GF(2^16) implementation.

use par_rs::create::{CreateOptions, SourceFile, VolumeScheme, create};
use par_rs::packet::{ScanOptions, load_par2_file};
use par_rs::repairer::{NullObserver, Par2Repairer, RepairOptions, RepairResult};
use std::path::{Path, PathBuf};
use std::process::Command;

fn par2_available() -> bool {
    Command::new("par2")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn rnd(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 41) as u8
        })
        .collect()
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("par-rs-diff-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn par2(dir: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new("par2")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run par2");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn write_files(dir: &Path, sizes: &[usize]) -> Vec<(String, Vec<u8>)> {
    sizes
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            let name = format!("data{i}.bin");
            let d = rnd(n, 77 + i as u64);
            std::fs::write(dir.join(&name), &d).unwrap();
            (name, d)
        })
        .collect()
}

fn check(dir: &Path, files: &[(String, Vec<u8>)]) {
    for (n, d) in files {
        assert_eq!(std::fs::read(dir.join(n)).unwrap(), *d, "{n}");
    }
}

#[test]
fn par2cmdline_verifies_and_repairs_our_sets() {
    if !par2_available() {
        eprintln!("par2 not available; skipping");
        return;
    }
    let dir = tmpdir("ours");
    let files = write_files(&dir, &[200_000, 70_001, 4096, 0]);
    let sources: Vec<SourceFile> = files
        .iter()
        .map(|(n, _)| SourceFile::new(dir.join(n)))
        .collect();
    let opts = CreateOptions {
        slice_size: 4096,
        recovery_blocks: 20,
        volumes: VolumeScheme::Exponential,
        ..CreateOptions::default()
    };
    create(&sources, &dir, "ours", &opts, None, &mut |_, _, _| {}).unwrap();

    let (ok, text) = par2(&dir, &["verify", "ours.par2"]);
    assert!(ok, "par2 verify failed on an intact set:\n{text}");
    assert!(text.contains("All files are correct"), "{text}");

    // Damage: corrupt several blocks of data0, delete data1, truncate data2.
    let p0 = dir.join("data0.bin");
    let mut d0 = std::fs::read(&p0).unwrap();
    for b in [0usize, 3, 17, 48] {
        d0[b * 4096 + 100] ^= 0x5A;
    }
    std::fs::write(&p0, &d0).unwrap();
    std::fs::remove_file(dir.join("data1.bin")).unwrap();
    std::fs::write(dir.join("data2.bin"), &files[2].1[..100]).unwrap();
    // 4 + 18 + 1 = 23 missing > 20 → par2 must report repair impossible with the loaded volumes.
    let (ok, text) = par2(&dir, &["verify", "ours.par2"]);
    assert!(!ok);
    assert!(
        text.contains("Repair is not possible") || text.contains("need"),
        "{text}"
    );

    // Restore data1 partially (first half) so 4 + 9 + 1 = 14 ≤ 20 and repair with par2.
    std::fs::write(dir.join("data1.bin"), &files[1].1[..36_000]).unwrap();
    let (ok, text) = par2(&dir, &["repair", "ours.par2"]);
    assert!(ok, "par2 repair failed using our recovery data:\n{text}");
    check(&dir, &files);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn we_verify_and_repair_par2cmdline_sets() {
    if !par2_available() {
        eprintln!("par2 not available; skipping");
        return;
    }
    let dir = tmpdir("theirs");
    let files = write_files(&dir, &[150_000, 33_333, 10, 0]);
    let (ok, text) = par2(
        &dir,
        &[
            "create",
            "-s4000",
            "-c15",
            "-n3",
            "theirs.par2",
            "data0.bin",
            "data1.bin",
            "data2.bin",
            "data3.bin",
        ],
    );
    assert!(ok, "par2 create failed:\n{text}");

    // Parse everything par2cmdline wrote.
    let idx = load_par2_file(&dir.join("theirs.par2"), ScanOptions::FULL).unwrap();
    assert!(idx.is_complete());
    assert_eq!(idx.slice_size(), Some(4000));
    // par2cmdline skips empty files, so data3.bin is not described.
    assert_eq!(idx.file_descs.len(), 3);
    assert!(idx.creator_string().to_lowercase().contains("par2"));
    assert_eq!(idx.stats.scan.resyncs, 0);
    assert_eq!(idx.stats.scan.md5_failures, 0);

    // Intact verification.
    let mut r = Par2Repairer::new(&dir, RepairOptions::default());
    let loaded = r.load_par2_set(&dir.join("theirs.par2")).unwrap();
    assert!(loaded.len() >= 2, "{loaded:?}");
    r.finalize().unwrap();
    assert_eq!(r.recovery_blocks(), 15);
    let v = r.verify(None, &mut NullObserver).unwrap();
    assert!(v.all_complete, "{:?}", r.source_files());

    // Damage within par2cmdline's recovery capacity and repair with the par-rs engine.
    let p0 = dir.join("data0.bin");
    let mut d0 = std::fs::read(&p0).unwrap();
    for b in [1usize, 2, 30, 37] {
        d0[b * 4000 + 7] ^= 0xFF;
    }
    std::fs::write(&p0, &d0).unwrap();
    std::fs::remove_file(dir.join("data1.bin")).unwrap(); // 9 blocks
    std::fs::write(dir.join("data2.bin"), b"xx").unwrap(); // 1 block damaged
    let mut r = Par2Repairer::new(&dir, RepairOptions::default());
    r.load_par2_set(&dir.join("theirs.par2")).unwrap();
    r.finalize().unwrap();
    let v = r.verify(None, &mut NullObserver).unwrap();
    assert_eq!(v.missing_blocks, 4 + 9 + 1);
    assert!(v.repair_possible);
    let res = r.repair(&mut NullObserver).unwrap();
    assert!(
        matches!(
            res,
            RepairResult::Repaired {
                blocks_recovered: 14,
                ..
            }
        ),
        "{res:?}"
    );
    check(&dir, &files);
    // par2cmdline agrees the result is correct.
    let (ok, text) = par2(&dir, &["verify", "theirs.par2"]);
    assert!(ok, "{text}");
    assert!(text.contains("All files are correct"), "{text}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn renamed_and_split_files_with_par2cmdline_set() {
    if !par2_available() {
        eprintln!("par2 not available; skipping");
        return;
    }
    let dir = tmpdir("renamed");
    let files = write_files(&dir, &[64_000, 30_000]);
    let (ok, text) = par2(
        &dir,
        &[
            "create",
            "-s2000",
            "-c6",
            "set.par2",
            "data0.bin",
            "data1.bin",
        ],
    );
    assert!(ok, "{text}");
    // Obfuscate data0, split data1 into misaligned pieces.
    std::fs::rename(dir.join("data0.bin"), dir.join("a1b2c3.xyz")).unwrap();
    let d1 = &files[1].1;
    std::fs::write(dir.join("data1.bin.001"), &d1[..11_111]).unwrap();
    std::fs::write(dir.join("data1.bin.002"), &d1[11_111..]).unwrap();
    std::fs::remove_file(dir.join("data1.bin")).unwrap();

    let mut r = Par2Repairer::new(&dir, RepairOptions::default());
    r.load_par2_set(&dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    let v = r.verify(None, &mut NullObserver).unwrap();
    assert_eq!(v.missing_blocks, 32 + 15);
    r.add_split_fragments(&dir, &mut NullObserver).unwrap();
    r.add_extra_files_from_dir(&dir, &mut NullObserver).unwrap();
    // The block straddling offset 11111 (block 5: 10000..12000) is lost; everything else found.
    assert_eq!(r.missing_blocks(), 1);
    let res = r.repair(&mut NullObserver).unwrap();
    assert!(matches!(
        res,
        RepairResult::Repaired {
            blocks_recovered: 1,
            ..
        }
    ));
    check(&dir, &files);
    let (ok, text) = par2(&dir, &["verify", "set.par2"]);
    assert!(ok, "{text}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn large_slice_count_and_many_missing_blocks() {
    if !par2_available() {
        eprintln!("par2 not available; skipping");
        return;
    }
    let dir = tmpdir("many");
    let files = write_files(&dir, &[1_000_000]);
    // 1000 input blocks, 300 recovery blocks from par2cmdline.
    let (ok, text) = par2(
        &dir,
        &["create", "-s1000", "-c300", "-n1", "many.par2", "data0.bin"],
    );
    assert!(ok, "{text}");
    let p = dir.join("data0.bin");
    let d = std::fs::read(&p).unwrap();
    // Zero out 250 scattered blocks.
    let mut dmg = d.clone();
    for b in (0..1000).step_by(4) {
        dmg[b * 1000..(b + 1) * 1000].fill(0);
    }
    std::fs::write(&p, &dmg).unwrap();
    let mut r = Par2Repairer::new(
        &dir,
        RepairOptions {
            num_threads: 0,
            ..RepairOptions::default()
        },
    );
    r.load_par2_set(&dir.join("many.par2")).unwrap();
    r.finalize().unwrap();
    let v = r.verify(None, &mut NullObserver).unwrap();
    assert_eq!(v.missing_blocks, 250);
    let t = std::time::Instant::now();
    let res = r.repair(&mut NullObserver).unwrap();
    eprintln!("repaired 250 blocks in {:.2}s", t.elapsed().as_secs_f64());
    assert!(matches!(
        res,
        RepairResult::Repaired {
            blocks_recovered: 250,
            ..
        }
    ));
    check(&dir, &files);
    std::fs::remove_dir_all(&dir).unwrap();
}
