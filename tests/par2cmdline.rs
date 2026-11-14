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

#[test]
fn balanced_volumes_match_reference_and_repair() {
    let explicit = std::env::var_os("PAR2_LAYOUT_REFERENCE");
    if explicit.is_none() && !par2_available() {
        eprintln!("par2 not available; skipping balanced reference comparison");
        return;
    }
    let reference = explicit.unwrap_or_else(|| "par2".into());
    let invoke = |dir: &Path, args: &[&str]| {
        let out = Command::new(&reference)
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{reference:?} {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    for (total, volumes, first_exponent, expected, names) in [
        (
            6,
            3,
            0,
            vec![(0, 2), (2, 2), (4, 2)],
            vec!["set.vol0+2.par2", "set.vol2+2.par2", "set.vol4+2.par2"],
        ),
        (
            7,
            3,
            17,
            vec![(17, 3), (20, 2), (22, 2)],
            vec!["set.vol17+3.par2", "set.vol20+2.par2", "set.vol22+2.par2"],
        ),
        (
            10,
            4,
            17,
            vec![(17, 3), (20, 3), (23, 2), (25, 2)],
            vec![
                "set.vol17+3.par2",
                "set.vol20+3.par2",
                "set.vol23+2.par2",
                "set.vol25+2.par2",
            ],
        ),
        (
            8,
            3,
            17,
            vec![(17, 3), (20, 3), (23, 2)],
            vec!["set.vol17+3.par2", "set.vol20+3.par2", "set.vol23+2.par2"],
        ),
        (
            7,
            3,
            0,
            vec![(0, 3), (3, 2), (5, 2)],
            vec!["set.vol0+3.par2", "set.vol3+2.par2", "set.vol5+2.par2"],
        ),
        (
            19,
            2,
            0,
            vec![(0, 10), (10, 9)],
            vec!["set.vol00+10.par2", "set.vol10+09.par2"],
        ),
        (
            7,
            3,
            32768,
            vec![(32768, 3), (32771, 2), (32773, 2)],
            vec![
                "set.vol32768+3.par2",
                "set.vol32771+2.par2",
                "set.vol32773+2.par2",
            ],
        ),
    ] {
        let dir = tmpdir(&format!("balanced-reference-{total}-{volumes}"));
        let files = write_files(&dir, &[256]);
        let source = SourceFile::new(dir.join("data0.bin"));
        let options = CreateOptions {
            slice_size: 64,
            recovery_blocks: total,
            first_exponent,
            volumes: VolumeScheme::Balanced(volumes),
            ..CreateOptions::default()
        };
        let own = dir.join("own");
        std::fs::create_dir(&own).unwrap();
        std::fs::write(own.join("data0.bin"), &files[0].1).unwrap();
        let report = create(&[source], &own, "set", &options, None, &mut |_, _, _| {}).unwrap();
        let external = dir.join("external");
        std::fs::create_dir(&external).unwrap();
        std::fs::write(external.join("data0.bin"), &files[0].1).unwrap();
        invoke(
            &external,
            &[
                "c",
                "-q",
                "-t1",
                "-s64",
                &format!("-c{total}"),
                &format!("-n{volumes}"),
                "-u",
                &format!("-f{first_exponent}"),
                "set.par2",
                "data0.bin",
            ],
        );
        for (((first, count), name), output) in
            expected.iter().zip(&names).zip(report.files.iter().skip(1))
        {
            assert_eq!(output.file_name().unwrap(), *name);
            for path in [output.clone(), external.join(name)] {
                let set = load_par2_file(&path, ScanOptions::FULL).unwrap();
                assert_eq!(
                    set.recovery.keys().copied().collect::<Vec<_>>(),
                    (*first..first + count).collect::<Vec<_>>()
                );
                assert!(set.recovery.values().all(|slice| slice.md5_verified));
            }
        }
        assert_eq!(report.files.len(), expected.len() + 1);
        invoke(&own, &["v", "-q", "set.par2"]);
        std::fs::remove_file(own.join("data0.bin")).unwrap();
        invoke(&own, &["r", "-q", "-t1", "set.par2"]);
        check(&own, &files);
        std::fs::remove_file(external.join("data0.bin")).unwrap();
        let mut repairer = Par2Repairer::new(&external, RepairOptions::default());
        repairer.load_par2_set(&external.join("set.par2")).unwrap();
        repairer.finalize().unwrap();
        let verified = repairer.verify(None, &mut NullObserver).unwrap();
        assert!(verified.repair_possible);
        assert_eq!(verified.missing_blocks, 4);
        assert!(matches!(
            repairer.repair(&mut NullObserver).unwrap(),
            RepairResult::Repaired { .. }
        ));
        check(&external, &files);
        invoke(&external, &["v", "-q", "set.par2"]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn limited_volumes_match_reference_and_cross_repair() {
    let explicit = std::env::var_os("PAR2_LAYOUT_REFERENCE");
    if explicit.is_none() && !par2_available() {
        eprintln!("par2 not available; skipping limited reference comparison");
        return;
    }
    let reference = explicit.unwrap_or_else(|| "par2".into());
    let invoke = |dir: &Path, args: &[&str]| {
        let out = Command::new(&reference)
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{reference:?} {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    for (total, size, first, counts) in [
        (7, 12, 0, vec![1, 2, 1, 3]),
        (8, 16, 2, vec![1, 2, 1, 4]),
        (9, 20, 0, vec![1, 2, 4, 2]),
        (10, 16, 0, vec![1, 2, 3, 4]),
        (63, 4, 0, vec![1; 63]),
        (8, 13, 0, vec![1, 2, 1, 4]),
        (7, 12, 32768, vec![1, 2, 1, 3]),
        (0, 16, 0, vec![]),
        (3, 64, 99, vec![1, 2]),
    ] {
        let dir = tmpdir(&format!("limited-reference-{total}-{size}-{first}"));
        let original = rnd(size, 435);
        let source = dir.join("data.bin");
        std::fs::write(&source, &original).unwrap();
        let cap = (size as u32).div_ceil(4);
        let own = dir.join("own");
        let report = create(
            &[SourceFile::new(source)],
            &own,
            "set",
            &CreateOptions {
                slice_size: 4,
                recovery_blocks: total,
                first_exponent: first,
                volumes: VolumeScheme::Limited(cap),
                ..CreateOptions::default()
            },
            None,
            &mut |_, _, _| {},
        )
        .unwrap();
        let external = dir.join("external");
        std::fs::create_dir(&external).unwrap();
        for destination in [&own, &external] {
            std::fs::write(destination.join("data.bin"), &original).unwrap();
        }
        invoke(
            &external,
            &[
                "c",
                "-q",
                "-t1",
                "-s4",
                &format!("-c{total}"),
                "-l",
                &format!("-f{first}"),
                "set.par2",
                "data.bin",
            ],
        );
        assert_eq!(report.files.len(), counts.len() + 1);
        let own_names: std::collections::BTreeSet<_> = report
            .files
            .iter()
            .map(|p| p.file_name().unwrap().to_owned())
            .collect();
        let external_names: std::collections::BTreeSet<_> = std::fs::read_dir(&external)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "par2"))
            .map(|p| p.file_name().unwrap().to_owned())
            .collect();
        assert_eq!(own_names, external_names);
        let mut next = first;
        for (&count, output) in counts.iter().zip(report.files.iter().skip(1)) {
            for path in [output.clone(), external.join(output.file_name().unwrap())] {
                let set = load_par2_file(&path, ScanOptions::FULL).unwrap();
                assert_eq!(
                    set.recovery.keys().copied().collect::<Vec<_>>(),
                    (next..next + count).collect::<Vec<_>>()
                );
                assert!(set.recovery.values().all(|slice| slice.md5_verified));
            }
            next += count;
        }
        assert_eq!(next, first + total);
        invoke(&own, &["v", "-q", "set.par2"]);
        if total > 0 {
            // Each creator is checked with both a missing target and a corrupt
            // target by the other implementation's actual repair path.
            for corrupt in [false, true] {
                if !corrupt && total < cap {
                    continue; // A missing whole file needs at least cap recovery slices.
                }
                let mut damaged = original.clone();
                damaged[0] ^= 255;
                for destination in [&own, &external] {
                    let path = destination.join("data.bin");
                    if corrupt {
                        std::fs::write(path, &damaged).unwrap();
                    } else {
                        std::fs::remove_file(path).unwrap();
                    }
                }
                invoke(&own, &["r", "-q", "-t1", "set.par2"]);
                assert_eq!(std::fs::read(own.join("data.bin")).unwrap(), original);
                if corrupt {
                    assert_eq!(std::fs::read(own.join("data.bin.1")).unwrap(), damaged);
                }
                let mut repairer = Par2Repairer::new(&external, RepairOptions::default());
                repairer.load_par2_set(&external.join("set.par2")).unwrap();
                repairer.finalize().unwrap();
                let verified = repairer.verify(None, &mut NullObserver).unwrap();
                assert!(verified.repair_possible);
                assert!(matches!(
                    repairer.repair(&mut NullObserver).unwrap(),
                    RepairResult::Repaired { .. }
                ));
                assert_eq!(std::fs::read(external.join("data.bin")).unwrap(), original);
                if corrupt {
                    assert_eq!(std::fs::read(external.join("data.bin.1")).unwrap(), damaged);
                }
                invoke(&external, &["v", "-q", "set.par2"]);
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn ordered_donor_policy_cross_repairs_with_reference() {
    use par_rs::ExtraFileScanPolicy;
    let explicit = std::env::var_os("PAR2_DONOR_REFERENCE");
    if explicit.is_none() && !par2_available() {
        eprintln!("par2 not available; skipping donor comparison");
        return;
    }
    let reference = explicit.unwrap_or_else(|| "par2".into());
    let artifact_root = std::env::var_os("PAR2_DONOR_ARTIFACT_DIR").map(PathBuf::from);
    if let Some(root) = &artifact_root {
        std::fs::create_dir_all(root).unwrap();
    }
    let invoke = |dir: &Path, args: &[&str]| {
        let out = Command::new(&reference)
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        eprintln!(
            "DONOR_REFERENCE cwd={} argv={reference:?} {args:?} status={:?}\n{}{}",
            dir.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out.status.code().unwrap()
    };
    for creator in ["library", "reference"] {
        for scenario in [
            "prefix",
            "shifted-ordered",
            "shifted-full",
            "perfect-and-damaged",
        ] {
            let tag = format!("ordered-{creator}-{scenario}-{}", std::process::id());
            let root = match &artifact_root {
                Some(root) => root.join(&tag),
                None => std::env::temp_dir().join(format!("par-rs-{tag}")),
            };
            std::fs::create_dir(&root).unwrap();
            eprintln!("ORDERED_REFERENCE_FIXTURE {}", root.display());
            let created = root.join("created");
            std::fs::create_dir(&created).unwrap();
            let a: Vec<u8> = if scenario == "perfect-and-damaged" {
                (0..16).collect()
            } else {
                (0..64).collect()
            };
            let b: Vec<u8> = (100..116).collect();
            let files = if scenario == "perfect-and-damaged" {
                vec![
                    ("a.bin".to_owned(), a.clone()),
                    ("b.bin".to_owned(), b.clone()),
                ]
            } else {
                vec![("a.bin".to_owned(), a.clone())]
            };
            let recovery = match scenario {
                "prefix" => 2,
                "perfect-and-damaged" => 1,
                _ => 0,
            };
            for (name, data) in &files {
                std::fs::write(created.join(name), data).unwrap();
            }
            if creator == "reference" {
                let count = format!("-c{recovery}");
                let mut args = vec![
                    "c",
                    "-qq",
                    "-t1",
                    "-T1",
                    "-m16",
                    "-s16",
                    count.as_str(),
                    "set.par2",
                    "a.bin",
                ];
                if files.len() == 2 {
                    args.push("b.bin");
                }
                assert_eq!(invoke(&created, &args), 0);
            } else {
                let sources: Vec<_> = files
                    .iter()
                    .map(|(name, _)| SourceFile::new(created.join(name)))
                    .collect();
                create(
                    &sources,
                    &created,
                    "set",
                    &CreateOptions {
                        slice_size: 16,
                        recovery_blocks: recovery,
                        engine: par_rs::EngineConfig {
                            num_threads: 1,
                            mem_limit_bytes: 16 << 20,
                            ..Default::default()
                        },
                        ..CreateOptions::default()
                    },
                    None,
                    &mut |_, _, _| {},
                )
                .unwrap();
            }
            let ours = root.join("ours");
            let theirs = root.join("theirs");
            let donor = match scenario {
                "prefix" => [a[..32].to_vec(), vec![255; 16]].concat(),
                "perfect-and-damaged" => a.clone(),
                _ => [vec![255; 7], a.clone()].concat(),
            };
            for dir in [&ours, &theirs] {
                std::fs::create_dir(dir).unwrap();
                for entry in std::fs::read_dir(&created).unwrap() {
                    let entry = entry.unwrap();
                    std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
                }
                std::fs::remove_file(dir.join("a.bin")).unwrap();
                std::fs::write(dir.join("donor.bin"), &donor).unwrap();
                if files.len() == 2 {
                    std::fs::write(dir.join("b.bin"), vec![255; 16]).unwrap();
                }
            }
            let policy = if scenario == "shifted-full" {
                ExtraFileScanPolicy::Full
            } else {
                ExtraFileScanPolicy::OrderedPrefix
            };
            let mut repairer = Par2Repairer::new(
                &ours,
                RepairOptions {
                    num_threads: 1,
                    mem_limit_bytes: 16 << 20,
                    full_file_md5: true,
                    ..RepairOptions::default()
                },
            );
            repairer.load_par2_set(&ours.join("set.par2")).unwrap();
            repairer.finalize().unwrap();
            repairer.verify(None, &mut NullObserver).unwrap();
            let newly = repairer
                .add_extra_file_with_policy(&ours.join("donor.bin"), policy, &mut NullObserver)
                .unwrap();
            let expected_offsets: Vec<u64> = match scenario {
                "prefix" => vec![0, 16],
                "shifted-full" => vec![7, 23, 39, 55],
                "perfect-and-damaged" => vec![0],
                _ => vec![],
            };
            let mut located: Vec<_> = repairer
                .block_locations()
                .iter()
                .flatten()
                .map(|location| {
                    assert_eq!(repairer.disk_files()[location.file], ours.join("donor.bin"));
                    location.offset
                })
                .collect();
            located.sort_unstable();
            assert_eq!(located, expected_offsets);
            assert_eq!(newly, expected_offsets.len());
            assert_eq!(std::fs::read(ours.join("donor.bin")).unwrap(), donor);
            assert!(!ours.join("a.bin").exists());
            let verdict = repairer.verify_result();
            let expected_status = if scenario == "shifted-ordered" { 2 } else { 1 };
            assert_eq!(verdict.repair_possible, expected_status == 1);
            let mut verify = vec!["v", "-qq", "-t1", "-T1", "-m16"];
            if policy == ExtraFileScanPolicy::OrderedPrefix {
                verify.push("-O");
            }
            verify.extend(["set.par2", "donor.bin"]);
            assert_eq!(invoke(&theirs, &verify), expected_status);
            verify[0] = "r";
            let ref_status = invoke(&theirs, &verify);
            if expected_status == 2 {
                assert_eq!(ref_status, 2);
                assert!(matches!(
                    repairer.repair(&mut NullObserver),
                    Err(par_rs::RepairError::NotEnoughRecovery { .. })
                ));
                assert!(!ours.join("a.bin").exists());
                assert!(!theirs.join("a.bin").exists());
            } else {
                assert_eq!(ref_status, 0);
                repairer.repair(&mut NullObserver).unwrap();
                check(&ours, &files);
                check(&theirs, &files);
                for dir in [&ours, &theirs] {
                    if scenario == "perfect-and-damaged" {
                        assert!(!dir.join("donor.bin").exists());
                        assert_eq!(std::fs::read(dir.join("b.bin.1")).unwrap(), vec![255; 16]);
                    } else {
                        assert_eq!(std::fs::read(dir.join("donor.bin")).unwrap(), donor);
                    }
                }
            }
            eprintln!(
                "DONOR_CASE_PASS creator={creator} scenario={scenario} newly={newly} reference_verify={expected_status} reference_repair={ref_status} bytes_and_effects_checked=true"
            );
            if artifact_root.is_none() {
                std::fs::remove_dir_all(root).unwrap();
            }
        }
    }
}
