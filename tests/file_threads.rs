// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! `file_threads` (par2cmdline `-T`) changes only how many files are hashed at once: the
//! created set and the verification verdict are identical for every value.
use par_rs::{
    CreateOptions, NullObserver, Par2Repairer, RepairOptions, RepairResult, SourceFile, create,
};
use std::path::{Path, PathBuf};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("par-rs-file-threads-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

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

/// Seven source files of different sizes (one empty) in `dir`.
fn write_sources(dir: &Path) -> Vec<SourceFile> {
    let sizes = [70_000, 3, 0, 12_345, 40_960, 99_999, 4_096];
    sizes
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            let p = dir.join(format!("f{i}.bin"));
            std::fs::write(&p, data(n, i as u32 + 1)).unwrap();
            SourceFile::new(p)
        })
        .collect()
}

fn create_with(sources: &[SourceFile], out: &Path, file_threads: usize) -> Vec<(String, Vec<u8>)> {
    std::fs::create_dir_all(out).unwrap();
    let opts = CreateOptions {
        slice_size: 4096,
        recovery_blocks: 40,
        creator: "file-threads-test".into(),
        file_threads,
        ..Default::default()
    };
    create(sources, out, "set", &opts, None, &mut |_, _, _| {}).unwrap();
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(out)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read(&p).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn create_output_does_not_depend_on_file_threads() {
    let dir = tmpdir("create");
    let sources = write_sources(&dir);
    let one = create_with(&sources, &dir.join("one"), 1);
    assert!(one.len() > 1);
    for threads in [2, 7, 32, 0] {
        assert_eq!(
            create_with(&sources, &dir.join(format!("t{threads}")), threads),
            one,
            "file_threads = {threads}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

fn verify_with(dir: &Path, file_threads: usize) -> (par_rs::VerifyResult, Vec<u32>) {
    let mut r = Par2Repairer::new(
        dir,
        RepairOptions {
            file_threads,
            ..RepairOptions::default()
        },
    );
    r.load_par2_set(&dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    let v = r.verify(None, &mut NullObserver).unwrap();
    let missing = r
        .source_files()
        .iter()
        .map(|f| f.missing_blocks())
        .collect();
    (v, missing)
}

#[test]
fn verify_and_repair_do_not_depend_on_file_threads() {
    let dir = tmpdir("verify");
    let sources = write_sources(&dir);
    create_with(&sources, &dir, 0);
    // Damage two files, remove one, and leave a complete copy under a wrong name.
    let mut f0 = std::fs::read(dir.join("f0.bin")).unwrap();
    f0[5000] ^= 0xFF;
    std::fs::write(dir.join("f0.bin"), &f0).unwrap();
    let mut f5 = std::fs::read(dir.join("f5.bin")).unwrap();
    f5.truncate(50_000);
    std::fs::write(dir.join("f5.bin"), &f5).unwrap();
    std::fs::rename(dir.join("f3.bin"), dir.join("renamed.dat")).unwrap();
    std::fs::remove_file(dir.join("f4.bin")).unwrap();

    let base = verify_with(&dir, 1);
    assert!(
        base.0.repair_needed && base.0.repair_possible,
        "{:?}",
        base.0
    );
    for threads in [2, 3, 16, 0] {
        assert_eq!(verify_with(&dir, threads), base, "file_threads = {threads}");
    }

    let mut r = Par2Repairer::new(
        &dir,
        RepairOptions {
            file_threads: 3,
            ..RepairOptions::default()
        },
    );
    r.load_par2_set(&dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    r.verify(None, &mut NullObserver).unwrap();
    r.add_extra_file(&dir.join("renamed.dat"), &mut NullObserver)
        .unwrap();
    assert!(matches!(
        r.repair(&mut NullObserver).unwrap(),
        RepairResult::Repaired { .. }
    ));
    for (i, n) in [70_000, 3, 0, 12_345, 40_960, 99_999, 4_096]
        .iter()
        .enumerate()
    {
        assert_eq!(
            std::fs::read(dir.join(format!("f{i}.bin"))).unwrap(),
            data(*n, i as u32 + 1),
            "f{i}.bin"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
