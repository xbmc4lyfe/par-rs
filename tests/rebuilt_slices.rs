// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! `Par2Repairer::set_verify_rebuilt_slices_only`: the post-repair check reads back only the
//! slices the repair wrote, and the result is slice-verified, never purge-safe.
use par_rs::{
    NullObserver, Par2Repairer, PurgeKept, QuickInfo, RepairCheck, RepairError, RepairObserver,
    RepairOptions, RepairResult, Segment, SetOptions, Stage, StreamingOptions, build_set,
    crc::crc32,
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

/// `a.bin` (49 slices of 4 KiB) with three damaged slices, `b.bin` intact or removed.
fn fixture(tag: &str, remove_b: bool) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("par-rs-rebuilt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a = data(200_000, 1);
    let b = data(30_000, 2);
    build_set(
        "set",
        &[("a.bin", &a), ("b.bin", &b)],
        &SetOptions {
            slice_size: 4096,
            recovery_blocks: 16,
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
    if !remove_b {
        std::fs::write(dir.join("b.bin"), &b).unwrap();
    }
    (dir, a, b)
}

/// Highest progress reported while re-verifying repaired files: the share of their bytes
/// that was read back.
#[derive(Default)]
struct ReadBack {
    in_stage: bool,
    max_permille: u32,
}
impl RepairObserver for ReadBack {
    fn stage(&mut self, stage: Stage) {
        self.in_stage = stage == Stage::VerifyingRepaired;
    }
    fn progress(&mut self, permille: u32, label: &str) {
        if self.in_stage && label == "Verifying repaired files" {
            self.max_permille = self.max_permille.max(permille);
        }
    }
}

fn repair(dir: &Path, slices_only: bool, options: RepairOptions) -> (Par2Repairer, u32) {
    let mut r = Par2Repairer::new(dir, options);
    r.set_verify_rebuilt_slices_only(slices_only);
    r.load_par2_set(&dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    r.verify(None, &mut NullObserver).unwrap();
    let mut obs = ReadBack::default();
    let result = r.repair(&mut obs).unwrap();
    assert!(
        matches!(result, RepairResult::Repaired { .. }),
        "{result:?}"
    );
    (r, obs.max_permille)
}

#[test]
fn in_place_repair_reads_back_only_the_written_slices() {
    let (dir, a, _) = fixture("inplace", false);
    let (mut r, permille) = repair(&dir, true, RepairOptions::default());
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(r.last_repair_check(), Some(RepairCheck::RebuiltSlices));
    // Three of 49 slices were rewritten: about 6% of the file was read back.
    assert!(
        permille > 0 && permille < 100,
        "read back {permille} permille"
    );
    // Slice-verified is not purge-safe.
    let report = r.purge(&mut NullObserver);
    assert!(!report.entries.is_empty());
    assert!(
        report.kept().all(|(_, why)| *why == PurgeKept::NotVerified),
        "{report:?}"
    );
    assert!(dir.join("set.par2").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn default_check_reads_everything_and_stays_purge_safe() {
    let (dir, a, _) = fixture("full", false);
    let (mut r, permille) = repair(&dir, false, RepairOptions::default());
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(r.last_repair_check(), Some(RepairCheck::Full));
    assert_eq!(permille, 1000);
    assert!(r.purge(&mut NullObserver).all_removed());
    assert!(!dir.join("set.par2").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rebuilt_missing_files_are_read_back_in_full() {
    // `b.bin` is rebuilt from scratch, so every one of its slices was written.
    let (dir, a, b) = fixture("missing", true);
    let (r, permille) = repair(&dir, true, RepairOptions::default());
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b);
    assert_eq!(r.last_repair_check(), Some(RepairCheck::RebuiltSlices));
    // All of b (30,000 bytes) plus three slices of a, out of 230,000 bytes.
    assert!(
        (100..300).contains(&permille),
        "read back {permille} permille"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn no_read_back_without_verify_repaired() {
    let (dir, a, _) = fixture("skipped", false);
    let mut r = Par2Repairer::new(
        &dir,
        RepairOptions {
            verify_repaired: false,
            ..RepairOptions::default()
        },
    );
    assert_eq!(r.last_repair_check(), None);
    r.set_verify_rebuilt_slices_only(true);
    r.load_par2_set(&dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    r.verify(None, &mut NullObserver).unwrap();
    r.repair(&mut NullObserver).unwrap();
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(r.last_repair_check(), Some(RepairCheck::Skipped));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn quick_verified_files_are_read_back_in_full() {
    // Slices placed from download CRCs were never MD5-checked on disk, so the check reads
    // every slice of the file rather than trusting them.
    let (dir, a, _) = fixture("quick", false);
    let damaged = std::fs::read(dir.join("a.bin")).unwrap();
    let segments: Vec<Segment> = damaged
        .chunks(4096)
        .enumerate()
        .map(|(i, chunk)| Segment {
            offset: (i * 4096) as i64,
            size: chunk.len() as i64,
            crc: crc32(chunk),
            // The articles holding the three damaged bytes failed.
            success: ![1usize, 12, 36].contains(&i),
        })
        .collect();
    let mut r = Par2Repairer::new(&dir, RepairOptions::default());
    r.set_verify_rebuilt_slices_only(true);
    r.load_par2_set(&dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    let mut quick = |name: &str| -> Option<QuickInfo> {
        (name == "a.bin").then(|| QuickInfo::Partial {
            segments: segments.clone(),
        })
    };
    let v = r.verify(Some(&mut quick), &mut NullObserver).unwrap();
    assert_eq!(v.quick_verified_files, 1);
    let mut obs = ReadBack::default();
    r.repair(&mut obs).unwrap();
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(r.last_repair_check(), Some(RepairCheck::RebuiltSlices));
    assert_eq!(obs.max_permille, 1000);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn slices_located_by_an_ended_streaming_session_are_read_back() {
    // Streaming checks the bytes it is handed, not the file. Here it is handed the good bytes
    // of slice 1 while the file on disk keeps a bad slice 1 (the write "failed"), then the
    // session ends. Every slice is located, so the repair writes nothing; the slices-only
    // check must still read slice 1 and fail the repair.
    let (dir, a, _) = fixture("streamed", false);
    let mut damaged = a.clone();
    damaged[5000] ^= 0xFF;
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();
    let mut r = Par2Repairer::new(&dir, RepairOptions::default());
    r.set_verify_rebuilt_slices_only(true);
    r.load_par2_set(&dir.join("set.par2")).unwrap();
    r.finalize().unwrap();
    let fi = r
        .source_files()
        .iter()
        .position(|f| f.target_filename == "a.bin")
        .unwrap();
    r.enable_streaming(&StreamingOptions::default()).unwrap();
    r.streaming_segment_data(fi, 4096, &a[4096..8192]).unwrap();
    r.disable_streaming();
    let v = r.verify(None, &mut NullObserver).unwrap();
    assert_eq!(v.missing_blocks, 0, "{v:?}");
    match r.repair(&mut NullObserver) {
        Err(RepairError::VerificationFailed { files }) => assert_eq!(files, ["a.bin"]),
        other => panic!("corrupt slice was not read back: {other:?}"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
