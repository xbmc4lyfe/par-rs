//! Patched ranges ([`StreamingParSession::on_range_replaced`]): the caller rewrites bytes of
//! a target file mid-download, and live repair reconciles only the slices the range touches.

use super::stress_tests::Rng;
use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// `metadata_entries` and `staging_bytes` must equal what the tracker actually holds.
fn assert_accounting_exact(s: &StreamingParSession) {
    let t = s.inner.tracker.lock().unwrap();
    let held: usize = t.covered.iter().map(Vec::len).sum::<usize>()
        + t.article_crcs.iter().map(Vec::len).sum::<usize>()
        + t.staging.values().map(|st| st.ranges.len()).sum::<usize>();
    assert_eq!(t.metadata_entries, held);
    let bytes: u64 = t.staging.values().map(|st| st.pieces.held() as u64).sum();
    assert_eq!(t.staging_bytes, bytes);
}

/// State and staged bytes with their ranges, of one slice.
type SliceSnapshot = (SliceState, Option<(usize, Vec<ByteRange>)>);

/// State and staging of every slice, by global index.
fn snapshot(s: &StreamingParSession) -> Vec<SliceSnapshot> {
    let t = s.inner.tracker.lock().unwrap();
    (0..t.states.len())
        .map(|g| {
            (
                t.states[g].clone(),
                t.staging
                    .get(&g)
                    .map(|st| (st.pieces.held(), st.ranges.clone())),
            )
        })
        .collect()
}

/// Deliver `data[lo..hi]` of file `fi` as an on-disk article with its RAM bytes.
fn deliver(s: &StreamingParSession, fx: &Fx, fi: usize, lo: usize, hi: usize) {
    let (name, data) = &fx.files[fi];
    let part = &data[lo..hi];
    write_at(&fx.dir.join(name), lo as u64, part);
    s.on_article_finished(
        &fid(fx, name),
        lo as u64,
        part.len() as u64,
        crc32(part),
        Some(part),
    )
    .unwrap();
}

/// Write the original bytes `[lo, hi)` of file `fi` back to disk and report the patch.
fn patch(
    s: &StreamingParSession,
    fx: &Fx,
    fi: usize,
    lo: usize,
    hi: usize,
    with_bytes: bool,
) -> RangeOutcome {
    let (name, data) = &fx.files[fi];
    let part = &data[lo..hi];
    write_at(&fx.dir.join(name), lo as u64, part);
    s.on_range_replaced(
        &fid(fx, name),
        lo as u64,
        part.len() as u64,
        with_bytes.then_some(part),
    )
    .unwrap()
}

/// Global slice index of slice `b` of `id`.
fn global(s: &StreamingParSession, id: &FileId, b: usize) -> usize {
    s.inner.files[s.inner.file_index[id]].first_slice + b
}

/// A cold verify of the target files: whether each slice (by global index) matches the
/// original bytes.
fn cold_verify(s: &StreamingParSession, fx: &Fx, slice: usize) -> BTreeMap<usize, bool> {
    let mut out = BTreeMap::new();
    for (name, data) in &fx.files {
        let disk = std::fs::read(fx.dir.join(name)).unwrap_or_default();
        for (b, lo) in (0..data.len()).step_by(slice).enumerate() {
            let hi = (lo + slice).min(data.len());
            out.insert(
                global(s, &fid(fx, name), b),
                disk.get(lo..hi) == Some(&data[lo..hi]),
            );
        }
    }
    out
}

#[test]
fn live_patch_three_ranges_keeps_other_staged_work() {
    const SS: usize = 1024;
    let fx = fixture(
        "patch-three",
        &[5 * SS + 300, 3 * SS, 2 * SS + 100],
        SS as u64,
        3,
        VolumeScheme::Uniform(1),
    );
    let ids: Vec<FileId> = fx.files.iter().map(|(n, _)| fid(&fx, n)).collect();
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    // 640-byte articles. File 0: articles 0..=5 and 7 (slices 0..=2 verified, 3 and 4 partly
    // staged, 5 unarrived). File 1: every article but [1280, 1920) (slice 1 partly staged).
    // File 2: a RAM-only piece in slice 0 and a lost range in slice 1.
    for a in (0..=5).chain([7]) {
        deliver(&s, &fx, 0, a * 640, (a + 1) * 640);
    }
    for a in [0, 1, 3, 4] {
        deliver(&s, &fx, 1, a * 640, ((a + 1) * 640).min(3 * SS));
    }
    let ram = &fx.files[2].1[..640];
    s.on_article_finished_memory_only(&ids[2], 0, ram, crc32(ram))
        .unwrap();
    s.on_article_failed_permanently(&ids[2], 1100, 200).unwrap();
    s.flush();
    let before = snapshot(&s);
    let folds = s.fold_stats().0;
    assert_eq!(s.status().verified, 5);
    assert_accounting_exact(&s);
    let f0s3 = global(&s, &ids[0], 3);
    assert_eq!(before[f0s3].1.as_ref().unwrap().0, 3840 - 3072);

    // Inside one partly staged slice, with the bytes: they replace the staged ones.
    let r = patch(&s, &fx, 0, 3200, 3500, true);
    assert_eq!(r.slices, vec![(3, PatchedSlice::Pending)]);
    assert!(r.is_reconciled());
    assert_eq!(snapshot(&s)[f0s3], before[f0s3]);
    // Across a verified slice and a staged one, read back from disk: the verified slice
    // still matches, and the staged bytes inside the range are dropped for the disk copy.
    let r = patch(&s, &fx, 0, 2900, 3300, false);
    assert_eq!(
        r.slices,
        vec![(2, PatchedSlice::Unchanged), (3, PatchedSlice::Pending)]
    );
    assert_eq!(
        snapshot(&s)[f0s3].1,
        Some((3840 - 3300, vec![ByteRange::new(3300 - 3072, 3840 - 3300)]))
    );
    // A whole volume: its verified slices are unchanged and its partial slice completes.
    let r = patch(&s, &fx, 1, 0, 3 * SS, true);
    assert_eq!(
        r.slices,
        vec![
            (0, PatchedSlice::Unchanged),
            (1, PatchedSlice::NewlyVerified),
            (2, PatchedSlice::Unchanged),
        ]
    );
    s.flush();
    assert_eq!(
        s.fold_stats().0,
        folds + 1,
        "only the completed slice folds"
    );
    assert_accounting_exact(&s);

    // No staged work outside the patched slices was dropped or changed.
    let after = snapshot(&s);
    let patched: Vec<usize> = [(0, 2), (0, 3), (1, 0), (1, 1), (1, 2)]
        .iter()
        .map(|&(fi, b)| global(&s, &ids[fi], b))
        .collect();
    for (g, (was, now)) in before.iter().zip(&after).enumerate() {
        if !patched.contains(&g) {
            assert_eq!(was, now, "slice {g} changed");
        }
    }
    assert!(after[global(&s, &ids[0], 4)].1.is_some());
    assert!(after[global(&s, &ids[2], 0)].1.is_some());

    // The rest arrives; the RAM-only piece reaches disk before recovery back-fills.
    deliver(&s, &fx, 0, 6 * 640, 7 * 640);
    deliver(&s, &fx, 0, 8 * 640, 5 * SS + 300);
    deliver(&s, &fx, 2, 640, 1100);
    deliver(&s, &fx, 2, 1300, 2 * SS + 100);
    write_at(&fx.dir.join(&fx.files[2].0), 0, ram);
    for v in &fx.vols {
        s.on_recovery_volume_arrived(v, None).unwrap();
    }
    s.flush();
    // The live verdict equals a cold verify of the files.
    let cold = cold_verify(&s, &fx, SS);
    let live = snapshot(&s);
    assert_eq!(cold.len(), live.len());
    for (g, (state, _)) in live.iter().enumerate() {
        assert_eq!(
            *state == SliceState::VerifiedGood,
            cold[&g],
            "slice {g}: live {state:?}"
        );
    }
    assert_eq!(s.status().damaged, 1);
    assert_eq!(s.staging_bytes(), 0);
    let rep = s.repair_available_targets_now(&ids).unwrap();
    assert_eq!(rep.repaired_slices, vec![(ids[2], 1)]);
    for (name, data) in &fx.files {
        assert_eq!(std::fs::read(fx.dir.join(name)).unwrap(), *data, "{name}");
    }
    assert!(
        rep.files
            .iter()
            .all(|(_, st, ok)| *ok && *st == VolumeStatus::CompleteAndVerified)
    );
    assert!(cold_verify(&s, &fx, SS).values().all(|ok| *ok));
    assert_accounting_exact(&s);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_patch_changing_a_verified_slice_is_unreconcilable_without_corruption() {
    let fx = fixture(
        "patch-diverge",
        &[4096, 2048],
        1024,
        2,
        VolumeScheme::Uniform(1),
    );
    let ids: Vec<FileId> = fx.files.iter().map(|(n, _)| fid(&fx, n)).collect();
    let path = fx.dir.join(&fx.files[0].0);
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    deliver(&s, &fx, 0, 0, 4096);
    deliver(&s, &fx, 1, 0, 1024);
    s.on_article_failed_permanently(&ids[1], 1024, 1024)
        .unwrap();
    let folds = s.fold_stats().0;

    // New bytes that differ from what was verified, given in RAM.
    let mut wrong = fx.files[0].1[100..200].to_vec();
    wrong[7] ^= 0x5a;
    write_at(&path, 100, &wrong);
    let r = s
        .on_range_replaced(&ids[0], 100, 100, Some(&wrong))
        .unwrap();
    assert_eq!(r.slices, vec![(0, PatchedSlice::Unreconcilable)]);
    assert!(!r.is_reconciled());
    assert_eq!(r.unreconcilable().collect::<Vec<_>>(), vec![0]);
    // The same, read back from disk, across two slices: only the changed one diverges.
    let mut wrong = fx.files[0].1[2000..2100].to_vec();
    wrong[90] ^= 1;
    write_at(&path, 2000, &wrong);
    let r = s.on_range_replaced(&ids[0], 2000, 100, None).unwrap();
    assert_eq!(
        r.slices,
        vec![
            (1, PatchedSlice::Unchanged),
            (2, PatchedSlice::Unreconcilable)
        ]
    );
    // Nothing was folded or unfolded, and the file never reports complete.
    assert_eq!(s.fold_stats().0, folds);
    assert_eq!(s.status().verified, 5);
    assert_eq!(
        s.volume_status(&ids[0]).unwrap(),
        VolumeStatus::Incomplete {
            verified: 2,
            damaged: 2,
            unarrived: 0
        }
    );

    // The syndromes still hold the verified content, so another file repairs correctly.
    for v in &fx.vols {
        s.on_recovery_volume_arrived(v, None).unwrap();
    }
    let rep = s.repair_available_targets_now(&ids).unwrap();
    assert_eq!(rep.repaired_slices, vec![(ids[1], 1)]);
    assert_eq!(
        std::fs::read(fx.dir.join(&fx.files[1].0)).unwrap(),
        fx.files[1].1
    );
    assert!(!rep.files[0].2, "a diverged file must not verify");
    assert!(rep.files[1].2);

    // Restoring the verified content reconciles both slices again.
    let r = patch(&s, &fx, 0, 0, 4096, false);
    assert!(r.slices.iter().all(|(_, o)| *o == PatchedSlice::Unchanged));
    assert_eq!(
        s.volume_status(&ids[0]).unwrap(),
        VolumeStatus::CompleteAndVerified
    );
    let rep = s.repair_available_targets_now(&ids[..1]).unwrap();
    assert!(rep.files[0].2);
    assert_accounting_exact(&s);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_patch_fills_damaged_slices_so_they_verify() {
    let fx = fixture("patch-heal", &[3072], 1024, 1, VolumeScheme::Uniform(1));
    let id = fid(&fx, &fx.files[0].0);
    let path = fx.dir.join(&fx.files[0].0);
    let data = fx.files[0].1.clone();
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    // A lost article damages slices 0 and 1; a corrupt one damages slice 2.
    deliver(&s, &fx, 0, 0, 1000);
    s.on_article_failed_permanently(&id, 1000, 100).unwrap();
    deliver(&s, &fx, 0, 1100, 2100);
    let mut bad = data[2100..2300].to_vec();
    bad[60] ^= 0xff;
    write_at(&path, 2100, &bad);
    s.on_article_finished(&id, 2100, 200, crc32(&bad), Some(&bad))
        .unwrap();
    deliver(&s, &fx, 0, 2300, 3072);
    assert_eq!(s.status().damaged, 3);
    let folds = s.fold_stats().0;

    // A patch beside the corrupt byte leaves slice 2 damaged.
    let r = patch(&s, &fx, 0, 2250, 2260, true);
    assert_eq!(r.slices, vec![(2, PatchedSlice::Damaged)]);
    // The stream-repaired lost article fills the hole: both slices verify.
    let r = patch(&s, &fx, 0, 1000, 1100, false);
    assert_eq!(
        r.slices,
        vec![
            (0, PatchedSlice::NewlyVerified),
            (1, PatchedSlice::NewlyVerified)
        ]
    );
    // Rewriting the corrupt byte heals slice 2.
    let r = patch(&s, &fx, 0, 2150, 2200, true);
    assert_eq!(r.slices, vec![(2, PatchedSlice::NewlyVerified)]);
    s.flush();
    let st = s.status();
    assert_eq!((st.verified, st.damaged), (3, 0));
    assert_eq!(st.needed_recovery_blocks, 0);
    assert_eq!(s.fold_stats().0, folds + 3);
    // Nothing is left to rebuild: no recovery volume is needed for a verified file.
    let rep = s.repair_available_targets_now(&[id]).unwrap();
    assert_eq!(rep.erasures, 0);
    assert!(rep.files[0].2);
    assert_accounting_exact(&s);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_patch_read_from_disk_replaces_staged_ram_bytes() {
    let fx = fixture("patch-ram", &[4096], 4096, 0, VolumeScheme::Single);
    let id = fid(&fx, &fx.files[0].0);
    let path = fx.dir.join(&fx.files[0].0);
    let data = fx.files[0].1.clone();
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    // A RAM-only piece with a bad byte is staged; it never reaches disk.
    let mut bad = data[..2048].to_vec();
    bad[500] ^= 1;
    s.on_article_finished_memory_only(&id, 0, &bad, crc32(&bad))
        .unwrap();
    assert_eq!(s.staging_bytes(), 2048);
    // The writer patches the first KiB on disk: the staged copy of that range is stale.
    write_at(&path, 0, &data[..1024]);
    let r = s.on_range_replaced(&id, 0, 1024, None).unwrap();
    assert_eq!(r.slices, vec![(0, PatchedSlice::Pending)]);
    assert_eq!(s.staging_bytes(), 1024);
    assert_accounting_exact(&s);
    // The rest arrives on disk; the slice completes from the kept RAM bytes and the disk.
    deliver(&s, &fx, 0, 2048, 4096);
    assert_eq!(s.status().verified, 1);
    assert_eq!(s.staging_bytes(), 0);
    assert_accounting_exact(&s);
    // An empty or out-of-file range touches nothing.
    assert_eq!(
        s.on_range_replaced(&id, 10, 0, None).unwrap(),
        RangeOutcome::default()
    );
    assert_eq!(
        s.on_range_replaced(&id, 5000, 10, None).unwrap(),
        RangeOutcome::default()
    );
    assert!(s.on_range_replaced(&id, 0, 10, Some(&[0; 4])).is_err());
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_patches_race_article_completions() {
    // Writers deliver articles while another thread keeps patching ranges with the original
    // bytes, so patches land between a completion's bookkeeping and its verification.
    const SS: usize = 512;
    for round in 0..8u64 {
        let fx = fixture(
            &format!("patch-race-{round}"),
            &[40 * SS + 100, 24 * SS],
            SS as u64,
            0,
            VolumeScheme::Single,
        );
        let s = StreamingParSession::new(
            &fx.set,
            &fx.dir,
            SessionOptions {
                fold_threads: (round % 2) as usize * 2,
                ..SessionOptions::default()
            },
        )
        .unwrap();
        let mut articles = Vec::new();
        for (fi, (_, data)) in fx.files.iter().enumerate() {
            let mut off = 0;
            let mut rng = Rng(round * 31 + fi as u64 + 1);
            while off < data.len() {
                let len = (rng.range(1, 3 * SS as u64 / 2) as usize).min(data.len() - off);
                articles.push((fi, off, len));
                off += len;
            }
        }
        let order = shuffled(articles.len(), round + 7);
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let writers: Vec<_> = (0..2)
                .map(|lane| {
                    let (s, fx, articles, order) = (&s, &fx, &articles, &order);
                    scope.spawn(move || {
                        for &i in order.iter().skip(lane).step_by(2) {
                            let (fi, off, len) = articles[i];
                            deliver(s, fx, fi, off, off + len);
                        }
                    })
                })
                .collect();
            let (s, fx, done) = (&s, &fx, &done);
            scope.spawn(move || {
                let mut rng = Rng(round + 99);
                while !done.load(Ordering::Acquire) {
                    let fi = (rng.next() % 2) as usize;
                    let n = fx.files[fi].1.len() as u64;
                    let lo = rng.range(0, n - 1);
                    let hi = rng.range(lo + 1, (lo + 3 * SS as u64).min(n));
                    let r = patch(s, fx, fi, lo as usize, hi as usize, rng.chance(50));
                    assert!(r.is_reconciled(), "{:?}", r.slices);
                }
            });
            for w in writers {
                w.join().unwrap();
            }
            done.store(true, Ordering::Release);
        });
        s.flush();
        let st = s.status();
        assert_eq!((st.verified, st.damaged), (st.total, 0), "round {round}");
        assert_eq!(s.staging_bytes(), 0);
        assert_accounting_exact(&s);
        let ids: Vec<FileId> = fx.files.iter().map(|(n, _)| fid(&fx, n)).collect();
        let rep = s.repair_available_targets_now(&ids).unwrap();
        assert!(rep.files.iter().all(|(_, _, ok)| *ok), "round {round}");
        std::fs::remove_dir_all(&fx.dir).unwrap();
    }
}
