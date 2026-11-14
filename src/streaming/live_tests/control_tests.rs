use super::*;

fn wait_until(mut ready: impl FnMut() -> bool) -> bool {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < end {
        if ready() {
            return true;
        }
        std::thread::yield_now();
    }
    false
}

fn cancel_inline_completion(donor: bool) {
    let tag = if donor {
        "cancel-inline-donor"
    } else {
        "cancel-inline-article"
    };
    let fx = fixture(tag, &[4096], 4096, 1, VolumeScheme::Uniform(1));
    let id = fid(&fx, &fx.files[0].0);
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            preallocated_syndrome_slots: 1,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    let slot = s.inner.slots.read().unwrap()[0].clone();
    let held = slot.lock().unwrap();
    std::thread::scope(|scope| {
        let op = scope.spawn(|| {
            if donor {
                s.try_splice_live_slice(
                    &id,
                    ByteRange::new(0, 4096),
                    &fx.files[0].1,
                    &fx.dir.join(&fx.files[0].0),
                )
                .map(|_| ())
            } else {
                s.on_article_finished(&id, 0, 4096, crc32(&fx.files[0].1), Some(&fx.files[0].1))
                    .map(|_| ())
            }
        });
        let reached = wait_until(|| s.status().verified == 1);
        s.cancel();
        drop(held);
        let result = op.join().unwrap();
        assert!(
            reached,
            "operation never reached the controlled fold boundary"
        );
        assert!(
            matches!(result, Err(RepairError::Cancelled)),
            "result: {result:?}"
        );
    });
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_review_cancelled_inline_article_never_publishes_success() {
    cancel_inline_completion(false);
}

#[test]
fn live_review_cancelled_inline_donor_never_publishes_success() {
    cancel_inline_completion(true);
}

#[test]
fn live_review_donor_reads_are_counted() {
    let fx = fixture(
        "donor-read-count",
        &[4096],
        4096,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fid(&fx, &fx.files[0].0);
    let path = fx.dir.join(&fx.files[0].0);
    write_at(&path, 0, &fx.files[0].1);
    write_at(&path, 128, &[0; 8]);
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    assert_eq!(
        s.try_splice_live_slice(&id, ByteRange::new(128, 8), &fx.files[0].1[128..136], &path)
            .unwrap(),
        vec![0]
    );
    assert_eq!(std::fs::read(&path).unwrap(), fx.files[0].1);
    assert_eq!(s.io_stats().source_bytes_read, 4096);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_review_failed_donor_candidate_observes_cancellation() {
    let fx = fixture(
        "cancel-bad-donor",
        &[4096],
        4096,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fid(&fx, &fx.files[0].0);
    let path = fx.dir.join(&fx.files[0].0);
    write_at(&path, 0, &fx.files[0].1);
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let tracker = s.inner.tracker.lock().unwrap();
    std::thread::scope(|scope| {
        let op = scope.spawn(|| {
            s.try_splice_live_slice(&id, ByteRange::new(0, 1), &[fx.files[0].1[0] ^ 1], &path)
        });
        let reached = wait_until(|| *s.inner.active_payloads.lock().unwrap() == 1);
        s.cancel();
        drop(tracker);
        let result = op.join().unwrap();
        assert!(reached);
        assert!(
            matches!(result, Err(RepairError::Cancelled)),
            "result: {result:?}"
        );
    });
    assert_eq!(std::fs::read(&path).unwrap(), fx.files[0].1);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_review_failed_disk_verification_does_not_retain_stale_coverage() {
    let fx = fixture(
        "coverage-io-error",
        &[65536; 4],
        65536,
        1,
        VolumeScheme::Uniform(1),
    );
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            max_working_bytes: (crate::hasher::READ_CHUNK + crate::packet::RESYNC_WINDOW) as u64,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    for (name, data) in &fx.files {
        let id = fid(&fx, name);
        for index in 0..3000 {
            s.on_article_finished(&id, index * 2, 1, 0, None).unwrap();
        }
        assert!(
            s.on_article_finished(&id, 0, 65536, crc32(data), None)
                .is_err()
        );
        let SliceState::PartiallyArrived { covered } = s.slice_state(&id, 0).unwrap() else {
            panic!("unread source must remain unverified");
        };
        assert_eq!(covered.len(), 1);
        assert_eq!(covered[0], ByteRange::new(0, 65536));
    }
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_review_donor_range_overflow_is_rejected_without_writes() {
    let fx = fixture("donor-overflow", &[4096], 4096, 1, VolumeScheme::Uniform(1));
    let id = fid(&fx, &fx.files[0].0);
    let path = fx.dir.join(&fx.files[0].0);
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    assert!(
        s.try_splice_live_slice(&id, ByteRange::new(i64::MAX, 1), &[0], &path)
            .is_err()
    );
    assert!(!path.exists());
    assert_eq!(s.status().unarrived, 1);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_counted_short_read_retains_successful_prefix_bytes() {
    let dir = std::env::temp_dir().join(format!("par-live-short-read-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("data");
    std::fs::write(&path, b"abc").unwrap();
    let control = LiveControl::default();
    let file = CountedFile::open(&path, &control, IoClass::Source).unwrap();
    assert!(file.read_at(0, &mut [0; 4]).is_err());
    assert_eq!(control.stats().source_bytes_read, 3);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn live_hosted_verified_donor_releases_crc_metadata_for_remaining_files() {
    let fx = fixture(
        "donor-crc-release",
        &[65536; 5],
        65536,
        1,
        VolumeScheme::Uniform(1),
    );
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            max_working_bytes: (crate::hasher::READ_CHUNK + crate::packet::RESYNC_WINDOW) as u64,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    for (name, data) in &fx.files {
        let id = fid(&fx, name);
        for offset in 0..3000 {
            s.on_article_finished(&id, offset, 1, 0, None).unwrap();
        }
        assert_eq!(
            s.try_splice_live_slice(&id, ByteRange::new(0, 65536), data, &fx.dir.join(name))
                .unwrap(),
            vec![0]
        );
    }
    assert_eq!(s.status().verified, 5);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_hosted_verified_rs_target_releases_crc_metadata_for_remaining_files() {
    let fx = fixture(
        "rs-crc-release",
        &[65536; 2],
        65536,
        2,
        VolumeScheme::Uniform(1),
    );
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            preallocated_syndrome_slots: 2,
            max_working_bytes: (crate::hasher::READ_CHUNK + crate::packet::RESYNC_WINDOW) as u64,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    let first = fid(&fx, &fx.files[0].0);
    let second = fid(&fx, &fx.files[1].0);
    for offset in 0..6000 {
        s.on_article_finished(&first, offset, 1, 0, None).unwrap();
    }
    for path in &fx.vols {
        s.on_recovery_volume_arrived(path, None).unwrap();
    }
    assert!(s.repair_available_targets_now(&[first]).unwrap().files[0].2);
    for offset in 0..3000 {
        s.on_article_finished(&second, offset, 1, 0, None).unwrap();
    }
    assert!(s.repair_available_targets_now(&[second]).unwrap().files[0].2);
    assert_eq!(
        std::fs::read(fx.dir.join(&fx.files[0].0)).unwrap(),
        fx.files[0].1
    );
    assert_eq!(
        std::fs::read(fx.dir.join(&fx.files[1].0)).unwrap(),
        fx.files[1].1
    );
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_cancel_refuses_work_without_writes() {
    let fx = fixture(
        "cancel-admission",
        &[4096],
        4096,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fid(&fx, &fx.files[0].0);
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    s.cancel();
    assert!(s.is_cancelled());
    assert!(matches!(
        s.on_article_finished(&id, 0, 4096, crc32(&fx.files[0].1), Some(&fx.files[0].1)),
        Err(RepairError::Cancelled)
    ));
    assert!(matches!(
        s.on_recovery_volume_arrived(&fx.vols[0], None),
        Err(RepairError::Cancelled)
    ));
    assert!(matches!(
        s.repair_available_targets_now(&[id]),
        Err(RepairError::Cancelled)
    ));
    assert!(!fx.dir.join(&fx.files[0].0).exists());
    assert_eq!(s.status().verified, 0);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_io_separates_ram_backfill_and_target_verification() {
    let fx = fixture(
        "io-classes",
        &[8192, 4096],
        4096,
        2,
        VolumeScheme::Uniform(1),
    );
    let id0 = fid(&fx, &fx.files[0].0);
    let id1 = fid(&fx, &fx.files[1].0);
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            preallocated_syndrome_slots: 1,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    let first = &fx.files[0].1[..4096];
    write_at(&fx.dir.join(&fx.files[0].0), 0, first);
    for _ in 0..2 {
        s.on_article_finished(&id0, 0, 4096, crc32(first), Some(first))
            .unwrap();
    }
    write_at(&fx.dir.join(&fx.files[1].0), 0, &fx.files[1].1);
    s.on_article_finished(&id1, 0, 4096, crc32(&fx.files[1].1), None)
        .unwrap();
    s.on_article_failed_permanently(&id0, 4096, 4096).unwrap();
    s.on_recovery_volume_arrived(&fx.vols[1], None).unwrap();
    s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap();
    let before = s.io_stats();
    assert_eq!(before.ram_bytes_verified, 4096);
    assert_eq!(before.source_bytes_read, 4096);
    assert_eq!(before.backfill_bytes_read, 8192);
    assert_eq!(before.target_verification_bytes_read, 0);
    assert!(before.recovery_bytes_read >= 8192);
    let report = s.repair_available_targets_now(&[id0]).unwrap();
    assert!(report.files[0].2);
    assert_eq!(
        std::fs::read(fx.dir.join(&fx.files[0].0)).unwrap(),
        fx.files[0].1
    );
    let after = s.io_stats();
    assert_eq!(after.source_bytes_read, before.source_bytes_read);
    assert_eq!(after.backfill_bytes_read, before.backfill_bytes_read);
    assert_eq!(after.target_verification_bytes_read, 8192);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_part40_global_repair_needs_rank_and_no_other_sources() {
    let fx = fixture(
        "part40-global",
        &[1024; 100],
        1024,
        1,
        VolumeScheme::Uniform(1),
    );
    let target = fid(&fx, &fx.files[39].0);
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            preallocated_syndrome_slots: 1,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    for (name, data) in &fx.files[..39] {
        write_at(&fx.dir.join(name), 0, data);
        s.on_article_finished(&fid(&fx, name), 0, 1024, crc32(data), Some(data))
            .unwrap();
    }
    s.on_article_failed_permanently(&target, 0, 1024).unwrap();
    s.on_recovery_volume_arrived(&fx.vols[0], None).unwrap();
    assert_eq!(s.status().unarrived + s.status().damaged, 61);
    assert!(!s.status().early_cutover_possible);
    assert!(matches!(
        s.repair_available_targets_now(&[target]),
        Err(RepairError::NotEnoughRecovery {
            needed: 61,
            available: 1
        })
    ));
    assert!(!fx.dir.join(&fx.files[39].0).exists());
    for (name, data) in &fx.files[40..] {
        write_at(&fx.dir.join(name), 0, data);
        s.on_article_finished(&fid(&fx, name), 0, 1024, crc32(data), Some(data))
            .unwrap();
    }
    s.flush();
    // Make a final read of any other source an actual I/O failure.
    for (i, (name, _)) in fx.files.iter().enumerate() {
        if i != 39 {
            std::fs::remove_file(fx.dir.join(name)).unwrap();
        }
    }
    assert!(s.status().early_cutover_possible);
    let rep = s.repair_available_targets_now(&[target]).unwrap();
    assert_eq!(rep.repaired_slices.len(), 1);
    assert!(rep.files[0].2);
    assert_eq!(
        std::fs::read(fx.dir.join(&fx.files[39].0)).unwrap(),
        fx.files[39].1
    );
    let io = s.io_stats();
    assert_eq!(io.ram_bytes_verified, 99 * 1024);
    assert_eq!(io.source_bytes_read, 0);
    assert_eq!(io.backfill_bytes_read, 0);
    assert_eq!(io.target_verification_bytes_read, 1024);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_rejects_invalid_geometry_before_allocating() {
    let mut fx = fixture(
        "duplicate-geometry",
        &[4096],
        4096,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fx.set.main.as_ref().unwrap().recoverable_file_ids[0];
    fx.set.main.as_mut().unwrap().recoverable_file_ids.push(id);
    assert!(StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).is_err());
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_rejects_truncated_ram_payload_before_state_change() {
    let fx = fixture("short-ram", &[4096], 4096, 1, VolumeScheme::Uniform(1));
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let id = fid(&fx, &fx.files[0].0);
    assert!(
        s.on_article_finished(&id, 0, 4096, 0, Some(&[0; 4095]))
            .is_err()
    );
    assert_eq!(s.status().unarrived, 1);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_rejects_offset_overflow_before_state_change() {
    let fx = fixture("range-overflow", &[4096], 4096, 1, VolumeScheme::Uniform(1));
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let id = fid(&fx, &fx.files[0].0);
    assert!(s.on_article_finished(&id, 1, u64::MAX, 0, None).is_err());
    assert_eq!(s.status().unarrived, 1);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_partial_replays_are_bounded_without_rejecting_duplicates() {
    let fx = fixture(
        "partial-metadata",
        &[65536],
        65536,
        1,
        VolumeScheme::Uniform(1),
    );
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            max_working_bytes: (crate::hasher::READ_CHUNK + crate::packet::RESYNC_WINDOW) as u64,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    let id = fid(&fx, &fx.files[0].0);
    for _ in 0..10000 {
        s.on_article_finished(&id, 0, 1, 0, Some(&[0])).unwrap();
    }
    let mut refused = false;
    for offset in 1..60000 {
        match s.on_article_finished(&id, offset, 1, 0, Some(&[0])) {
            Err(RepairError::StreamingMemoryLimit { .. }) => {
                refused = true;
                break;
            }
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert!(
        refused,
        "partial article metadata must have bounded admission"
    );
    assert_eq!(s.status().verified, 0);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}
