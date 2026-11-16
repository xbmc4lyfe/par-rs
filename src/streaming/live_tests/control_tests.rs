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
    assert_eq!(s.repair_phase_stats(), RepairPhaseStats::default());
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
    let refused = s.repair_phase_stats();
    assert_eq!(refused.attempts, 1);
    assert_eq!(refused.completed, 0);
    assert_eq!(refused.target_bytes_written, 0);
    assert!(refused.total_ns > 0);
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
    let phases = s.repair_phase_stats();
    assert_eq!(phases.attempts, 2);
    assert_eq!(phases.completed, 1);
    assert_eq!(phases.target_bytes_written, 1024);
    assert!(phases.matrix_ns > 0 && phases.decode_ns > 0);
    assert!(phases.target_write_ns > 0 && phases.target_sync_ns > 0);
    assert!(phases.refold_ns > 0 && phases.target_verification_ns > 0);
    assert!(phases.total_ns >= phases.decode_ns);
    assert!(phases.decode_ns >= phases.target_write_ns);
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

#[test]
fn live_ram_only_pressure_never_reads_an_uncommitted_source() {
    let fx = fixture(
        "ram-only-pressure",
        &[8192],
        4096,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fid(&fx, &fx.files[0].0);
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            max_staging_bytes: 2048,
            preallocated_syndrome_slots: 1,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    let data = &fx.files[0].1;
    s.on_article_finished_memory_only(&id, 0, &data[..2048], crc32(&data[..2048]))
        .unwrap();
    let before = s.status();
    let refused =
        s.on_article_finished_memory_only(&id, 4096, &data[4096..6144], crc32(&data[4096..6144]));
    assert!(matches!(
        refused,
        Err(RepairError::StreamingMemoryLimit { .. })
    ));
    assert_eq!(
        s.status(),
        before,
        "refusal must not accept coverage or mark damage"
    );
    s.on_article_finished_memory_only(&id, 2048, &data[2048..4096], crc32(&data[2048..4096]))
        .unwrap();
    s.on_article_finished_memory_only(&id, 4096, &data[4096..6144], crc32(&data[4096..6144]))
        .unwrap();
    s.on_article_finished_memory_only(&id, 6144, &data[6144..], crc32(&data[6144..]))
        .unwrap();
    assert_eq!(s.status().verified, 2);
    assert_eq!(s.io_stats().source_bytes_read, 0);
    assert!(!fx.dir.join(&fx.files[0].0).exists());
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_ram_only_full_slices_work_without_staging_or_target_files() {
    let fx = fixture("ram-only-whole", &[8192], 4096, 1, VolumeScheme::Uniform(1));
    let id = fid(&fx, &fx.files[0].0);
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            max_staging_bytes: 0,
            preallocated_syndrome_slots: 1,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    s.on_article_finished_memory_only(&id, 0, &fx.files[0].1, crc32(&fx.files[0].1))
        .unwrap();
    assert_eq!(s.status().verified, 2);
    assert_eq!(s.io_stats().ram_bytes_verified, 8192);
    assert_eq!(s.io_stats().source_bytes_read, 0);
    s.cancel();
    assert!(matches!(
        s.on_article_finished_memory_only(&id, 0, &fx.files[0].1, crc32(&fx.files[0].1)),
        Err(RepairError::Cancelled)
    ));
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_ram_only_whole_slice_does_not_starve_the_adjacent_partial_slice() {
    let fx = fixture(
        "ram-only-adjacent",
        &[8192],
        4096,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fid(&fx, &fx.files[0].0);
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            max_staging_bytes: 4096,
            preallocated_syndrome_slots: 1,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    let data = &fx.files[0].1;
    s.on_article_finished_memory_only(&id, 0, &data[..6144], crc32(&data[..6144]))
        .unwrap();
    s.on_article_finished_memory_only(&id, 6144, &data[6144..], crc32(&data[6144..]))
        .unwrap();
    assert_eq!(s.status().verified, 2);
    assert_eq!(s.io_stats().source_bytes_read, 0);
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_ram_only_does_not_complete_coverage_previously_accepted_without_ram() {
    let fx = fixture(
        "ram-only-legacy",
        &[4096],
        4096,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fid(&fx, &fx.files[0].0);
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    s.on_article_finished(&id, 0, 2048, crc32(&fx.files[0].1[..2048]), None)
        .unwrap();
    let before = s.status();
    assert!(
        s.on_article_finished_memory_only(
            &id,
            2048,
            &fx.files[0].1[2048..],
            crc32(&fx.files[0].1[2048..])
        )
        .is_err()
    );
    assert_eq!(s.status(), before);
    assert_eq!(s.io_stats().source_bytes_read, 0);
    s.on_article_finished_memory_only(&id, 0, &fx.files[0].1, crc32(&fx.files[0].1))
        .unwrap();
    assert_eq!(s.status().verified, 1);
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_repair_phase_stats_preserve_the_verify_only_path() {
    let fx = fixture(
        "repair-phase-verify-only",
        &[4096],
        4096,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fid(&fx, &fx.files[0].0);
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    write_at(&fx.dir.join(&fx.files[0].0), 0, &fx.files[0].1);
    s.on_article_finished_memory_only(&id, 0, &fx.files[0].1, crc32(&fx.files[0].1))
        .unwrap();
    let report = s.repair_available_targets_now(&[id]).unwrap();
    assert!(report.files[0].2);
    let phases = s.repair_phase_stats();
    assert_eq!(phases.attempts, 1);
    assert_eq!(phases.completed, 1);
    assert_eq!(phases.target_bytes_written, 0);
    assert_eq!(phases.decode_ns, 0);
    assert_eq!(phases.target_write_ns, 0);
    assert!(phases.target_verification_ns > 0);
    assert_eq!(s.io_stats().target_verification_bytes_read, 4096);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_target_hashes_reuse_the_required_verification_read() {
    let fx = fixture(
        "target-hashes",
        &[777, 1024],
        1024,
        1,
        VolumeScheme::Uniform(1),
    );
    let target = fid(&fx, &fx.files[0].0);
    let other = fid(&fx, &fx.files[1].0);
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    session
        .on_article_finished_memory_only(&other, 0, &fx.files[1].1, crc32(&fx.files[1].1))
        .unwrap();
    session
        .on_recovery_volume_arrived(&fx.vols[0], None)
        .unwrap();
    let (report, hashes) = session
        .repair_available_targets_with_hashes_now(&[target])
        .unwrap();
    assert!(report.files[0].2);
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].0, target);
    assert_eq!(hashes[0].1.crc32, crc32(&fx.files[0].1));
    assert_eq!(hashes[0].1.len, 777);
    assert_eq!(hashes[0].1.md5_full, fx.set.file_descs[&target].hash_full);
    assert_eq!(
        std::fs::read(fx.dir.join(&fx.files[0].0)).unwrap(),
        fx.files[0].1
    );
    assert_eq!(session.io_stats().target_verification_bytes_read, 777);
    assert_eq!(session.io_stats().source_bytes_read, 0);
    let (_, hashes) = session
        .repair_available_targets_with_hashes_now(&[target])
        .unwrap();
    assert_eq!(hashes[0].1.len, 777);
    assert_eq!(session.io_stats().target_verification_bytes_read, 1554);
    // Verified slice state cannot authorize a changed target's CRC or wrong length.
    std::fs::write(fx.dir.join(&fx.files[0].0), vec![0; 777]).unwrap();
    let (report, hashes) = session
        .repair_available_targets_with_hashes_now(&[target])
        .unwrap();
    assert!(!report.files[0].2);
    assert!(hashes.is_empty());
    let mut extra = fx.files[0].1.clone();
    extra.push(0);
    std::fs::write(fx.dir.join(&fx.files[0].0), extra).unwrap();
    let (report, hashes) = session
        .repair_available_targets_with_hashes_now(&[target])
        .unwrap();
    assert!(!report.files[0].2);
    assert!(hashes.is_empty());
    session.cancel();
    assert!(matches!(
        session.repair_available_targets_with_hashes_now(&[target]),
        Err(RepairError::Cancelled)
    ));
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_repair_phase_stats_count_cancelled_attempts_without_writes() {
    let fx = fixture(
        "repair-phase-cancelled",
        &[4096],
        4096,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fid(&fx, &fx.files[0].0);
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    session.cancel();
    assert!(matches!(
        session.repair_available_targets_now(&[id]),
        Err(RepairError::Cancelled)
    ));
    let phases = session.repair_phase_stats();
    assert_eq!(phases.attempts, 1);
    assert_eq!(phases.completed, 0);
    assert_eq!(phases.target_bytes_written, 0);
    assert_eq!(phases.matrix_ns, 0);
    assert_eq!(phases.decode_ns, 0);
    assert_eq!(phases.target_verification_ns, 0);
    assert!(phases.total_ns > 0);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

// Change bytes while preserving CRC32, so backfill must also check IFSC MD5.
fn different_bytes_with_same_crc(data: &[u8]) -> Vec<u8> {
    assert!(data.len() >= 5);
    let mut changed = data.to_vec();
    changed[0] ^= 1;
    let tail = changed.len() - 4;
    changed[tail..].fill(0);
    let base = crc32(&changed);
    let mut basis = [(0u32, 0u32); 32];
    for bit in 0..32 {
        changed[tail + bit / 8] ^= 1 << (bit % 8);
        let mut value = crc32(&changed) ^ base;
        changed[tail + bit / 8] ^= 1 << (bit % 8);
        let mut patch = 1u32 << bit;
        while value != 0 {
            let pivot = (31 - value.leading_zeros()) as usize;
            if basis[pivot].0 == 0 {
                basis[pivot] = (value, patch);
                break;
            }
            value ^= basis[pivot].0;
            patch ^= basis[pivot].1;
        }
    }
    let mut delta = crc32(data) ^ base;
    let mut patch = 0u32;
    while delta != 0 {
        let pivot = (31 - delta.leading_zeros()) as usize;
        assert_ne!(basis[pivot].0, 0);
        delta ^= basis[pivot].0;
        patch ^= basis[pivot].1;
    }
    changed[tail..].copy_from_slice(&patch.to_le_bytes());
    assert_ne!(changed, data);
    assert_eq!(crc32(&changed), crc32(data));
    changed
}

fn late_backfill_refuses_stale_disk_then_retries(mode: &str) {
    let fx = fixture(
        &format!("authenticated-backfill-{mode}"),
        &[2049, 777, 1000],
        1024,
        5,
        VolumeScheme::Uniform(1),
    );
    let session = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            preallocated_syndrome_slots: 4,
            max_syndrome_slots: 5,
            fold_threads: 0,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    let late = fx
        .vols
        .iter()
        .find(|path| {
            load_par2_file(path, ScanOptions::FULL)
                .unwrap()
                .recovery
                .contains_key(&4)
        })
        .unwrap();
    let known = &fx.files[..2];
    // Ensure at least one original row is successfully backfilled before refusal.
    let stale = known
        .iter()
        .max_by_key(|(name, _)| {
            session.inner.files[session.inner.file_index[&fid(&fx, name)]].first_slice
        })
        .unwrap();
    for (name, data) in known {
        let id = fid(&fx, name);
        for (index, chunk) in data.chunks(1024).enumerate() {
            session
                .on_article_finished_memory_only(&id, (index * 1024) as u64, chunk, crc32(chunk))
                .unwrap();
        }
        std::fs::write(fx.dir.join(name), data).unwrap();
    }
    assert_eq!(session.io_stats().source_bytes_read, 0);
    let stale_path = fx.dir.join(&stale.0);
    let stale_id = fid(&fx, &stale.0);
    let stale_global = session.inner.files[session.inner.file_index[&stale_id]].first_slice;
    match mode {
        "sparse" => {
            let file = std::fs::File::create(&stale_path).unwrap();
            file.set_len(stale.1.len() as u64).unwrap();
        }
        "same-crc" => {
            let mut bad = stale.1.clone();
            let size = bad.len().min(1024);
            bad[..size].copy_from_slice(&different_bytes_with_same_crc(&stale.1[..size]));
            std::fs::write(&stale_path, bad).unwrap();
        }
        "truncated" => {
            std::fs::File::create(&stale_path).unwrap();
        }
        _ => unreachable!(),
    }
    let (target_name, target_data) = &fx.files[2];
    let target_id = fid(&fx, target_name);
    let target = fx.dir.join(target_name);
    let untouched = vec![0; target_data.len()];
    std::fs::write(&target, &untouched).unwrap();
    session
        .on_article_failed_permanently(&target_id, 0, target_data.len() as u64)
        .unwrap();
    assert!(
        session.on_recovery_volume_arrived(late, None).is_err(),
        "stale source must not seed the fifth exponent"
    );
    let fifth = session
        .inner
        .slots
        .read()
        .unwrap()
        .iter()
        .find(|slot| slot.lock().unwrap().exponent == 4)
        .unwrap()
        .clone();
    assert!(!fifth.lock().unwrap().folded_mask.get(stale_global));
    assert!(fifth.lock().unwrap().folded_mask.count_ones() > 0);
    assert!(session.repair_available_targets_now(&[target_id]).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), untouched);
    assert_eq!(session.repair_phase_stats().target_bytes_written, 0);
    // The real cache/committed writer eventually supplies the original bytes.
    std::fs::write(&stale_path, &stale.1).unwrap();
    let before = session.io_stats().backfill_bytes_read;
    assert_eq!(session.on_recovery_volume_arrived(late, None).unwrap(), 0);
    // The first, shared back-fill skipped only the slices it could not
    // authenticate and folded the rest of the file; the retry re-reads just
    // those (with "same-crc" only the first 1 KiB slice was wrong).
    let missing = if mode == "same-crc" {
        stale.1.len().min(1024) as u64
    } else {
        stale.1.len() as u64
    };
    assert_eq!(
        session.io_stats().backfill_bytes_read - before,
        missing,
        "deduplication must retry missing rows with exactly one source read"
    );
    assert!(fifth.lock().unwrap().folded_mask.get(stale_global));
    let complete = fifth.lock().unwrap().data.clone();
    let after = session.io_stats().backfill_bytes_read;
    assert_eq!(session.on_recovery_volume_arrived(late, None).unwrap(), 0);
    assert_eq!(session.io_stats().backfill_bytes_read, after);
    assert_eq!(
        fifth.lock().unwrap().data,
        complete,
        "successful rows must not be XORed twice"
    );
    // Exponent four is the only available recovery row: a good result proves its backfill.
    assert_eq!(session.status().ready_recovery, 1);
    let report = session.repair_available_targets_now(&[target_id]).unwrap();
    assert_eq!(report.repaired_slices, vec![(target_id, 0)]);
    assert!(report.files.iter().all(|(_, _, valid)| *valid));
    assert_eq!(std::fs::read(&target).unwrap(), *target_data);
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn late_backfill_rejects_sparse_uncommitted_source_then_retries() {
    late_backfill_refuses_stale_disk_then_retries("sparse");
}

#[test]
fn late_backfill_checks_md5_even_when_crc_matches() {
    late_backfill_refuses_stale_disk_then_retries("same-crc");
}

#[test]
fn late_backfill_rejects_short_source_then_retries() {
    late_backfill_refuses_stale_disk_then_retries("truncated");
}

fn admitted_target(fx: &Fx, index: usize, data: &[u8]) -> crate::RepairTargetFile {
    let (name, _) = &fx.files[index];
    let path = fx.dir.join(name);
    std::fs::write(&path, data).unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    std::fs::rename(&path, fx.dir.join(format!("admitted-{index}"))).unwrap();
    crate::RepairTargetFile {
        file_id: fid(fx, name),
        file,
    }
}

#[test]
fn live_target_files_repair_and_hash_actual_descriptors() {
    let fx = fixture(
        "target-fds-repair",
        &[777, 1024],
        1024,
        1,
        VolumeScheme::Single,
    );
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let targets = [
        admitted_target(&fx, 0, &[]),
        admitted_target(&fx, 1, &fx.files[1].1),
    ];
    session
        .on_article_finished_memory_only(
            &targets[1].file_id,
            0,
            &fx.files[1].1,
            crc32(&fx.files[1].1),
        )
        .unwrap();
    session
        .on_recovery_volume_arrived(&fx.vols[0], None)
        .unwrap();
    for (name, data) in &fx.files {
        std::fs::write(fx.dir.join(name), vec![0x55; data.len()]).unwrap();
    }
    let ids = [targets[0].file_id, targets[1].file_id];
    let (report, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&ids, &targets)
        .unwrap();
    assert_eq!(report.repaired_slices, vec![(ids[0], 0)]);
    assert_eq!(hashes.len(), 2);
    assert!(
        report
            .files
            .iter()
            .all(|(_, status, ok)| *ok && *status == VolumeStatus::CompleteAndVerified)
    );
    for (index, (name, data)) in fx.files.iter().enumerate() {
        assert_eq!(
            std::fs::read(fx.dir.join(format!("admitted-{index}"))).unwrap(),
            *data
        );
        assert_eq!(
            std::fs::read(fx.dir.join(name)).unwrap(),
            vec![0x55; data.len()]
        );
        assert_eq!(hashes[index].0, ids[index]);
        assert_eq!(hashes[index].1.crc32, crc32(data));
    }
    assert_eq!(session.io_stats().target_verification_bytes_read, 1801);
    assert_eq!(session.io_stats().source_bytes_read, 0);
    assert_eq!(session.repair_phase_stats().target_bytes_written, 777);
    // A retry is verify-only and repeated requests preserve report/hash multiplicity.
    let (retry, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&[ids[0], ids[0]], &targets[..1])
        .unwrap();
    assert!(retry.repaired_slices.is_empty());
    assert_eq!(retry.files.len(), 2);
    assert_eq!(hashes.len(), 2);
    assert_eq!(session.io_stats().target_verification_bytes_read, 3355);
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_target_files_verify_only_rewinds_and_checks_whole_length() {
    use std::io::{Seek, SeekFrom};
    let fx = fixture("target-fds-verify", &[777], 1024, 1, VolumeScheme::Single);
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let targets = [admitted_target(&fx, 0, &fx.files[0].1)];
    let id = targets[0].file_id;
    session
        .on_article_finished_memory_only(&id, 0, &fx.files[0].1, crc32(&fx.files[0].1))
        .unwrap();
    // No pathname remains; reopening or depending on the inherited cursor fails.
    targets[0]
        .file
        .try_clone()
        .unwrap()
        .seek(SeekFrom::Start(733))
        .unwrap();
    let (report, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&[id], &targets)
        .unwrap();
    assert!(report.files[0].2);
    assert_eq!(hashes[0].1.len, 777);
    assert_eq!(hashes[0].1.md5_full, fx.set.file_descs[&id].hash_full);
    assert_eq!(session.io_stats().target_verification_bytes_read, 777);
    assert_eq!(session.repair_phase_stats().target_bytes_written, 0);
    assert_eq!(session.repair_phase_stats().decode_ns, 0);
    for (len, corrupt) in [(778, false), (776, false), (777, true)] {
        targets[0].file.set_len(len).unwrap();
        if corrupt {
            write_all_at(&targets[0].file, 0, &vec![0; 777]).unwrap();
        }
        let (report, hashes) = session
            .repair_available_targets_with_files_and_hashes_now(&[id], &targets)
            .unwrap();
        assert!(!report.files[0].2);
        assert!(hashes.is_empty());
        assert_eq!(targets[0].file.metadata().unwrap().len(), len);
    }
    // A write-only FD cannot authorize hashes even if tracked slice states are good.
    let unreadable = [crate::RepairTargetFile {
        file_id: id,
        file: OpenOptions::new()
            .write(true)
            .open(fx.dir.join("admitted-0"))
            .unwrap(),
    }];
    let (report, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&[id], &unreadable)
        .unwrap();
    assert!(!report.files[0].2);
    assert!(hashes.is_empty());
    assert!(!fx.dir.join(&fx.files[0].0).exists());
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_target_files_zero_length_and_renamed_parent_never_reopen() {
    let fx = fixture("target-fds-empty", &[0, 512], 1024, 1, VolumeScheme::Single);
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let targets = [
        admitted_target(&fx, 0, &[]),
        admitted_target(&fx, 1, &fx.files[1].1),
    ];
    session
        .on_article_finished_memory_only(
            &targets[1].file_id,
            0,
            &fx.files[1].1,
            crc32(&fx.files[1].1),
        )
        .unwrap();
    let renamed = fx.dir.with_extension("renamed");
    std::fs::rename(&fx.dir, &renamed).unwrap();
    let ids = [targets[0].file_id, targets[1].file_id];
    let (report, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&ids, &targets)
        .unwrap();
    assert!(report.files.iter().all(|(_, _, ok)| *ok));
    assert_eq!(hashes[0].1.len, 0);
    assert_eq!(hashes[0].1.md5_full, fx.set.file_descs[&ids[0]].hash_full);
    assert!(!fx.dir.exists());
    assert_eq!(session.io_stats().target_verification_bytes_read, 512);
    std::fs::remove_dir_all(renamed).unwrap();
}

#[test]
fn live_target_files_reject_entire_bad_batch_before_mutation() {
    let fx = fixture(
        "target-fds-admission",
        &[777, 512],
        1024,
        2,
        VolumeScheme::Single,
    );
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    session
        .on_recovery_volume_arrived(&fx.vols[0], None)
        .unwrap();
    let targets = [admitted_target(&fx, 0, &[]), admitted_target(&fx, 1, &[])];
    let ids = [targets[0].file_id, targets[1].file_id];
    assert!(
        session
            .repair_available_targets_with_files_and_hashes_now(&ids, &targets[..1])
            .is_err()
    );
    assert!(
        session
            .repair_available_targets_with_files_and_hashes_now(&ids[..1], &targets)
            .is_err()
    );
    assert!(
        session
            .repair_available_targets_with_files_and_hashes_now(&[], &targets)
            .is_err()
    );
    let duplicate = [
        crate::RepairTargetFile {
            file_id: ids[0],
            file: targets[0].file.try_clone().unwrap(),
        },
        crate::RepairTargetFile {
            file_id: ids[0],
            file: targets[0].file.try_clone().unwrap(),
        },
    ];
    assert!(
        session
            .repair_available_targets_with_files_and_hashes_now(&ids, &duplicate)
            .is_err()
    );
    let invalid = [crate::RepairTargetFile {
        file_id: FileId([0xff; 16]),
        file: targets[0].file.try_clone().unwrap(),
    }];
    assert!(
        session
            .repair_available_targets_with_files_and_hashes_now(&[FileId([0xff; 16])], &invalid)
            .is_err()
    );
    let directory = [
        crate::RepairTargetFile {
            file_id: ids[0],
            file: targets[0].file.try_clone().unwrap(),
        },
        crate::RepairTargetFile {
            file_id: ids[1],
            file: File::open(&fx.dir).unwrap(),
        },
    ];
    assert!(
        session
            .repair_available_targets_with_files_and_hashes_now(&ids, &directory)
            .is_err()
    );
    for target in &targets {
        assert_eq!(target.file.metadata().unwrap().len(), 0);
    }
    assert_eq!(session.repair_phase_stats().target_bytes_written, 0);
    assert_eq!(session.io_stats().target_verification_bytes_read, 0);
    for (name, _) in &fx.files {
        assert!(!fx.dir.join(name).exists());
    }
    assert_eq!(session.repair_phase_stats().attempts, 6);
    assert_eq!(session.repair_phase_stats().completed, 0);
    // Invalid admission has not consumed any syndromes.
    let (report, _) = session
        .repair_available_targets_with_files_and_hashes_now(&ids, &targets)
        .unwrap();
    assert!(report.files.iter().all(|(_, _, ok)| *ok));
    std::fs::remove_dir_all(fx.dir).unwrap();
}

fn target_files_backfill_retry(mode: &str) {
    let fx = fixture(
        &format!("target-fds-backfill-{mode}"),
        &[777, 1000],
        1024,
        2,
        VolumeScheme::Uniform(1),
    );
    let session = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            preallocated_syndrome_slots: 1,
            max_syndrome_slots: 2,
            fold_threads: 0,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    let targets = [
        admitted_target(&fx, 0, &fx.files[0].1),
        admitted_target(&fx, 1, &[]),
    ];
    let ids = [targets[0].file_id, targets[1].file_id];
    session
        .on_article_finished_memory_only(&ids[0], 0, &fx.files[0].1, crc32(&fx.files[0].1))
        .unwrap();
    let late = fx
        .vols
        .iter()
        .find(|p| {
            load_par2_file(p, ScanOptions::FULL)
                .unwrap()
                .recovery
                .contains_key(&1)
        })
        .unwrap();
    assert!(session.on_recovery_volume_arrived(late, None).is_err());
    // The pathname would authenticate, but the actual admitted description must refuse.
    std::fs::write(fx.dir.join(&fx.files[0].0), &fx.files[0].1).unwrap();
    match mode {
        "same-crc" => write_all_at(
            &targets[0].file,
            0,
            &different_bytes_with_same_crc(&fx.files[0].1),
        )
        .unwrap(),
        "short" => targets[0].file.set_len(776).unwrap(),
        "sparse" => {
            targets[0].file.set_len(0).unwrap();
            targets[0].file.set_len(777).unwrap();
        }
        _ => unreachable!(),
    }
    assert!(
        session
            .repair_available_targets_with_files_and_hashes_now(&ids, &targets)
            .is_err()
    );
    assert_eq!(targets[1].file.metadata().unwrap().len(), 0);
    assert_eq!(session.repair_phase_stats().target_bytes_written, 0);
    write_all_at(&targets[0].file, 0, &fx.files[0].1).unwrap();
    std::fs::remove_file(fx.dir.join(&fx.files[0].0)).unwrap();
    let before = session.io_stats().backfill_bytes_read;
    let (report, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&ids, &targets)
        .unwrap();
    assert!(report.files.iter().all(|(_, _, ok)| *ok));
    assert_eq!(hashes.len(), 2);
    assert_eq!(session.io_stats().backfill_bytes_read - before, 777);
    assert_eq!(
        std::fs::read(fx.dir.join("admitted-1")).unwrap(),
        fx.files[1].1
    );
    let before = session.io_stats().backfill_bytes_read;
    session
        .repair_available_targets_with_files_and_hashes_now(&ids, &targets)
        .unwrap();
    assert_eq!(session.io_stats().backfill_bytes_read, before);
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_target_files_backfill_checks_md5_and_retries() {
    target_files_backfill_retry("same-crc");
}

#[test]
fn live_target_files_backfill_rejects_short_and_retries() {
    target_files_backfill_retry("short");
}

#[test]
fn live_target_files_backfill_rejects_sparse_and_retries() {
    target_files_backfill_retry("sparse");
}

#[test]
fn live_target_files_write_failures_restore_syndromes_and_retry() {
    for length in [0, 777] {
        let fx = fixture(
            &format!("target-fds-write-error-{length}"),
            &[777],
            1024,
            1,
            VolumeScheme::Single,
        );
        let session =
            StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
        session
            .on_recovery_volume_arrived(&fx.vols[0], None)
            .unwrap();
        let good = [admitted_target(&fx, 0, &vec![0; length])];
        let ids = [good[0].file_id];
        let readonly = [crate::RepairTargetFile {
            file_id: ids[0],
            file: File::open(fx.dir.join("admitted-0")).unwrap(),
        }];
        let before: Vec<_> = session
            .inner
            .slots
            .read()
            .unwrap()
            .iter()
            .map(|s| s.lock().unwrap().data.clone())
            .collect();
        assert!(
            session
                .repair_available_targets_with_files_and_hashes_now(&ids, &readonly)
                .is_err()
        );
        let after: Vec<_> = session
            .inner
            .slots
            .read()
            .unwrap()
            .iter()
            .map(|s| s.lock().unwrap().data.clone())
            .collect();
        assert_eq!(before, after);
        assert_eq!(session.repair_phase_stats().target_bytes_written, 0);
        assert!(!fx.dir.join(&fx.files[0].0).exists());
        let (report, hashes) = session
            .repair_available_targets_with_files_and_hashes_now(&ids, &good)
            .unwrap();
        assert!(report.files[0].2);
        assert_eq!(hashes.len(), 1);
        std::fs::remove_dir_all(fx.dir).unwrap();
    }
}

#[test]
fn live_target_files_cancelled_admission_never_mutates() {
    let fx = fixture("target-fds-cancel", &[777], 1024, 1, VolumeScheme::Single);
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let targets = [admitted_target(&fx, 0, &[])];
    session.cancel();
    assert!(matches!(
        session.repair_available_targets_with_files_and_hashes_now(&[targets[0].file_id], &targets),
        Err(RepairError::Cancelled)
    ));
    assert_eq!(targets[0].file.metadata().unwrap().len(), 0);
    assert_eq!(session.repair_phase_stats().attempts, 1);
    assert_eq!(session.repair_phase_stats().completed, 0);
    assert_eq!(session.repair_phase_stats().target_bytes_written, 0);
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_target_files_empty_and_zero_row_requests_do_not_mutate() {
    let fx = fixture(
        "target-fds-zero-row",
        &[777, 512],
        1024,
        1,
        VolumeScheme::Single,
    );
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let targets = [admitted_target(&fx, 0, &fx.files[0].1)];
    let id = targets[0].file_id;
    session
        .on_article_finished_memory_only(&id, 0, &fx.files[0].1, crc32(&fx.files[0].1))
        .unwrap();
    session
        .on_recovery_volume_arrived(&fx.vols[0], None)
        .unwrap();
    let (empty, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&[], &[])
        .unwrap();
    assert_eq!(empty.erasures, 1);
    assert!(empty.files.is_empty() && hashes.is_empty());
    let (report, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&[id], &targets)
        .unwrap();
    assert_eq!(report.erasures, 1);
    assert!(report.repaired_slices.is_empty());
    assert!(report.files[0].2);
    assert_eq!(hashes.len(), 1);
    assert_eq!(session.repair_phase_stats().target_bytes_written, 0);
    assert!(!fx.dir.join(&fx.files[1].0).exists());
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[cfg(unix)]
#[test]
fn live_target_files_symlink_replacement_and_oversize_are_preserved() {
    let fx = fixture("target-fds-symlink", &[777], 1024, 1, VolumeScheme::Single);
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    session
        .on_recovery_volume_arrived(&fx.vols[0], None)
        .unwrap();
    let targets = [admitted_target(&fx, 0, &vec![0x33; 778])];
    let decoy = fx.dir.join("decoy");
    std::fs::write(&decoy, b"do not alter").unwrap();
    std::os::unix::fs::symlink(&decoy, fx.dir.join(&fx.files[0].0)).unwrap();
    let (report, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&[targets[0].file_id], &targets)
        .unwrap();
    assert_eq!(report.repaired_slices.len(), 1);
    assert!(!report.files[0].2);
    assert!(hashes.is_empty());
    let actual = std::fs::read(fx.dir.join("admitted-0")).unwrap();
    assert_eq!(&actual[..777], &fx.files[0].1);
    assert_eq!(actual[777], 0x33);
    assert_eq!(std::fs::read(decoy).unwrap(), b"do not alter");
    std::fs::remove_dir_all(fx.dir).unwrap();
}

// A typed, one-shot test rendezvous, scoped to the repair caller thread. It
// cannot call host code, and is entirely absent from non-test builds.
struct TargetIoPause {
    verify: bool,
    reached: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

thread_local! {
    static TARGET_IO_PAUSE: std::cell::RefCell<Option<TargetIoPause>> = const {
        std::cell::RefCell::new(None)
    };
}

pub(in crate::streaming) fn pause_target_io(verify: bool) {
    let pause = TARGET_IO_PAUSE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|pause| pause.verify == verify) {
            slot.take()
        } else {
            None
        }
    });
    if let Some(pause) = pause {
        pause.reached.send(()).unwrap();
        pause.resume.recv().unwrap();
    }
}

pub(in crate::streaming) struct PausedTargetRead<'a>(pub(in crate::streaming) CountedFile<'a>);

impl io::Read for &PausedTargetRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = io::Read::read(&mut &self.0, buf)?;
        if n > 0 {
            pause_target_io(true);
        }
        Ok(n)
    }
}

fn target_files_cancel_during_io(verify: bool) {
    let tag = if verify {
        "target-fds-cancel-verify"
    } else {
        "target-fds-cancel-decode"
    };
    let len = 8 << 20;
    let fx = fixture(tag, &[len], len as u64, 1, VolumeScheme::Single);
    let session = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            solve_threads: 1,
            solve_mem_limit_bytes: 16 << 20,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    let targets = [admitted_target(
        &fx,
        0,
        if verify { &fx.files[0].1 } else { &[] },
    )];
    let id = targets[0].file_id;
    if verify {
        session
            .on_article_finished_memory_only(&id, 0, &fx.files[0].1, crc32(&fx.files[0].1))
            .unwrap();
    } else {
        session
            .on_recovery_volume_arrived(&fx.vols[0], None)
            .unwrap();
    }
    let before: Vec<_> = session
        .inner
        .slots
        .read()
        .unwrap()
        .iter()
        .map(|s| s.lock().unwrap().data.clone())
        .collect();
    std::thread::scope(|scope| {
        let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
        let op = scope.spawn(|| {
            TARGET_IO_PAUSE.with(|slot| {
                *slot.borrow_mut() = Some(TargetIoPause {
                    verify,
                    reached: reached_tx,
                    resume: resume_rx,
                });
            });
            session.repair_available_targets_with_files_and_hashes_now(&[id], &targets)
        });
        reached_rx
            .recv()
            .expect("operation ended before the I/O rendezvous");
        let bytes = if verify {
            session.io_stats().target_verification_bytes_read
        } else {
            session.repair_phase_stats().target_bytes_written
        };
        assert!(
            bytes > 0 && bytes < len as u64,
            "must pause after real partial I/O"
        );
        assert!(!op.is_finished());
        session.cancel();
        resume_tx.send(()).unwrap();
        let result = op.join().unwrap();
        assert!(matches!(result, Err(RepairError::Cancelled)));
    });
    assert_eq!(session.repair_phase_stats().completed, 0);
    let after: Vec<_> = session
        .inner
        .slots
        .read()
        .unwrap()
        .iter()
        .map(|s| s.lock().unwrap().data.clone())
        .collect();
    assert_eq!(before, after);
    assert!(!fx.dir.join(&fx.files[0].0).exists());
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_target_files_cancel_during_decode_restores_syndromes() {
    target_files_cancel_during_io(false);
}

#[test]
fn live_target_files_cancel_during_verification_returns_no_receipts() {
    target_files_cancel_during_io(true);
}

#[cfg(unix)]
#[test]
fn live_target_files_clone_failure_and_one_transient_descriptor() {
    const CHILD: &str = "PAR_TARGET_FD_LIMIT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("ulimit -n 96 || exit 90; exec \"$1\" --exact streaming::live_tests::control_tests::live_target_files_clone_failure_and_one_transient_descriptor --test-threads=1 --show-output")
            .arg("par-target-fd-limit")
            .arg(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("descriptor-limit child stdout:\n{stdout}\nstderr:\n{stderr}");
        assert!(output.status.success());
        assert!(stdout.contains("1 passed; 0 failed"));
        return;
    }
    let fx = fixture(
        "target-fds-limit",
        &[777, 512],
        1024,
        1,
        VolumeScheme::Single,
    );
    let session = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let targets = [
        admitted_target(&fx, 0, &fx.files[0].1),
        admitted_target(&fx, 1, &fx.files[1].1),
    ];
    let ids = [targets[0].file_id, targets[1].file_id];
    for (index, id) in ids.iter().enumerate() {
        session
            .on_article_finished_memory_only(id, 0, &fx.files[index].1, crc32(&fx.files[index].1))
            .unwrap();
    }
    // Exhaust only this child's table; the caller-owned originals remain valid.
    let mut fillers = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(file) => fillers.push(file),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(24)); // EMFILE on supported Unix targets.
                break;
            }
        }
        assert!(
            fillers.len() < 96,
            "child descriptor limit was not installed"
        );
    }
    let (report, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&ids, &targets)
        .unwrap();
    assert!(report.files.iter().all(|(_, _, ok)| !ok));
    assert!(hashes.is_empty());
    assert_eq!(session.io_stats().target_verification_bytes_read, 0);
    drop(fillers.pop().unwrap());
    // With just one free FD, every sequential target still hashes successfully.
    let (report, hashes) = session
        .repair_available_targets_with_files_and_hashes_now(&ids, &targets)
        .unwrap();
    assert!(report.files.iter().all(|(_, _, ok)| *ok));
    assert_eq!(hashes.len(), 2);
    assert_eq!(session.io_stats().target_verification_bytes_read, 1289);
    assert_eq!(session.repair_phase_stats().target_bytes_written, 0);
    drop(fillers);
    std::fs::remove_dir_all(fx.dir).unwrap();
}

#[test]
fn live_staging_charges_only_the_bytes_held() {
    // One quarter-slice article into a 16 KiB slice charges 4 KiB, not the whole slice.
    let fx = fixture("staging-held", &[16384], 16384, 0, VolumeScheme::Single);
    let id = fid(&fx, &fx.files[0].0);
    let s = StreamingParSession::new(&fx.set, &fx.dir, SessionOptions::default()).unwrap();
    let data = &fx.files[0].1;
    let piece = |o: usize, e: usize| (o as u64, &data[o..e], crc32(&data[o..e]));
    let (o, d, c) = piece(0, 4096);
    s.on_article_finished_memory_only(&id, o, d, c).unwrap();
    assert_eq!(s.staging_bytes(), 4096);
    // A disjoint piece adds its own length; a duplicate adds nothing.
    let (o, d, c) = piece(8192, 12288);
    s.on_article_finished_memory_only(&id, o, d, c).unwrap();
    assert_eq!(s.staging_bytes(), 8192);
    let (o, d, c) = piece(0, 4096);
    s.on_article_finished_memory_only(&id, o, d, c).unwrap();
    assert_eq!(s.staging_bytes(), 8192);
    // Filling the gaps completes, verifies and releases the slice.
    let (o, d, c) = piece(4096, 8192);
    s.on_article_finished_memory_only(&id, o, d, c).unwrap();
    assert_eq!(s.staging_bytes(), 12288);
    let (o, d, c) = piece(12288, 16384);
    s.on_article_finished_memory_only(&id, o, d, c).unwrap();
    assert_eq!(s.staging_bytes(), 0);
    assert_eq!(s.status().verified, 1);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

#[test]
fn live_zero_preallocated_slots_still_repair() {
    // No syndrome slot exists before damage; slots are created when recovery is admitted and
    // back-filled from the verified slices.
    let fx = fixture("zero-slots", &[1024; 8], 1024, 2, VolumeScheme::Uniform(1));
    let target = fid(&fx, &fx.files[3].0);
    let s = StreamingParSession::new(
        &fx.set,
        &fx.dir,
        SessionOptions {
            preallocated_syndrome_slots: 0,
            ..SessionOptions::default()
        },
    )
    .unwrap();
    for (i, (name, data)) in fx.files.iter().enumerate() {
        if i == 3 {
            continue;
        }
        write_at(&fx.dir.join(name), 0, data);
        s.on_article_finished(&fid(&fx, name), 0, 1024, crc32(data), Some(data))
            .unwrap();
    }
    s.on_article_failed_permanently(&target, 0, 1024).unwrap();
    for vol in &fx.vols {
        s.on_recovery_volume_arrived(vol, None).unwrap();
    }
    s.flush();
    assert!(s.status().early_cutover_possible);
    let rep = s.repair_available_targets_now(&[target]).unwrap();
    assert_eq!(rep.repaired_slices.len(), 1);
    assert_eq!(
        std::fs::read(fx.dir.join(&fx.files[3].0)).unwrap(),
        fx.files[3].1
    );
    std::fs::remove_dir_all(&fx.dir).unwrap();
}
