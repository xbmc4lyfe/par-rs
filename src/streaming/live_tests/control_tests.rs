use super::*;

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
