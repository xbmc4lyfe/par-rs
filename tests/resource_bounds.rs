//! Resource regressions for large PAR2 slices.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct TrackingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);
// SAFETY: allocation and deallocation are delegated to the system allocator.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        PEAK.fetch_max(live, Ordering::Relaxed);
        LARGEST.fetch_max(size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[test]
fn large_slices_use_bounded_buffers() {
    use par_rs::parhash::{HashRange, hash_ranges_parallel};
    use par_rs::scanner::{BlockRef, ChecksumEntry, ChecksumIndex, ScanConfig, scan_source};
    let size = 40 << 20;
    let data = vec![0x5a; size];
    let expected = par_rs::hasher::slice_checksums(&data);
    let path = std::env::temp_dir().join(format!("par-rs-resources-{}", std::process::id()));
    std::fs::write(&path, &data).unwrap();
    LARGEST.store(0, Ordering::Relaxed);
    let hashes = hash_ranges_parallel(
        &[&path],
        &[HashRange {
            file: 0,
            offset: 0,
            len: size as u64,
            pad_to: size as u64,
        }],
        1,
        None,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(hashes, vec![expected]);
    let hash_allocation = LARGEST.load(Ordering::Relaxed);
    std::fs::remove_file(&path).unwrap();
    assert!(
        hash_allocation <= 1 << 20,
        "hash allocation {hash_allocation}"
    );

    let mut padded = vec![0u8; size];
    padded[..17].copy_from_slice(&data[..17]);
    let short_digest = par_rs::hasher::slice_checksums(&padded);
    padded.fill(0);
    let zero_digest = par_rs::hasher::slice_checksums(&padded);
    drop(padded);
    std::fs::write(&path, &data[..17]).unwrap();
    let mixed = [
        HashRange {
            file: 0,
            offset: 0,
            len: 17,
            pad_to: size as u64,
        },
        HashRange {
            file: 0,
            offset: 0,
            len: 17,
            pad_to: 17,
        },
        HashRange {
            file: 0,
            offset: 0,
            len: 0,
            pad_to: size as u64,
        },
    ];
    let got = hash_ranges_parallel(&[&path], &mixed, 1, None, &mut |_| {}).unwrap();
    assert_eq!(
        got,
        vec![
            short_digest,
            par_rs::hasher::slice_checksums(&data[..17]),
            zero_digest
        ]
    );
    std::fs::remove_file(&path).unwrap();

    let index = ChecksumIndex::new(
        size as u64,
        vec![ChecksumEntry {
            crc32: expected.0,
            md5: expected.1,
            block: BlockRef {
                file_index: 0,
                block_index: 0,
            },
        }],
    );
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    let report = scan_source(
        &data,
        &index,
        None,
        &ScanConfig::default(),
        None,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(report.found.len(), 1);
    assert_eq!(report.file_hashes.unwrap().md5_full, expected.1);
    assert!(PEAK.load(Ordering::Relaxed) - baseline <= 1 << 20);
    let scan_allocation = LARGEST.load(Ordering::Relaxed);
    assert!(
        scan_allocation <= 1 << 20,
        "scan allocation {scan_allocation}"
    );
    many_files_release_descriptors();
    verification_obeys_small_budget_with_many_workers();
    streaming_payloads_obey_byte_caps();
}

fn many_files_release_descriptors() {
    use par_rs::parhash::{HashRange, hash_ranges_parallel};
    let dir = std::env::temp_dir().join(format!("par-rs-fds-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let paths: Vec<_> = (0..300)
        .map(|i| {
            let path = dir.join(i.to_string());
            std::fs::write(&path, [i as u8]).unwrap();
            path
        })
        .collect();
    let refs: Vec<_> = paths.iter().map(|p| p.as_path()).collect();
    let ranges: Vec<_> = (0..300)
        .map(|file| HashRange {
            file,
            offset: 0,
            len: 1,
            pad_to: 4,
        })
        .collect();
    let mut peak_fds = 0;
    let result = hash_ranges_parallel(&refs, &ranges, 1, None, &mut |_| {
        #[cfg(unix)]
        {
            peak_fds = peak_fds.max(std::fs::read_dir("/dev/fd").unwrap().count());
        }
    })
    .unwrap();
    for (i, digest) in result.iter().enumerate() {
        assert_eq!(
            *digest,
            par_rs::hasher::slice_checksums(&[i as u8, 0, 0, 0])
        );
    }
    assert!(peak_fds < 32, "open descriptors {peak_fds}");
    std::fs::remove_dir_all(dir).unwrap();
}

fn verification_obeys_small_budget_with_many_workers() {
    use par_rs::create::{CreateOptions, SourceFile, create};
    use par_rs::{NullObserver, Par2Repairer, RepairOptions};
    let dir = std::env::temp_dir().join(format!("par-rs-budget-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut data = vec![0x5a; 1 << 20];
    let sources: Vec<_> = (1..=64)
        .map(|i| {
            let path = dir.join(format!("part{i}.bin"));
            data[0] = i;
            std::fs::write(&path, &data).unwrap();
            SourceFile::new(path)
        })
        .collect();
    let options = CreateOptions {
        recovery_blocks: 10,
        ..CreateOptions::default()
    };
    create(&sources, &dir, "set", &options, None, &mut |_, _, _| {}).unwrap();
    let mut repairer = Par2Repairer::new(
        &dir,
        RepairOptions {
            num_threads: 64,
            mem_limit_bytes: 16 << 20,
            full_file_md5: true,
            ..RepairOptions::default()
        },
    );
    repairer.load_par2_set(&dir.join("set.par2")).unwrap();
    repairer.finalize().unwrap();
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    assert!(
        repairer
            .verify(None, &mut NullObserver)
            .unwrap()
            .all_complete
    );
    let allocated = PEAK.load(Ordering::Relaxed) - baseline;
    assert!(allocated < 12 << 20, "verification allocated {allocated}");

    data[0] = 0;
    for source in &sources {
        std::fs::write(&source.path, &data).unwrap();
    }
    let mut repairer = Par2Repairer::new(
        &dir,
        RepairOptions {
            num_threads: 64,
            mem_limit_bytes: 16 << 20,
            full_file_md5: true,
            ..RepairOptions::default()
        },
    );
    repairer.load_par2_set(&dir.join("set.par2")).unwrap();
    repairer.finalize().unwrap();
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let result = repairer.verify(None, &mut NullObserver).unwrap();
    assert_eq!(result.missing_blocks, 64);
    let allocated = PEAK.load(Ordering::Relaxed) - baseline;
    assert!(allocated < 12 << 20, "damaged scan allocated {allocated}");

    for (i, source) in sources.iter().enumerate() {
        if i < 8 {
            std::fs::remove_file(&source.path).unwrap();
        } else {
            data[0] = (i + 1) as u8;
            std::fs::write(&source.path, &data).unwrap();
        }
    }
    let mut repairer = Par2Repairer::new(
        &dir,
        RepairOptions {
            num_threads: 10,
            ..RepairOptions::default()
        },
    );
    repairer.load_par2_set(&dir.join("set.par2")).unwrap();
    repairer.finalize().unwrap();
    assert_eq!(
        repairer
            .verify(None, &mut NullObserver)
            .unwrap()
            .missing_blocks,
        8
    );
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    repairer.repair(&mut NullObserver).unwrap();
    let allocated = PEAK.load(Ordering::Relaxed) - baseline;
    assert!(
        allocated < 48 << 20,
        "repair pipeline allocated {allocated}"
    );
    for (i, source) in sources.iter().take(8).enumerate() {
        data[0] = (i + 1) as u8;
        assert_eq!(std::fs::read(&source.path).unwrap(), data);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

fn streaming_payloads_obey_byte_caps() {
    use par_rs::create::{CreateOptions, SourceFile, VolumeScheme, create};
    use par_rs::packet::{ScanOptions, load_par2_file};
    use par_rs::streaming::{SessionOptions, StreamingParSession};
    let dir = std::env::temp_dir().join(format!("par-rs-live-budget-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let data = vec![0x3c; 16 << 20];
    let path = dir.join("part.bin");
    std::fs::write(&path, &data).unwrap();
    let created = create(
        &[SourceFile::new(path)],
        &dir,
        "set",
        &CreateOptions {
            slice_size: 1 << 20,
            recovery_blocks: 4,
            volumes: VolumeScheme::Uniform(1),
            ..Default::default()
        },
        None,
        &mut |_, _, _| {},
    )
    .unwrap();
    let set = load_par2_file(&created.files[0], ScanOptions::FULL).unwrap();
    let session = StreamingParSession::new(
        &set,
        &dir,
        SessionOptions {
            max_syndrome_bytes: 2 << 20,
            max_working_bytes: 4 << 20,
            max_staging_bytes: 1 << 20,
            fold_threads: 4,
            fold_queue_depth: 64,
            ..Default::default()
        },
    )
    .unwrap();
    let id = session.file_id_by_name(b"part.bin").unwrap();
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    session
        .on_article_finished(
            &id,
            0,
            data.len() as u64,
            par_rs::crc::crc32(&data),
            Some(&data),
        )
        .unwrap();
    session.flush();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    assert!(peak < 8 << 20, "streaming bulk article peak {peak}");
    assert_eq!(session.status().verified, 16);
    // Exponents 0 and 1 already have slots. A different exponent is refused
    // before either full-slice input or split scratch is allocated.
    LARGEST.store(0, Ordering::Relaxed);
    assert_eq!(
        session
            .on_recovery_volume_arrived(&created.files[3], None)
            .unwrap(),
        0
    );
    assert!(LARGEST.load(Ordering::Relaxed) < 1 << 20);
    drop(session);
    let session = StreamingParSession::new(
        &set,
        &dir,
        SessionOptions {
            max_syndrome_bytes: 2 << 20,
            max_working_bytes: 4 << 20,
            max_staging_bytes: 1 << 20,
            fold_threads: 4,
            fold_queue_depth: 64,
            ..Default::default()
        },
    )
    .unwrap();
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    std::thread::scope(|scope| {
        for lane in 0..4 {
            let session = &session;
            let data = &data;
            scope.spawn(move || {
                for block in (lane..16).step_by(4) {
                    let bytes = &data[block << 20..(block + 1) << 20];
                    session
                        .on_article_finished(
                            &id,
                            (block << 20) as u64,
                            1 << 20,
                            par_rs::crc::crc32(bytes),
                            Some(bytes),
                        )
                        .unwrap();
                }
            });
        }
    });
    session.flush();
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    assert!(peak < 8 << 20, "streaming concurrent peak {peak}");
    assert_eq!(session.status().verified, 16);
    drop(session);
    let tail = &data[..(1 << 20) - 1];
    let path = dir.join("tail.bin");
    std::fs::write(&path, tail).unwrap();
    let created = create(
        &[SourceFile::new(path)],
        &dir,
        "tail",
        &CreateOptions {
            slice_size: 1 << 20,
            recovery_blocks: 0,
            ..Default::default()
        },
        None,
        &mut |_, _, _| {},
    )
    .unwrap();
    let set = load_par2_file(&created.files[0], ScanOptions::FULL).unwrap();
    let session = StreamingParSession::new(
        &set,
        &dir,
        SessionOptions {
            max_syndrome_bytes: 2 << 20,
            max_working_bytes: 4 << 20,
            ..Default::default()
        },
    )
    .unwrap();
    let id = session.file_id_by_name(b"tail.bin").unwrap();
    LARGEST.store(0, Ordering::Relaxed);
    session
        .on_article_finished(
            &id,
            0,
            tail.len() as u64,
            par_rs::crc::crc32(tail),
            Some(tail),
        )
        .unwrap();
    assert!(
        LARGEST.load(Ordering::Relaxed) <= 1 << 20,
        "tail padding grew beyond one slice"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
