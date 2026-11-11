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
        hash_allocation <= 32 << 20,
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
    assert!(PEAK.load(Ordering::Relaxed) - baseline <= 10 << 20);
    let scan_allocation = LARGEST.load(Ordering::Relaxed);
    assert!(
        scan_allocation <= 8 << 20,
        "scan allocation {scan_allocation}"
    );
    many_files_release_descriptors();
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
