// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! Public supplied-byte fusion, independently checked against existing digest helpers.
use par_rs::packet::SliceChecksum;
use par_rs::{FileHasher, FileSliceHasher};

fn checksum(bytes: &[u8]) -> SliceChecksum {
    let (crc32, md5) = par_rs::hasher::slice_checksums(bytes);
    SliceChecksum { crc32, md5 }
}
#[test]
fn fusion_emits_padded_slices_and_preserves_actual_file_hashes() {
    let mut fused = FileSliceHasher::new(4).unwrap();
    let mut got = Vec::new();
    let mut emit = |i, s| {
        got.push((i, s));
        Ok(())
    };
    fused.update(b"ab", None, &mut emit).unwrap();
    fused.update(b"cde", None, &mut emit).unwrap();
    let file = fused.finish(None, &mut emit).unwrap();
    let mut expected = FileHasher::new();
    expected.update(b"abcde");
    assert_eq!(file, expected.finish());
    assert_eq!(got, [(0, checksum(b"abcd")), (1, checksum(b"e\0\0\0"))]);
}

fn oracle(data: &[u8], slice: usize) -> (par_rs::FileHashes, Vec<(u64, SliceChecksum)>) {
    let mut file = FileHasher::new();
    file.update(data);
    let slices = data
        .chunks(slice)
        .enumerate()
        .map(|(i, p)| {
            let mut padded = vec![0; slice];
            padded[..p.len()].copy_from_slice(p);
            (i as u64, checksum(&padded))
        })
        .collect();
    (file.finish(), slices)
}
fn partitions(
    data: &[u8],
    slice: u64,
    steps: &[usize],
) -> (par_rs::FileHashes, Vec<(u64, SliceChecksum)>) {
    let mut h = FileSliceHasher::new(slice).unwrap();
    let mut emitted = Vec::new();
    let mut emit = |i, s| {
        emitted.push((i, s));
        Ok(())
    };
    let mut pos = 0;
    let mut step = 0;
    h.update(&[], None, &mut emit).unwrap();
    while pos < data.len() {
        let n = steps[step % steps.len()].min(data.len() - pos);
        h.update(&data[pos..pos + n], None, &mut emit).unwrap();
        pos += n;
        step += 1;
    }
    let file = h.finish(None, &mut emit).unwrap();
    (file, emitted)
}
#[test]
fn arbitrary_chunk_boundaries_match_independent_file_prefix_and_padded_slice_oracles() {
    let data: Vec<_> = (0..32773).map(|i| ((i * 37 + i / 7) % 251) as u8).collect();
    for len in [0, 1, 3, 4, 5, 7, 8, 16383, 16384, 16385, 32773] {
        for slice in [4, 12, 16384, 65536] {
            let expected = oracle(&data[..len], slice);
            for steps in [
                &[1][..],
                &[3, 5, 7][..],
                &[16383, 2, 16385][..],
                &[65536][..],
            ] {
                assert_eq!(
                    partitions(&data[..len], slice as u64, steps),
                    expected,
                    "len={len} slice={slice} steps={steps:?}"
                );
            }
        }
    }
}
#[test]
fn known_whole_and_prefix_digests_exclude_zero_padding() {
    let (file, slices) = partitions(b"abc", 4, &[1, 2]);
    assert_eq!(
        file.md5_full,
        [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
            0x7f, 0x72
        ]
    );
    assert_eq!(file.md5_16k, file.md5_full);
    assert_eq!(file.crc32, 0x352441c2);
    assert_eq!(file.len, 3);
    assert_eq!(slices, [(0, checksum(b"abc\0"))]);
    let data = [vec![b'a'; 16384], vec![b'b'; 7]].concat();
    let (file, _) = partitions(&data, 32768, &[16383, 1, 7]);
    assert_eq!(file.md5_16k, par_rs::hasher::md5(&data[..16384]));
    assert_eq!(file.md5_full, par_rs::hasher::md5(&data));
}
#[test]
fn empty_exact_and_large_valid_geometry_emit_only_required_slices() {
    for slice in [4, u64::from(u32::MAX) + 1, u64::MAX - 3] {
        let mut emitted = 0;
        let file = FileSliceHasher::new(slice)
            .unwrap()
            .finish(None, &mut |_, _| {
                emitted += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(file, FileHasher::new().finish());
        assert_eq!(emitted, 0);
    }
    let (_, got) = partitions(b"abcdefgh", 4, &[4]);
    assert_eq!(got.len(), 2);
    for invalid in [0, 1, 2, 3, 5, u64::MAX] {
        assert!(
            matches!(FileSliceHasher::new(invalid),Err(e) if e.kind()==std::io::ErrorKind::InvalidInput)
        );
    }
}
#[test]
fn callback_failure_first_middle_and_last_poisons_without_reemission() {
    for fail in [0, 1, 2] {
        let mut h = FileSliceHasher::new(4).unwrap();
        let mut attempts = Vec::new();
        let mut delivered = Vec::new();
        let mut emit = |i, s| {
            attempts.push(i);
            if i == fail {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "original callback error",
                ))
            } else {
                delivered.push((i, s));
                Ok(())
            }
        };
        let error = h.update(b"abcdefghijkl", None, &mut emit).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "original callback error");
        assert!(h.update(b"more", None, &mut emit).is_err());
        assert!(h.update(b"", None, &mut emit).is_err());
        assert!(h.finish(None, &mut emit).is_err());
        assert_eq!(attempts, (0..=fail).collect::<Vec<_>>());
        assert_eq!(delivered.len(), fail as usize);
    }
}
#[test]
fn tail_callback_error_and_callback_cancel_do_not_return_file_hashes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut h = FileSliceHasher::new(8).unwrap();
    h.update(b"abc", None, &mut |_, _| panic!("tail is not complete"))
        .unwrap();
    let mut calls = 0;
    let error = h
        .finish(None, &mut |i, _| {
            assert_eq!(i, 0);
            calls += 1;
            Err(std::io::Error::other("tail failure"))
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "tail failure");
    assert_eq!(calls, 1);
    for (data, slice) in [(b"abcd".as_slice(), 4), (b"abc".as_slice(), 4)] {
        let flag = AtomicBool::new(false);
        let mut h = FileSliceHasher::new(slice).unwrap();
        let mut calls = 0;
        let mut emit = |_, _| {
            calls += 1;
            flag.store(true, Ordering::Relaxed);
            Ok(())
        };
        let update = h.update(data, Some(&flag), &mut emit);
        if data.len() == 4 {
            assert!(matches!(update,Err(e) if e.kind()==std::io::ErrorKind::Interrupted));
            assert!(h.finish(Some(&flag), &mut emit).is_err());
        } else {
            update.unwrap();
            assert!(
                matches!(h.finish(Some(&flag),&mut emit),Err(e) if e.kind()==std::io::ErrorKind::Interrupted)
            );
        }
        assert_eq!(calls, 1);
    }
    let flag = AtomicBool::new(false);
    let mut h = FileSliceHasher::new(4).unwrap();
    let mut calls = 0;
    let mut emit = |_, _| {
        calls += 1;
        flag.store(true, Ordering::Relaxed);
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "callback before cancellation",
        ))
    };
    let e = h.update(b"abcd", Some(&flag), &mut emit).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(e.to_string(), "callback before cancellation");
    assert!(h.finish(Some(&flag), &mut emit).is_err());
    assert_eq!(calls, 1);
}
#[test]
fn cancellation_in_empty_updates_and_before_finish_poison_without_callbacks() {
    use std::sync::atomic::AtomicBool;
    let cancel = AtomicBool::new(true);
    let mut calls = 0;
    let mut emit = |_, _| {
        calls += 1;
        Ok(())
    };
    let mut h = FileSliceHasher::new(4).unwrap();
    assert!(
        matches!(h.update(b"",Some(&cancel),&mut emit),Err(e) if e.kind()==std::io::ErrorKind::Interrupted)
    );
    assert!(h.update(b"abcd", None, &mut emit).is_err());
    assert!(h.finish(None, &mut emit).is_err());
    let mut h = FileSliceHasher::new(8).unwrap();
    h.update(b"abc", None, &mut emit).unwrap();
    assert!(
        matches!(h.finish(Some(&cancel),&mut emit),Err(e) if e.kind()==std::io::ErrorKind::Interrupted)
    );
    assert_eq!(calls, 0);
}

#[test]
fn caller_owned_counted_file_is_supplied_once_with_bounded_read_buffer() {
    use std::io::{Read, Write};
    let retained = std::env::var_os("PAR2_FUSED_ARTIFACT_DIR");
    let parent = retained
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = parent.join(format!("par-rs-fused-held-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("data.bin");
    let mut output = std::fs::File::create(&path).unwrap();
    let mut left = 50021;
    let chunk = [37; 509];
    while left > 0 {
        let n = left.min(chunk.len());
        output.write_all(&chunk[..n]).unwrap();
        left -= n;
    }
    drop(output);
    struct Counted {
        file: std::fs::File,
        bytes: u64,
        reads: usize,
        max: usize,
    }
    impl Read for Counted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.max = self.max.max(buf.len());
            self.reads += 1;
            let n = self.file.read(buf)?;
            self.bytes += n as u64;
            Ok(n)
        }
    }
    let mut reader = Counted {
        file: std::fs::File::open(&path).unwrap(),
        bytes: 0,
        reads: 0,
        max: 0,
    };
    let mut h = FileSliceHasher::new(4096).unwrap();
    let mut checksums = Vec::new();
    let mut emit = |i, s| {
        checksums.push((i, s));
        Ok(())
    };
    let mut buffer = [0; 997];
    loop {
        let n = reader.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        h.update(&buffer[..n], None, &mut emit).unwrap();
    }
    let actual = h.finish(None, &mut emit).unwrap();
    assert_eq!(reader.bytes, 50021);
    assert_eq!(reader.max, 997);
    assert_eq!(actual.len, reader.bytes);
    // Separate oracle reads are outside the preceding counted one-traversal feed.
    assert_eq!(actual, par_rs::hash_file(&path).unwrap());
    let mut oracle_file = std::fs::File::open(&path).unwrap();
    let mut expected = Vec::new();
    let mut slice = [0; 4096];
    let mut index = 0;
    loop {
        slice.fill(0);
        let mut n = 0;
        while n < slice.len() {
            let got = oracle_file.read(&mut slice[n..]).unwrap();
            if got == 0 {
                break;
            }
            n += got;
        }
        if n == 0 {
            break;
        }
        expected.push((index, checksum(&slice)));
        index += 1;
    }
    assert_eq!(checksums, expected);
    eprintln!(
        "held-file feed: bytes={} read_calls={} max_requested={} slices={}; oracle reads separate",
        reader.bytes,
        reader.reads,
        reader.max,
        checksums.len()
    );
    if retained.is_some() {
        std::fs::write(dir.join("receipt.txt"),format!("supplied_bytes={}\nread_calls={}\nmax_request={}\nslice_count={}\nwhole_md5={:02x?}\n",reader.bytes,reader.reads,reader.max,checksums.len(),actual.md5_full)).unwrap();
    } else {
        std::fs::remove_dir_all(dir).unwrap();
    }
}
