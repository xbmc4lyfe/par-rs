//! Parallel hashing of file ranges: a thread pool over `(file, offset, length)` jobs, each job
//! hashing its ranges with the multi-lane MD5 ([`crate::md5simd`]) and hardware CRC-32.
//!
//! PAR2 verification and creation are hash bound: every slice needs its own MD5 and CRC, and
//! on one core MD5 runs at about 1 GB/s. Slices are independent messages, so a job of several
//! slices is hashed in lockstep lanes, and jobs are spread over all cores. The whole-file MD5
//! chains (file description digests) cannot be split, so they run one file per thread.

use crate::crc::Crc32;
use crate::hasher::{FileHasher, FileHashes, READ_CHUNK};
use crate::md5simd::{INIT as MD5_INIT, LANES, compress_blocks};
use crate::packet::read_exact_at;
use md5::{Digest, Md5};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// One message to hash: `len` bytes of file `file` at `offset`, zero padded to `pad_to` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashRange {
    /// Index into the caller's file list.
    pub file: usize,
    /// Byte offset of the message within the file.
    pub offset: u64,
    /// Bytes read from the file (clamped to the file length by the caller).
    pub len: u64,
    /// Message length after zero padding (`>= len`).
    pub pad_to: u64,
}

/// Target aggregate verification scratch space, independent of set size.
pub(crate) const WORKING_MEMORY_BYTES: u64 = 8 << 20;
const HASH_CHUNK: usize = 64 << 10;

/// Resolve the worker count.
pub(crate) fn thread_count(requested: usize) -> usize {
    if requested == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        requested
    }
}

/// Group consecutive ranges from one file into full SIMD lanes.
fn plan_jobs(ranges: &[HashRange]) -> Vec<std::ops::Range<usize>> {
    let mut jobs = Vec::new();
    let mut start = 0;
    while start < ranges.len() {
        let file = ranges[start].file;
        let count = ranges[start..]
            .iter()
            .take(LANES)
            .take_while(|r| r.file == file)
            .count();
        jobs.push(start..start + count);
        start += count;
    }
    jobs
}

fn padded_bytes(length: u64) -> Option<u64> {
    (length / 64 + 1 + u64::from(length % 64 >= 56)).checked_mul(64)
}

/// Shared pool state.
struct Pool<'a> {
    paths: &'a [&'a Path],
    ranges: &'a [HashRange],
    jobs: Vec<std::ops::Range<usize>>,
    chunk_bytes: usize,
    buffer_bytes: usize,
    next: AtomicUsize,
    bytes_done: AtomicU64,
    error: Mutex<Option<io::Error>>,
    stop: AtomicBool,
    cancel: Option<&'a AtomicBool>,
    out: Mutex<Vec<(u32, [u8; 16])>>,
}

impl Pool<'_> {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || self.cancel.is_some_and(|c| c.load(Ordering::Relaxed))
    }

    fn fail(&self, e: io::Error) {
        let mut g = self.error.lock().unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            *g = Some(e);
        }
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Run jobs until none are left; report completed file bytes after each job.
    fn work(&self, on_job: &mut dyn FnMut(u64)) {
        let mut file: Option<(usize, File)> = None;
        if self.stopped() {
            return;
        }
        let mut buf = Vec::with_capacity(self.buffer_bytes);
        loop {
            if self.stopped() {
                return;
            }
            let j = self.next.fetch_add(1, Ordering::Relaxed);
            let Some(job) = self.jobs.get(j) else {
                return;
            };
            let ranges = &self.ranges[job.clone()];
            let result = (|| -> io::Result<Vec<(u32, [u8; 16])>> {
                if ranges.iter().any(|r| r.len > 0)
                    && file.as_ref().map(|(i, _)| *i) != Some(ranges[0].file)
                {
                    drop(file.take());
                    file = Some((ranges[0].file, File::open(self.paths[ranges[0].file])?));
                }
                let mut scalar = (ranges.len() == 1).then(Md5::new);
                let mut states = vec![MD5_INIT; ranges.len()];
                let mut crcs: Vec<Crc32> = ranges.iter().map(|_| Crc32::new()).collect();
                let lengths: Vec<u64> = ranges
                    .iter()
                    .map(|r| padded_bytes(r.pad_to).unwrap())
                    .collect();
                let end = lengths.iter().copied().max().unwrap_or(0);
                buf.resize(ranges.len() * self.chunk_bytes, 0);
                let mut pos = 0;
                while pos < end {
                    if self.stopped() {
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                    }
                    let mut messages = Vec::with_capacity(ranges.len());
                    for (lane, bytes) in buf.chunks_mut(self.chunk_bytes).enumerate() {
                        let r = ranges[lane];
                        let n = lengths[lane]
                            .saturating_sub(pos)
                            .min(self.chunk_bytes as u64) as usize;
                        let bytes = &mut bytes[..n];
                        bytes.fill(0);
                        let read = r.len.saturating_sub(pos).min(n as u64) as usize;
                        if read > 0 {
                            read_exact_at(
                                &file.as_ref().unwrap().1,
                                r.offset + pos,
                                &mut bytes[..read],
                            )?;
                        }
                        let data = r.pad_to.saturating_sub(pos).min(n as u64) as usize;
                        crcs[lane].update(&bytes[..data]);
                        if let Some(digest) = &mut scalar {
                            digest.update(&bytes[..data]);
                        }
                        if r.pad_to >= pos && r.pad_to - pos < n as u64 {
                            bytes[(r.pad_to - pos) as usize] = 0x80;
                        }
                        if n > 0 && pos + n as u64 == lengths[lane] {
                            bytes[n - 8..].copy_from_slice(&r.pad_to.wrapping_mul(8).to_le_bytes());
                        }
                        messages.push(&*bytes);
                    }
                    if scalar.is_none() {
                        compress_blocks(&mut states, &messages);
                    }
                    pos = pos.saturating_add(self.chunk_bytes as u64);
                }
                if let Some(digest) = scalar {
                    return Ok(vec![(crcs[0].finish(), digest.finalize().into())]);
                }
                Ok(states
                    .iter()
                    .zip(crcs)
                    .map(|(state, crc)| {
                        let mut digest = [0u8; 16];
                        for (bytes, word) in digest.chunks_mut(4).zip(state) {
                            bytes.copy_from_slice(&word.to_le_bytes());
                        }
                        (crc.finish(), digest)
                    })
                    .collect())
            })();
            match result {
                Ok(digests) => self.out.lock().unwrap_or_else(|p| p.into_inner())[job.clone()]
                    .copy_from_slice(&digests),
                Err(e) => {
                    self.fail(e);
                    return;
                }
            }
            let read_bytes = ranges.iter().map(|r| r.len).sum();
            let done = self.bytes_done.fetch_add(read_bytes, Ordering::Relaxed) + read_bytes;
            on_job(done);
        }
    }
}

/// CRC-32 and MD5 of every range, using up to `threads` workers (0 = all cores).
/// Worker message buffers share at most 8 MiB of scratch space.
///
/// `progress` receives the cumulative number of file bytes hashed; it is only called from the
/// calling thread. Ranges past the end of a file must be clamped by the caller (`len` may be 0
/// for an all-zero message).
pub fn hash_ranges_parallel(
    paths: &[&Path],
    ranges: &[HashRange],
    threads: usize,
    cancel: Option<&AtomicBool>,
    progress: &mut dyn FnMut(u64),
) -> io::Result<Vec<(u32, [u8; 16])>> {
    hash_ranges_parallel_with_budget(
        paths,
        ranges,
        threads,
        WORKING_MEMORY_BYTES,
        cancel,
        progress,
    )
}

/// Hash ranges with a shared budget for worker message buffers.
pub(crate) fn hash_ranges_parallel_with_budget(
    paths: &[&Path],
    ranges: &[HashRange],
    threads: usize,
    memory_bytes: u64,
    cancel: Option<&AtomicBool>,
    progress: &mut dyn FnMut(u64),
) -> io::Result<Vec<(u32, [u8; 16])>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    if ranges
        .iter()
        .any(|r| r.file >= paths.len() || r.len > r.pad_to || r.offset.checked_add(r.len).is_none())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid hash range",
        ));
    }
    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
    }
    if ranges.iter().any(|r| padded_bytes(r.pad_to).is_none()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hash range too large",
        ));
    }
    let memory_bytes = memory_bytes.clamp(READ_CHUNK as u64, WORKING_MEMORY_BYTES);
    let jobs = plan_jobs(ranges);
    let lanes = jobs.iter().map(|j| j.len()).max().unwrap_or(1);
    let threads = thread_count(threads).clamp(1, jobs.len());
    let threads = (threads as u64).min(memory_bytes / (lanes * 64) as u64) as usize;
    let per_lane = (memory_bytes / threads as u64 / lanes as u64).min(HASH_CHUNK as u64);
    let chunk_bytes = 1usize << per_lane.ilog2();
    let buffer_bytes = lanes * chunk_bytes;
    let pool = Pool {
        paths,
        ranges,
        jobs,
        chunk_bytes,
        buffer_bytes,
        next: AtomicUsize::new(0),
        bytes_done: AtomicU64::new(0),
        error: Mutex::new(None),
        stop: AtomicBool::new(false),
        cancel,
        out: Mutex::new(vec![(0u32, [0u8; 16]); ranges.len()]),
    };
    std::thread::scope(|s| {
        for _ in 1..threads {
            let p = &pool;
            s.spawn(move || p.work(&mut |_| {}));
        }
        pool.work(progress);
    });
    if let Some(e) = pool.error.into_inner().unwrap_or_else(|p| p.into_inner()) {
        return Err(e);
    }
    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
    }
    progress(pool.bytes_done.load(Ordering::Relaxed));
    Ok(pool.out.into_inner().unwrap_or_else(|p| p.into_inner()))
}

/// Ranges for every `slice_size` slice of a file: `slices` messages at `b * slice_size`, each
/// reading what the file has there (`file_len` is the on-disk length) and padding to a full slice.
pub fn slice_ranges(file: usize, file_len: u64, slice_size: u64, slices: u64) -> Vec<HashRange> {
    (0..slices)
        .map(|b| {
            let offset = b * slice_size;
            let len = file_len.saturating_sub(offset).min(slice_size);
            HashRange {
                file,
                offset,
                len,
                pad_to: slice_size,
            }
        })
        .collect()
}

/// Whole-file digests (CRC-32, MD5, 16k MD5) of several files, one file per thread.
pub fn file_hashes_parallel(
    paths: &[&Path],
    threads: usize,
    cancel: Option<&AtomicBool>,
) -> io::Result<Vec<FileHashes>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let threads = thread_count(threads).clamp(1, paths.len());
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Option<FileHashes>>> = Mutex::new(vec![None; paths.len()]);
    let error: Mutex<Option<io::Error>> = Mutex::new(None);
    let stop = AtomicBool::new(false);
    let work = || {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            if stop.load(Ordering::Relaxed) || cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return;
            }
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some(path) = paths.get(i) else {
                return;
            };
            let res: io::Result<FileHashes> = (|| {
                let mut f = File::open(path)?;
                let mut h = FileHasher::new();
                loop {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                    }
                    let n = match f.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    };
                    h.update(&buf[..n]);
                }
                Ok(h.finish())
            })();
            match res {
                Ok(h) => out.lock().unwrap_or_else(|p| p.into_inner())[i] = Some(h),
                Err(e) => {
                    let mut g = error.lock().unwrap_or_else(|p| p.into_inner());
                    if g.is_none() {
                        *g = Some(e);
                    }
                    stop.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }
    };
    std::thread::scope(|s| {
        for _ in 1..threads {
            s.spawn(work);
        }
        work();
    });
    if let Some(e) = error.into_inner().unwrap_or_else(|p| p.into_inner()) {
        return Err(e);
    }
    let out = out.into_inner().unwrap_or_else(|p| p.into_inner());
    out.into_iter()
        .map(|h| h.ok_or_else(|| io::Error::new(io::ErrorKind::Interrupted, "cancelled")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{hash_file, slice_checksums};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("par-rs-parhash-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn streaming_simd_matches_scalar_at_lane_chunk_and_padding_boundaries() {
        let dir = tmpdir("streaming-simd");
        let path = dir.join("data");
        let data: Vec<u8> = (0..262144u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        std::fs::write(&path, &data).unwrap();
        let sizes = [
            0, 1, 55, 56, 63, 64, 16383, 16384, 16385, 65535, 65536, 65537, 131071, 131072, 131073,
        ];
        let ranges: Vec<HashRange> = (0..33)
            .map(|i| {
                let len = sizes[i % sizes.len()];
                HashRange {
                    file: 0,
                    offset: (i * 17) as u64,
                    len,
                    pad_to: len + (i % 5) as u64,
                }
            })
            .collect();
        let expected: Vec<_> = ranges
            .iter()
            .map(|r| {
                let mut message = data[r.offset as usize..(r.offset + r.len) as usize].to_vec();
                message.resize(r.pad_to as usize, 0);
                slice_checksums(&message)
            })
            .collect();
        for (range, expected) in ranges.iter().zip(&expected) {
            let got = hash_ranges_parallel(&[&path], &[*range], 1, None, &mut |_| {}).unwrap();
            assert_eq!(got, vec![*expected]);
        }
        for count in [1, 2, 4, 5, 8, 9, 16, 17, 33] {
            for budget in [1 << 20, 8 << 20] {
                let got = hash_ranges_parallel_with_budget(
                    &[&path],
                    &ranges[..count],
                    3,
                    budget,
                    None,
                    &mut |_| {},
                )
                .unwrap();
                assert_eq!(got, expected[..count], "lanes {count}, budget {budget}");
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_ranges_and_cancelled_huge_padding_do_not_panic() {
        let paths = [Path::new("unused")];
        for range in [
            HashRange {
                file: 1,
                offset: 0,
                len: 0,
                pad_to: 0,
            },
            HashRange {
                file: 0,
                offset: 0,
                len: 2,
                pad_to: 1,
            },
            HashRange {
                file: 0,
                offset: u64::MAX,
                len: 1,
                pad_to: 1,
            },
        ] {
            let error = hash_ranges_parallel(&paths, &[range], 1, None, &mut |_| {}).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        let cancel = AtomicBool::new(true);
        let range = HashRange {
            file: 0,
            offset: 0,
            len: 0,
            pad_to: u64::MAX,
        };
        let error =
            hash_ranges_parallel(&paths, &[range], 1, Some(&cancel), &mut |_| {}).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn slice_hashes_match_sequential_for_short_last_slice_and_missing_tail() {
        let dir = tmpdir("slices");
        let ss = 1000u64;
        let data: Vec<u8> = (0..12_345u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 7) as u8)
            .collect();
        let p = dir.join("a.bin");
        std::fs::write(&p, &data).unwrap();
        let q = dir.join("b.bin");
        std::fs::write(&q, &data[..5000]).unwrap();
        let mut ranges = slice_ranges(0, data.len() as u64, ss, 13);
        ranges.extend(slice_ranges(1, 5000, ss, 13)); // declared longer than on disk
        let paths = [p.as_path(), q.as_path()];
        for threads in [1, 3] {
            let mut last = 0;
            let got =
                hash_ranges_parallel(&paths, &ranges, threads, None, &mut |b| last = b).unwrap();
            assert_eq!(got.len(), 26);
            assert_eq!(last, data.len() as u64 + 5000);
            for b in 0..13usize {
                let mut s =
                    data[(b * 1000).min(data.len())..((b + 1) * 1000).min(data.len())].to_vec();
                s.resize(1000, 0);
                assert_eq!(got[b], slice_checksums(&s), "file a slice {b}");
                let mut s = data[(b * 1000).min(5000)..((b + 1) * 1000).min(5000)].to_vec();
                s.resize(1000, 0);
                assert_eq!(got[13 + b], slice_checksums(&s), "file b slice {b}");
            }
        }
        // Many small ranges exercise multi-job planning.
        let many: Vec<HashRange> = (0..3000)
            .map(|i| HashRange {
                file: 0,
                offset: (i % 12_000) as u64,
                len: 300,
                pad_to: 300,
            })
            .collect();
        let got = hash_ranges_parallel(&paths, &many, 4, None, &mut |_| {}).unwrap();
        for (i, r) in many.iter().enumerate() {
            assert_eq!(
                got[i],
                slice_checksums(&data[r.offset as usize..r.offset as usize + 300])
            );
        }
        assert!(plan_jobs(&many).len() > 1);
        let big: Vec<HashRange> = (0..100)
            .map(|i| HashRange {
                file: 0,
                offset: 0,
                len: 0,
                pad_to: (32 << 20) / 10 * (1 + i % 2),
            })
            .collect();
        assert!(plan_jobs(&big).len() > 1);

        // Errors and cancellation surface.
        let missing = [dir.join("nope.bin")];
        let mp = [missing[0].as_path()];
        assert!(
            hash_ranges_parallel(&mp, &slice_ranges(0, 10, 5, 2), 2, None, &mut |_| {}).is_err()
        );
        let c = AtomicBool::new(true);
        assert!(hash_ranges_parallel(&paths, &ranges, 2, Some(&c), &mut |_| {}).is_err());
        assert!(
            hash_ranges_parallel(&paths, &[], 2, None, &mut |_| {})
                .unwrap()
                .is_empty()
        );

        let fh = file_hashes_parallel(&paths, 2, None).unwrap();
        assert_eq!(fh[0], hash_file(&p).unwrap());
        assert_eq!(fh[1], hash_file(&q).unwrap());
        assert!(file_hashes_parallel(&mp, 1, None).is_err());
        assert!(file_hashes_parallel(&paths, 1, Some(&c)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
