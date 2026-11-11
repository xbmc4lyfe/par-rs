//! Parallel hashing of file ranges: a thread pool over `(file, offset, length)` jobs, each job
//! hashing its ranges with the multi-lane MD5 ([`crate::md5simd`]) and hardware CRC-32.
//!
//! PAR2 verification and creation are hash bound: every slice needs its own MD5 and CRC, and
//! on one core MD5 runs at about 1 GB/s. Slices are independent messages, so a job of several
//! slices is hashed in lockstep lanes, and jobs are spread over all cores. The whole-file MD5
//! chains (file description digests) cannot be split, so they run one file per thread.

use crate::crc::{Crc32, crc32};
use crate::hasher::{FileHasher, FileHashes, READ_CHUNK};
use crate::md5simd::{LANES, md5_many_into};
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

/// Target bytes of message data per job (more lanes per job, fewer pool round trips).
const JOB_BYTES: u64 = 32 << 20;

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

/// Group consecutive ranges into jobs of roughly [`JOB_BYTES`], keeping multiples of the MD5
/// lane count where possible so no lane idles.
fn plan_jobs(ranges: &[HashRange]) -> Vec<std::ops::Range<usize>> {
    let mut jobs = Vec::new();
    let mut start = 0usize;
    let mut bytes = 0u64;
    for (i, r) in ranges.iter().enumerate() {
        if i > start && r.pad_to.max(1) > JOB_BYTES.saturating_sub(bytes) {
            jobs.push(start..i);
            start = i;
            bytes = 0;
        }
        bytes = bytes.saturating_add(r.pad_to.max(1));
        let count = i + 1 - start;
        let full = bytes >= JOB_BYTES
            && (count.is_multiple_of(LANES) || r.pad_to.max(1) > JOB_BYTES / LANES as u64);
        if full {
            jobs.push(start..i + 1);
            start = i + 1;
            bytes = 0;
        }
    }
    if start < ranges.len() {
        jobs.push(start..ranges.len());
    }
    jobs
}

/// Shared pool state.
struct Pool<'a> {
    paths: &'a [&'a Path],
    ranges: &'a [HashRange],
    jobs: Vec<std::ops::Range<usize>>,
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

    /// Run jobs until none are left; `on_job` is called after each job with the bytes done so far.
    fn work(&self, on_job: &mut dyn FnMut(u64)) {
        let mut file: Option<(usize, File)> = None;
        let mut buf: Vec<u8> = Vec::new();
        let mut digests: Vec<[u8; 16]> = Vec::new();
        loop {
            if self.stopped() {
                return;
            }
            let j = self.next.fetch_add(1, Ordering::Relaxed);
            let Some(job) = self.jobs.get(j) else {
                return;
            };
            let rs = &self.ranges[job.clone()];
            if rs[0].pad_to > JOB_BYTES {
                let r = rs[0];
                let result = (|| -> io::Result<(u32, [u8; 16])> {
                    let f = if r.len > 0 {
                        Some(File::open(self.paths[r.file])?)
                    } else {
                        None
                    };
                    buf.resize(READ_CHUNK, 0);
                    let mut crc = Crc32::new();
                    let mut md5 = Md5::new();
                    let mut pos = 0;
                    while pos < r.pad_to {
                        if self.stopped() {
                            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                        }
                        let n = (r.pad_to - pos).min(buf.len() as u64) as usize;
                        let read = r.len.saturating_sub(pos).min(n as u64) as usize;
                        if let Some(f) = &f
                            && read > 0
                        {
                            read_exact_at(f, r.offset + pos, &mut buf[..read])?;
                        }
                        buf[read..n].fill(0);
                        crc.update(&buf[..n]);
                        md5.update(&buf[..n]);
                        pos += n as u64;
                    }
                    Ok((crc.finish(), md5.finalize().into()))
                })();
                match result {
                    Ok(digest) => {
                        self.out.lock().unwrap_or_else(|p| p.into_inner())[job.start] = digest
                    }
                    Err(e) => {
                        self.fail(e);
                        return;
                    }
                }
                let done = self.bytes_done.fetch_add(r.len, Ordering::Relaxed) + r.len;
                on_job(done);
                continue;
            }
            let total: usize = rs.iter().map(|r| r.pad_to as usize).sum();
            buf.clear();
            buf.reserve_exact(total);
            buf.resize(total, 0);
            let mut off = 0usize;
            let mut read_bytes = 0u64;
            for r in rs {
                let n = r.len as usize;
                if n > 0 {
                    if file.as_ref().map(|(i, _)| *i) != Some(r.file) {
                        // Close the previous file before opening another one.
                        drop(file.take());
                        match File::open(self.paths[r.file]) {
                            Ok(f) => file = Some((r.file, f)),
                            Err(e) => {
                                self.fail(e);
                                return;
                            }
                        }
                    }
                    let f = &file.as_ref().unwrap().1;
                    if let Err(e) = read_exact_at(f, r.offset, &mut buf[off..off + n]) {
                        self.fail(e);
                        return;
                    }
                    read_bytes += n as u64;
                }
                off += r.pad_to as usize;
            }
            let mut msgs: Vec<&[u8]> = Vec::with_capacity(rs.len());
            let mut off = 0usize;
            for r in rs {
                msgs.push(&buf[off..off + r.pad_to as usize]);
                off += r.pad_to as usize;
            }
            digests.clear();
            digests.resize(rs.len(), [0u8; 16]);
            md5_many_into(&msgs, &mut digests);
            {
                let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
                for (k, m) in msgs.iter().enumerate() {
                    out[job.start + k] = (crc32(m), digests[k]);
                }
            }
            let done = self.bytes_done.fetch_add(read_bytes, Ordering::Relaxed) + read_bytes;
            on_job(done);
        }
    }
}

/// CRC-32 and MD5 of every range, in order, computed on `threads` threads (0 = all cores).
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
    let jobs = plan_jobs(ranges);
    let threads = thread_count(threads).clamp(1, jobs.len());
    let pool = Pool {
        paths,
        ranges,
        jobs,
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
        assert!(plan_jobs(&many).len() == 1);
        let big: Vec<HashRange> = (0..100)
            .map(|i| HashRange {
                file: 0,
                offset: 0,
                len: 0,
                pad_to: (JOB_BYTES / 10) * (1 + i % 2),
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
