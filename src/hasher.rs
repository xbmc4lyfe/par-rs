//! Fused single-pass hashing: CRC-32, full-file MD5 and the PAR2 "16k" MD5.
//!
//! PAR2 identifies files by three digests: the MD5 of the whole file, the MD5 of its first
//! 16384 bytes (used to match renamed/obfuscated files cheaply) and, per slice, an MD5 plus a
//! CRC-32. [`FileHasher`] computes all three file-level digests in a single pass over the data
//! so a verification read never has to touch the bytes twice.

use crate::crc::Crc32;
use md5::{Digest, Md5};
use std::io::{self, Read};

/// Size of the PAR2 "16k" hash prefix.
pub const HASH_16K_LEN: u64 = 16 * 1024;

/// Preferred read buffer size for file hashing.
pub const READ_CHUNK: usize = 1 << 20;

/// Result of hashing a whole file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileHashes {
    /// CRC-32 of the whole file.
    pub crc32: u32,
    /// MD5 of the whole file.
    pub md5_full: [u8; 16],
    /// MD5 of the first `min(len, 16384)` bytes.
    pub md5_16k: [u8; 16],
    /// Number of bytes hashed.
    pub len: u64,
}

/// Streaming fused hasher.
#[derive(Clone)]
pub struct FileHasher {
    crc: Crc32,
    md5: Md5,
    md5_16k: Md5,
    len: u64,
}

impl Default for FileHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl FileHasher {
    /// New hasher.
    pub fn new() -> Self {
        Self { crc: Crc32::new(), md5: Md5::new(), md5_16k: Md5::new(), len: 0 }
    }

    /// Feed data (one pass over `data` for all digests).
    pub fn update(&mut self, data: &[u8]) {
        if self.len < HASH_16K_LEN {
            let take = ((HASH_16K_LEN - self.len) as usize).min(data.len());
            self.md5_16k.update(&data[..take]);
        }
        self.crc.update(data);
        self.md5.update(data);
        self.len += data.len() as u64;
    }

    /// Bytes processed so far.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing has been hashed yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Current CRC-32 (does not consume).
    pub fn crc32(&self) -> u32 {
        self.crc.finish()
    }

    /// Finish and return all digests.
    pub fn finish(self) -> FileHashes {
        FileHashes {
            crc32: self.crc.finish(),
            md5_full: self.md5.finalize().into(),
            md5_16k: self.md5_16k.finalize().into(),
            len: self.len,
        }
    }
}

/// MD5 of `data`.
pub fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// MD5 of the first `min(len, 16384)` bytes of `data`.
pub fn md5_16k(data: &[u8]) -> [u8; 16] {
    let n = data.len().min(HASH_16K_LEN as usize);
    md5(&data[..n])
}

/// CRC-32 and MD5 of a slice buffer (the IFSC checksum pair).
pub fn slice_checksums(slice: &[u8]) -> (u32, [u8; 16]) {
    (crate::crc::crc32(slice), md5(slice))
}

/// Hash everything readable from `reader`.
pub fn hash_reader<R: Read>(mut reader: R) -> io::Result<FileHashes> {
    let mut buf = vec![0u8; READ_CHUNK];
    let mut h = FileHasher::new();
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
    }
    Ok(h.finish())
}

/// Hash a file on disk.
pub fn hash_file(path: &std::path::Path) -> io::Result<FileHashes> {
    hash_reader(std::fs::File::open(path)?)
}

/// MD5 of the first 16 KiB of a file on disk (reads at most 16384 bytes).
pub fn file_md5_16k(path: &std::path::Path) -> io::Result<[u8; 16]> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; HASH_16K_LEN as usize];
    let mut filled = 0usize;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(md5(&buf[..filled]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn md5_known_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn fused_hasher_matches_separate_digests() {
        let data: Vec<u8> = (0..40_000u32).map(|i| (i.wrapping_mul(2654435761u32) >> 13) as u8).collect();
        let mut h = FileHasher::new();
        assert!(h.is_empty());
        for chunk in data.chunks(1234) {
            h.update(chunk);
        }
        assert_eq!(h.len(), data.len() as u64);
        assert_eq!(h.crc32(), crate::crc::crc32(&data));
        let r = h.finish();
        assert_eq!(r.crc32, crate::crc::crc32(&data));
        assert_eq!(r.md5_full, md5(&data));
        assert_eq!(r.md5_16k, md5(&data[..16384]));
        assert_eq!(r.md5_16k, md5_16k(&data));
        assert_eq!(r.len, data.len() as u64);

        // Short input: the 16k hash equals the full hash.
        let short = &data[..1000];
        let mut h = FileHasher::new();
        h.update(short);
        let r = h.finish();
        assert_eq!(r.md5_16k, r.md5_full);
        assert_eq!(md5_16k(short), md5(short));

        // Exactly 16384 bytes.
        let mut h = FileHasher::new();
        h.update(&data[..16384]);
        let r = h.finish();
        assert_eq!(r.md5_16k, r.md5_full);

        let (c, m) = slice_checksums(short);
        assert_eq!(c, crate::crc::crc32(short));
        assert_eq!(m, md5(short));
    }

    #[test]
    fn reader_and_file_helpers() {
        let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let r = hash_reader(&data[..]).unwrap();
        assert_eq!(r.md5_full, md5(&data));
        let dir = std::env::temp_dir().join(format!("par-rs-hasher-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.bin");
        std::fs::write(&p, &data).unwrap();
        let f = hash_file(&p).unwrap();
        assert_eq!(f, r);
        assert_eq!(file_md5_16k(&p).unwrap(), md5_16k(&data));
        let empty = dir.join("empty.bin");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(file_md5_16k(&empty).unwrap(), md5(b""));
        assert_eq!(hash_file(&empty).unwrap().len, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
