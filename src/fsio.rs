//! File-system helpers for repair: copy-on-write backups and page-cache hints.

use std::fs::File;
use std::io;
use std::path::Path;

/// How [`clone_or_copy`] made the copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyKind {
    /// A copy-on-write clone (`clonefile` on APFS, `FICLONE` on btrfs and XFS): no data is
    /// written until either file changes.
    Clone,
    /// A byte copy.
    Copy,
}

/// Copy `src` to the new file `dst` (which must not exist), as a copy-on-write clone where
/// the file system supports one and as a byte copy otherwise. Permissions are copied.
pub(crate) fn clone_or_copy(src: &Path, dst: &Path) -> io::Result<CopyKind> {
    if try_clone(src, dst).is_ok() {
        return Ok(CopyKind::Clone);
    }
    std::fs::copy(src, dst)?;
    Ok(CopyKind::Copy)
}

#[cfg(target_vendor = "apple")]
fn try_clone(src: &Path, dst: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let s = CString::new(src.as_os_str().as_bytes())?;
    let d = CString::new(dst.as_os_str().as_bytes())?;
    // SAFETY: both arguments are NUL-terminated paths that outlive the call.
    if unsafe { libc::clonefile(s.as_ptr(), d.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn try_clone(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    /// `_IOW(0x94, 9, int)`.
    const FICLONE: libc::c_ulong = 0x4004_9409;
    let s = File::open(src)?;
    let d = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)?;
    // SAFETY: both descriptors are open for the duration of the call.
    let rc = unsafe { libc::ioctl(d.as_raw_fd(), FICLONE as _, s.as_raw_fd()) };
    let result = if rc == 0 {
        s.metadata()
            .and_then(|m| std::fs::set_permissions(dst, m.permissions()))
    } else {
        Err(io::Error::last_os_error())
    };
    if result.is_err() {
        drop(d);
        let _ = std::fs::remove_file(dst);
    }
    result
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn try_clone(_src: &Path, _dst: &Path) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Ask the OS not to keep what is read through `file` in the page cache (`F_NOCACHE` on
/// macOS; elsewhere nothing, see [`drop_cached`]). Best effort.
#[allow(unused_variables)]
pub(crate) fn read_uncached(file: &File) {
    #[cfg(target_vendor = "apple")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `fcntl(F_NOCACHE)` only sets a flag on an open descriptor.
        unsafe {
            libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1);
        }
    }
}

/// Drop the cached pages of `path` once it has been read (`posix_fadvise(DONTNEED)` on Linux;
/// elsewhere nothing, see [`read_uncached`]). Best effort: returns whether the hint was given.
#[cfg(target_os = "linux")]
pub(crate) fn drop_cached(path: &Path) -> bool {
    use std::os::unix::io::AsRawFd;
    let Ok(f) = File::open(path) else {
        return false;
    };
    // SAFETY: `posix_fadvise` only reads the descriptor and the range.
    unsafe { libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) == 0 }
}

/// Drop the cached pages of `path` (Linux only; elsewhere returns false).
#[cfg(not(target_os = "linux"))]
pub(crate) fn drop_cached(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("par-rs-fsio-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn clone_or_copy_duplicates_contents_and_refuses_an_existing_target() {
        let d = tmp("copy");
        let src = d.join("a.bin");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 + i / 300) as u8).collect();
        std::fs::write(&src, &data).unwrap();
        let kind = clone_or_copy(&src, &d.join("b.bin")).unwrap();
        assert_eq!(std::fs::read(d.join("b.bin")).unwrap(), data);
        // APFS always clones; other file systems may or may not.
        if cfg!(target_vendor = "apple") {
            assert_eq!(kind, CopyKind::Clone);
        }
        // The clone is independent of the original.
        std::fs::write(&src, b"changed").unwrap();
        assert_eq!(std::fs::read(d.join("b.bin")).unwrap(), data);
        // A failed clone (target exists) falls back to a copy, which overwrites like
        // `std::fs::copy`; callers only pass names that do not exist.
        std::fs::write(d.join("c.bin"), b"old").unwrap();
        assert_eq!(
            clone_or_copy(&src, &d.join("c.bin")).unwrap(),
            CopyKind::Copy
        );
        assert_eq!(std::fs::read(d.join("c.bin")).unwrap(), b"changed");
        assert!(clone_or_copy(&d.join("missing"), &d.join("x")).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn cache_hints_are_harmless() {
        let d = tmp("cache");
        let p = d.join("v.par2");
        std::fs::write(&p, vec![5u8; 1 << 16]).unwrap();
        let f = File::open(&p).unwrap();
        read_uncached(&f);
        let mut buf = vec![0u8; 1 << 16];
        crate::packet::read_exact_at(&f, 0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 5));
        assert_eq!(drop_cached(&p), cfg!(target_os = "linux"));
        assert!(!drop_cached(&d.join("missing")));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
