use super::RepairError;
use crate::packet::PacketSource;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const READ_STEP: usize = 64 * 1024;

/// Cumulative logical bytes consumed by a live session, not physical device I/O.
/// Successful chunks before a failed read are included. Recovery bytes include
/// packet scanning, authentication and payload reads; they can exceed file size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LiveIoStats {
    /// IFSC-verified source bytes supplied by the caller, counted once per slice.
    pub ram_bytes_verified: u64,
    /// Source bytes read to verify arriving slices without complete RAM data.
    pub source_bytes_read: u64,
    /// Source bytes reread to populate later recovery exponents.
    pub backfill_bytes_read: u64,
    /// Recovery file bytes read, including metadata, and repeated hash reads.
    pub recovery_bytes_read: u64,
    /// Repaired target bytes read for the final whole-file hash.
    pub target_verification_bytes_read: u64,
}

#[derive(Default)]
pub(super) struct LiveControl {
    pub cancelled: AtomicBool,
    pub ram: AtomicU64,
    source: AtomicU64,
    backfill: AtomicU64,
    recovery: AtomicU64,
    target: AtomicU64,
}

#[derive(Clone, Copy)]
pub(super) enum IoClass {
    Source,
    Backfill,
    Recovery,
    Target,
}

impl LiveControl {
    pub fn ensure_running(&self) -> Result<(), RepairError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(RepairError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn ensure_reading(&self) -> io::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(io::Error::other("live session cancelled"))
        } else {
            Ok(())
        }
    }

    fn count(&self, class: IoClass, bytes: usize) {
        let counter = match class {
            IoClass::Source => &self.source,
            IoClass::Backfill => &self.backfill,
            IoClass::Recovery => &self.recovery,
            IoClass::Target => &self.target,
        };
        counter.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn io_error(&self, context: String, error: io::Error) -> RepairError {
        if self.cancelled.load(Ordering::Acquire) {
            RepairError::Cancelled
        } else {
            RepairError::Io {
                context,
                source: error,
            }
        }
    }

    pub fn stats(&self) -> LiveIoStats {
        LiveIoStats {
            ram_bytes_verified: self.ram.load(Ordering::Relaxed),
            source_bytes_read: self.source.load(Ordering::Relaxed),
            backfill_bytes_read: self.backfill.load(Ordering::Relaxed),
            recovery_bytes_read: self.recovery.load(Ordering::Relaxed),
            target_verification_bytes_read: self.target.load(Ordering::Relaxed),
        }
    }
}

pub(super) struct CountedFile<'a> {
    file: Mutex<File>,
    len: u64,
    control: &'a LiveControl,
    class: IoClass,
}

impl<'a> CountedFile<'a> {
    pub fn open(path: &Path, control: &'a LiveControl, class: IoClass) -> io::Result<Self> {
        control.ensure_reading()?;
        Self::from_file(File::open(path)?, control, class)
    }

    pub fn from_file(file: File, control: &'a LiveControl, class: IoClass) -> io::Result<Self> {
        control.ensure_reading()?;
        let len = file.metadata()?.len();
        Ok(Self {
            file: Mutex::new(file),
            len,
            control,
            class,
        })
    }

    fn read_chunk(&self, file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
        self.control.ensure_reading()?;
        let len = buf.len().min(READ_STEP);
        let n = file.read(&mut buf[..len])?;
        self.control.count(self.class, n);
        Ok(n)
    }
}

impl PacketSource for CountedFile<'_> {
    fn source_len(&self) -> u64 {
        self.len
    }
    fn read_at(&self, offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        self.control.ensure_reading()?;
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        file.seek(SeekFrom::Start(offset))?;
        while !buf.is_empty() {
            match self.read_chunk(&mut file, buf) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => buf = &mut buf[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl Read for &CountedFile<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        self.read_chunk(&mut file, buf)
    }
}
