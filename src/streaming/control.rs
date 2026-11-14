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

/// Cumulative wall-clock nanoseconds for selected-target repair calls.
/// Timers include failed and cancelled attempts. Decode time includes output
/// callbacks; target write time is nested within decode time. Parallel work can
/// overlap, so these fields must not be summed or subtracted as CPU time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RepairPhaseStats {
    /// Total started calls. Counts refusals and cancellations.
    pub attempts: u64,
    /// Calls that returned an `Ok` report; inspect its per-file verification flags.
    pub completed: u64,
    /// Bytes in fully successful target write callbacks, not physical device I/O.
    pub target_bytes_written: u64,
    /// Time waiting for exclusive payload admission.
    pub payload_wait_ns: u64,
    /// Time reconciling recovery slots before matrix planning.
    pub backfill_ns: u64,
    /// Recovery matrix planning, inversion, and selected-row construction.
    pub matrix_ns: u64,
    /// Decode engine wall time, including its output callbacks.
    pub decode_ns: u64,
    /// Target write system calls within the decode callbacks.
    pub target_write_ns: u64,
    /// Target data synchronization attempts.
    pub target_sync_ns: u64,
    /// Publishing and folding reconstructed source slices into syndromes.
    pub refold_ns: u64,
    /// Whole-file target MD5 and length checks.
    pub target_verification_ns: u64,
    /// Elapsed time for the entire selected-target call.
    pub total_ns: u64,
}

#[derive(Clone, Copy)]
pub(super) enum RepairPhase {
    PayloadWait,
    Backfill,
    Matrix,
    Decode,
    Write,
    Sync,
    Refold,
    Verify,
    Total,
}

pub(super) struct PhaseTimer<'a> {
    counter: &'a AtomicU64,
    started: std::time::Instant,
}
impl Drop for PhaseTimer<'_> {
    fn drop(&mut self) {
        let elapsed = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let _ = self
            .counter
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(old.saturating_add(elapsed))
            });
    }
}

#[derive(Default)]
pub(super) struct LiveControl {
    pub cancelled: AtomicBool,
    pub ram: AtomicU64,
    source: AtomicU64,
    backfill: AtomicU64,
    recovery: AtomicU64,
    target: AtomicU64,
    pub repair_attempts: AtomicU64,
    pub repair_completed: AtomicU64,
    pub repair_written: AtomicU64,
    phases: [AtomicU64; 9],
}

#[derive(Clone, Copy)]
pub(super) enum IoClass {
    Source,
    Backfill,
    Recovery,
    Target,
}

impl LiveControl {
    pub fn phase(&self, phase: RepairPhase) -> PhaseTimer<'_> {
        PhaseTimer {
            counter: &self.phases[phase as usize],
            started: std::time::Instant::now(),
        }
    }
    pub fn repair_stats(&self) -> RepairPhaseStats {
        let phase = |p: RepairPhase| self.phases[p as usize].load(Ordering::Relaxed);
        RepairPhaseStats {
            attempts: self.repair_attempts.load(Ordering::Relaxed),
            completed: self.repair_completed.load(Ordering::Relaxed),
            target_bytes_written: self.repair_written.load(Ordering::Relaxed),
            payload_wait_ns: phase(RepairPhase::PayloadWait),
            backfill_ns: phase(RepairPhase::Backfill),
            matrix_ns: phase(RepairPhase::Matrix),
            decode_ns: phase(RepairPhase::Decode),
            target_write_ns: phase(RepairPhase::Write),
            target_sync_ns: phase(RepairPhase::Sync),
            refold_ns: phase(RepairPhase::Refold),
            target_verification_ns: phase(RepairPhase::Verify),
            total_ns: phase(RepairPhase::Total),
        }
    }
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
