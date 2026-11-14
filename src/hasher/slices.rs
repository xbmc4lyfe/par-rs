// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! Fused whole-file and padded slice hashing of caller-supplied bytes.
use super::{FileHasher, FileHashes};
use crate::crc::Crc32;
use crate::packet::SliceChecksum;
use md5::{Digest, Md5};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

const WORK_WINDOW: usize = 64 << 10;
const ZEROS: [u8; 4096] = [0; 4096];
type Emitter<'a> = dyn FnMut(u64, SliceChecksum) -> io::Result<()> + 'a;

/// File and PAR2 slice digests with caller-owned input and record storage.
///
/// Feed the same ordered byte stream and callback across updates. The callback owns
/// any collected records and their count/allocation admission. Only an incomplete
/// final slice is padded; whole-file hashes and length contain actual bytes only.
/// This helper performs no I/O and provides no source-binding or publication proof.
/// It has no default geometry, cloning, or resume interface.
pub struct FileSliceHasher {
    file: FileHasher,
    slice_crc: Crc32,
    slice_md5: Md5,
    slice_size: u64,
    in_slice: u64,
    next_index: u64,
    failed: bool,
}
impl FileSliceHasher {
    /// Start with a positive slice size divisible by four.
    ///
    /// Invalid geometry returns InvalidInput. No additional input-size ceiling is
    /// imposed; large geometry remains caller-chosen work, with bounded polling.
    pub fn new(slice_size: u64) -> io::Result<Self> {
        if slice_size == 0 || !slice_size.is_multiple_of(4) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "slice size must be a positive multiple of four",
            ));
        }
        Ok(Self {
            file: FileHasher::new(),
            slice_crc: Crc32::new(),
            slice_md5: Md5::new(),
            slice_size,
            in_slice: 0,
            next_index: 0,
            failed: false,
        })
    }

    /// Feed actual bytes and emit completed slices with zero-based indexes.
    ///
    /// Cancellation is checked even for an empty update, between processing windows
    /// of at most 64 KiB, and before/after callbacks. Observed cancellation returns
    /// Interrupted; counter overflow returns InvalidData. A callback's error returns
    /// unchanged, ahead of cancellation that it also sets. Any terminal failure
    /// poisons reuse: later update/finish returns Other before digest work/callbacks.
    /// Already emitted records are provisional caller state and are not rolled back.
    pub fn update(
        &mut self,
        bytes: &[u8],
        cancel: Option<&AtomicBool>,
        emit: &mut dyn FnMut(u64, SliceChecksum) -> io::Result<()>,
    ) -> io::Result<()> {
        self.update_checked(
            bytes,
            &mut || cancel.is_some_and(|c| c.load(Ordering::Relaxed)),
            emit,
        )
    }

    /// Emit any incomplete padded tail and return actual-byte file hashes.
    ///
    /// Empty input emits no slice; an exact boundary emits no additional slice.
    /// Padding uses fixed 4 KiB windows with cancellation checks. Cancellation set
    /// by the last callback is checked before success. This consumes the object;
    /// failure returns no FileHashes and does not revoke earlier emitted records.
    pub fn finish(
        self,
        cancel: Option<&AtomicBool>,
        emit: &mut dyn FnMut(u64, SliceChecksum) -> io::Result<()>,
    ) -> io::Result<FileHashes> {
        self.finish_checked(
            &mut || cancel.is_some_and(|c| c.load(Ordering::Relaxed)),
            emit,
        )
    }

    fn poison(&mut self, error: io::Error) -> io::Error {
        self.failed = true;
        error
    }
    fn arithmetic(&mut self, message: &'static str) -> io::Error {
        self.poison(io::Error::new(io::ErrorKind::InvalidData, message))
    }
    fn checkpoint(&mut self, cancelled: &mut dyn FnMut() -> bool) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other(
                "file/slice hasher cannot continue after failure",
            ));
        }
        if cancelled() {
            return Err(self.poison(io::Error::new(
                io::ErrorKind::Interrupted,
                "file/slice hashing cancelled",
            )));
        }
        Ok(())
    }
    fn emit_slice(
        &mut self,
        cancelled: &mut dyn FnMut() -> bool,
        emit: &mut Emitter<'_>,
    ) -> io::Result<()> {
        self.checkpoint(cancelled)?;
        let next = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| self.arithmetic("slice index overflow"))?;
        let checksum = SliceChecksum {
            crc32: self.slice_crc.finish(),
            md5: std::mem::take(&mut self.slice_md5).finalize().into(),
        };
        self.failed = true;
        emit(self.next_index, checksum)?;
        self.failed = false;
        self.next_index = next;
        self.in_slice = 0;
        self.slice_crc = Crc32::new();
        self.checkpoint(cancelled)
    }
    fn update_checked(
        &mut self,
        mut bytes: &[u8],
        cancelled: &mut dyn FnMut() -> bool,
        emit: &mut Emitter<'_>,
    ) -> io::Result<()> {
        self.checkpoint(cancelled)?;
        let actual = u64::try_from(bytes.len())
            .map_err(|_| self.arithmetic("input length does not fit u64"))?;
        self.file
            .len()
            .checked_add(actual)
            .ok_or_else(|| self.arithmetic("actual file length overflow"))?;
        while !bytes.is_empty() {
            self.checkpoint(cancelled)?;
            let left = self
                .slice_size
                .checked_sub(self.in_slice)
                .ok_or_else(|| self.arithmetic("invalid slice position"))?;
            if left == 0 {
                return Err(self.arithmetic("unemitted complete slice"));
            }
            let n = left.min(bytes.len() as u64).min(WORK_WINDOW as u64) as usize;
            let next = self
                .in_slice
                .checked_add(n as u64)
                .ok_or_else(|| self.arithmetic("slice position overflow"))?;
            let fragment = &bytes[..n];
            // The whole update's actual length was admitted before FileHasher's
            // unchecked internal counter can advance. Padding never reaches it.
            self.file.update(fragment);
            self.slice_crc.update(fragment);
            self.slice_md5.update(fragment);
            self.in_slice = next;
            bytes = &bytes[n..];
            if self.in_slice == self.slice_size {
                self.emit_slice(cancelled, emit)?;
            }
        }
        self.checkpoint(cancelled)
    }
    fn finish_checked(
        mut self,
        cancelled: &mut dyn FnMut() -> bool,
        emit: &mut Emitter<'_>,
    ) -> io::Result<FileHashes> {
        self.checkpoint(cancelled)?;
        if self.in_slice > 0 {
            let mut left = self
                .slice_size
                .checked_sub(self.in_slice)
                .ok_or_else(|| self.arithmetic("invalid final slice position"))?;
            while left > 0 {
                self.checkpoint(cancelled)?;
                let n = left.min(ZEROS.len() as u64) as usize;
                let next = self
                    .in_slice
                    .checked_add(n as u64)
                    .ok_or_else(|| self.arithmetic("padding position overflow"))?;
                self.slice_crc.update_zeros(n as u64);
                self.slice_md5.update(&ZEROS[..n]);
                self.in_slice = next;
                left = left
                    .checked_sub(n as u64)
                    .ok_or_else(|| self.arithmetic("padding length underflow"))?;
            }
            self.emit_slice(cancelled, emit)?;
        }
        self.checkpoint(cancelled)?;
        Ok(self.file.finish())
    }
}

#[cfg(test)]
mod tests;
