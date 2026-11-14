//! Ordered donor admission, separate from the incumbent full-scan update path.

use super::*;
use crate::hasher::FileHashes;
use crate::packet::{FileSource, PacketSource};
use crate::scanner::{FoundBlock, MAX_BUFFER, MIN_BUFFER, Window};
use std::mem::size_of;

const MAX_BLOCKS: usize = 32768;

pub(super) struct OrderedReport {
    accepted: Vec<FoundBlock>,
    file_hashes: Option<FileHashes>,
    complete: Option<usize>,
    metadata_bytes: usize,
    buffer_size: usize,
}

struct Pending {
    report: OrderedReport,
    seen: Vec<bool>,
}

impl Pending {
    fn new(blocks: usize, budget: u64, preferred_buffer: usize) -> Result<Self, RepairError> {
        if blocks > MAX_BLOCKS {
            return Err(io_ctx("planning ordered donor scan")(io::Error::new(
                io::ErrorKind::InvalidData,
                "ordered donor scan exceeds 32768 source blocks",
            )));
        }
        let minimum = blocks * (size_of::<FoundBlock>() + size_of::<bool>()) + 3 * MIN_BUFFER;
        let limit = |required: usize| RepairError::StreamingMemoryLimit {
            context: "ordered donor scan",
            required_bytes: required as u64,
            limit_bytes: budget,
        };
        if minimum as u64 > budget {
            return Err(limit(minimum));
        }
        let mut accepted = Vec::new();
        accepted
            .try_reserve_exact(blocks)
            .map_err(|e| io_ctx("reserving ordered donor entries")(io::Error::other(e)))?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(blocks)
            .map_err(|e| io_ctx("reserving ordered donor state")(io::Error::other(e)))?;
        seen.resize(blocks, false);
        let metadata_bytes =
            accepted.capacity() * size_of::<FoundBlock>() + seen.capacity() * size_of::<bool>();
        if metadata_bytes as u64 + (3 * MIN_BUFFER) as u64 > budget {
            return Err(limit(metadata_bytes + 3 * MIN_BUFFER));
        }
        let buffer_size = ((budget - metadata_bytes as u64) / 3)
            .min(preferred_buffer as u64)
            .clamp(MIN_BUFFER as u64, MAX_BUFFER as u64) as usize;
        Ok(Self {
            report: OrderedReport {
                accepted,
                file_hashes: None,
                complete: None,
                metadata_bytes,
                buffer_size,
            },
            seen,
        })
    }
}

struct Selection<'a> {
    engine: &'a Par2Repairer,
    pending: &'a [bool],
    donor_index: Option<usize>,
}
impl Selection<'_> {
    fn global(&self, block: BlockRef) -> usize {
        self.engine.files[block.file_index as usize].first_block + block.block_index as usize
    }

    fn is_set(&self, block: BlockRef) -> bool {
        let global = self.global(block);
        self.pending[global] || self.engine.locations[global].is_some()
    }

    fn same_donor(&self, block: BlockRef) -> bool {
        let global = self.global(block);
        self.pending[global]
            || self.engine.locations[global]
                .as_ref()
                .is_some_and(|location| Some(location.file) == self.donor_index)
    }

    fn length(&self, block: BlockRef) -> u64 {
        let file = &self.engine.files[block.file_index as usize];
        (file.file_length - u64::from(block.block_index) * self.engine.block_size())
            .min(self.engine.block_size())
    }

    fn entry(&self, block: BlockRef) -> &ChecksumEntry {
        &self.engine.checksums[block.file_index as usize]
            .as_ref()
            .unwrap()[block.block_index as usize]
    }

    fn terminal(&self, block: BlockRef) -> bool {
        block.block_index + 1 == self.engine.files[block.file_index as usize].block_count
    }

    fn other_match(
        &self,
        crc: u32,
        hash: [u8; 16],
        offset: u64,
        remaining: u64,
        suggested: Option<BlockRef>,
        preferred: Option<usize>,
    ) -> Option<BlockRef> {
        let index = self.engine.index.as_ref().unwrap();
        // ChecksumIndex retains Main/block insertion order within a CRC bucket.
        let candidates = || index.lookup(crc).filter(|entry| entry.md5 == hash);
        let mut matches = candidates();
        let first = matches.next()?.block;
        let admissible_length =
            |block| remaining >= self.engine.block_size() || self.length(block) == remaining;
        if matches.next().is_none() {
            if self.engine.files[first.file_index as usize]
                .complete_file
                .is_some()
                || !admissible_length(first)
            {
                return None;
            }
            if first.block_index == 0 && offset == 0 {
                return Some(first);
            }
            if Some(first) == suggested {
                return (!self.same_donor(first)).then_some(first);
            }
            return (!self.is_set(first)).then_some(first);
        }
        let unused =
            |entry: &&ChecksumEntry| !self.is_set(entry.block) && admissible_length(entry.block);
        if let Some(file) = preferred
            && let Some(entry) = candidates()
                .filter(unused)
                .find(|entry| entry.block.file_index as usize == file)
        {
            return Some(entry.block);
        }
        candidates().find(unused).map(|entry| entry.block)
    }

    fn find<S: PacketSource + ?Sized>(
        &self,
        source: &S,
        window: &mut Window<'_, S>,
        offset: u64,
        suggested: Option<BlockRef>,
        preferred: Option<usize>,
    ) -> Result<Option<BlockRef>, RepairError> {
        let slice = self.engine.block_size();
        let remaining = source.source_len() - offset;
        let cancel = Some(self.engine.cancel.as_ref());
        let cancelled = || RepairError::Cancelled;
        let read_error = || io_ctx("reading ordered donor");
        let indexed = |crc| {
            self.engine
                .index
                .as_ref()
                .unwrap()
                .lookup(crc)
                .next()
                .is_some()
        };
        let mut full = None;
        let mut suggested_hash = None;
        if let Some(block) = suggested {
            let entry = self.entry(block);
            if self.terminal(block) {
                let length = self.length(block);
                // A virtual zero must not stand in for an absent actual payload byte.
                if length <= remaining {
                    let checksums = if length == slice {
                        let result = window
                            .checksums(offset, slice, indexed, cancel)
                            .map_err(read_error())?
                            .ok_or_else(cancelled)?;
                        full = Some(result);
                        result
                    } else {
                        window
                            .padded_checksums(
                                offset,
                                length,
                                slice,
                                |crc| crc == entry.crc32,
                                cancel,
                            )
                            .map_err(read_error())?
                            .ok_or_else(cancelled)?
                    };
                    if checksums.0 == entry.crc32 {
                        suggested_hash = Some(checksums.1);
                        if checksums.1 == entry.md5 {
                            return Ok(Some(block));
                        }
                    }
                }
            } else if !self.is_set(block) {
                let checksums = window
                    .checksums(offset, slice, indexed, cancel)
                    .map_err(read_error())?
                    .ok_or_else(cancelled)?;
                full = Some(checksums);
                if checksums.0 == entry.crc32 {
                    suggested_hash = Some(checksums.1);
                    if checksums.1 == entry.md5 {
                        return Ok(Some(block));
                    }
                }
            }
        }
        let (crc, hash) = match full {
            Some(result) => result,
            None => window
                .checksums(offset, slice, indexed, cancel)
                .map_err(read_error())?
                .ok_or_else(cancelled)?,
        };
        Ok(self.other_match(
            crc,
            suggested_hash.unwrap_or(hash),
            offset,
            remaining,
            suggested,
            preferred,
        ))
    }
}

impl Par2Repairer {
    /// Scan an extra file with an explicit block-admission policy.
    ///
    /// `Full` preserves [`Self::add_extra_file`]. `OrderedPrefix` stops at the
    /// first absent or out-of-order block and can replace selected locations.
    /// Its return value counts previously missing blocks, excluding replacements.
    /// Partial prefixes have no complete-file hashes or identity. Complete copies
    /// and eligible checksum-absent fallback require full and 16 KiB MD5 hashes.
    /// Reads/errors and cancellation finish before staged locations are committed.
    /// No scan moves, removes, or overwrites a donor or target path.
    pub fn add_extra_file_with_policy(
        &mut self,
        path: &Path,
        policy: ExtraFileScanPolicy,
        observer: &mut dyn RepairObserver,
    ) -> Result<usize, RepairError> {
        if policy == ExtraFileScanPolicy::Full {
            return self.add_extra_file(path, observer);
        }
        if !self.finalized {
            return Err(RepairError::NotFinalized);
        }
        if self.scanned_extra.contains(path)
            || self
                .files
                .iter()
                .any(|file| file.target_path == path && file.status == FileStatus::Complete)
            || (self.missing_blocks() == 0
                && self
                    .files
                    .iter()
                    .all(|file| file.status == FileStatus::Complete))
        {
            return Ok(0);
        }
        observer.stage(Stage::ScanningExtra);
        observer.message(
            Level::Info,
            &format!("Scanning extra file {}", path.display()),
        );
        let source = FileSource::open(path).map_err(io_ctx("opening ordered donor"))?;
        self.add_ordered_source(path, &source, observer)
    }

    pub(super) fn scan_ordered_source<S: PacketSource + ?Sized>(
        &self,
        source: &S,
        donor_index: Option<usize>,
        progress: &mut dyn FnMut(u64),
    ) -> Result<OrderedReport, RepairError> {
        if self.cancelled() {
            return Err(RepairError::Cancelled);
        }
        let source_blocks = self.files.iter().try_fold(0u64, |sum, file| {
            sum.checked_add(file.file_length.div_ceil(self.block_size()))
        });
        if source_blocks != Some(self.locations.len() as u64)
            || source_blocks.is_none_or(|blocks| blocks > MAX_BLOCKS as u64)
        {
            return Err(io_ctx("planning ordered donor scan")(io::Error::new(
                io::ErrorKind::InvalidData,
                "ordered donor scan requires at most 32768 consistent source blocks",
            )));
        }
        let mut pending = Pending::new(
            self.locations.len(),
            self.verification_memory(),
            self.options.scan_buffer,
        )?;
        debug_assert!(
            pending.report.metadata_bytes as u64 + 3 * pending.report.buffer_size as u64
                <= self.verification_memory()
        );
        let length = source.source_len();
        let mut window = Window::new(source, pending.report.buffer_size, true);
        let mut offset = 0;
        let mut preferred = None;
        let mut suggested = None;
        let fallback = self.index.as_ref().unwrap().is_empty() || length == 0;
        if fallback
            && !self.files.iter().enumerate().any(|(fi, file)| {
                self.checksums[fi].is_none()
                    && file.complete_file.is_none()
                    && file.file_length == length
            })
        {
            return Ok(pending.report);
        }
        if !fallback {
            while offset < length {
                if self.cancelled() {
                    return Err(RepairError::Cancelled);
                }
                let selection = Selection {
                    engine: self,
                    pending: &pending.seen,
                    donor_index,
                };
                let Some(block) =
                    selection.find(source, &mut window, offset, suggested, preferred)?
                else {
                    return Ok(pending.report);
                };
                if preferred.is_none() {
                    if block.block_index != 0 {
                        return Ok(pending.report);
                    }
                    preferred = Some(block.file_index as usize);
                } else if Some(block) != suggested {
                    return Ok(pending.report);
                }
                let payload = selection.length(block);
                if payload > length - offset {
                    return Ok(pending.report);
                }
                let global = selection.global(block);
                let terminal = selection.terminal(block);
                pending.report.accepted.push(FoundBlock { offset, block });
                pending.seen[global] = true;
                offset += payload;
                progress(offset);
                suggested = (!terminal).then_some(BlockRef {
                    file_index: block.file_index,
                    block_index: block.block_index + 1,
                });
                if terminal {
                    if offset != length {
                        return Ok(pending.report);
                    }
                    break;
                }
            }
            if suggested.is_some() {
                // A donor ending before the source prefix is complete has no identity.
                return Ok(pending.report);
            }
        }
        if !window
            .hash_until(length, Some(&self.cancel))
            .map_err(io_ctx("hashing ordered donor"))?
        {
            return Err(RepairError::Cancelled);
        }
        let hashes = window.complete_hash().ok_or_else(|| {
            io_ctx("hashing ordered donor")(io::Error::other("incomplete donor hash"))
        })?;
        let identity_matches = |file: &SourceFileState| {
            file.file_length == hashes.len
                && file.hash_full == hashes.md5_full
                && file.hash_16k == hashes.md5_16k
        };
        if fallback {
            if let Some((fi, file)) = self.files.iter().enumerate().find(|(fi, file)| {
                self.checksums[*fi].is_none()
                    && file.complete_file.is_none()
                    && identity_matches(file)
            }) {
                for block_index in 0..file.block_count {
                    pending.report.accepted.push(FoundBlock {
                        offset: u64::from(block_index) * self.block_size(),
                        block: BlockRef {
                            file_index: fi as u32,
                            block_index,
                        },
                    });
                }
                pending.report.complete = Some(fi);
            }
        } else if let Some(fi) = preferred
            && identity_matches(&self.files[fi])
        {
            pending.report.complete = Some(fi);
        }
        pending.report.file_hashes = Some(hashes);
        Ok(pending.report)
    }

    fn add_ordered_source<S: PacketSource + ?Sized>(
        &mut self,
        path: &Path,
        source: &S,
        observer: &mut dyn RepairObserver,
    ) -> Result<usize, RepairError> {
        let report =
            self.scan_ordered_source(source, self.disk_index.get(path).copied(), &mut |done| {
                let total = source.source_len().max(1);
                observer.progress(
                    ((u128::from(done.min(total)) * 1000) / u128::from(total)) as u32,
                    "Scanning ordered donor",
                );
            })?;
        observer.progress(1000, "Ordered donor admission finished");
        if self.cancelled() {
            return Err(RepairError::Cancelled);
        }
        let count = self.apply_ordered(path, &report);
        self.scanned_extra.insert(path.to_path_buf());
        Ok(count)
    }

    pub(super) fn apply_ordered(&mut self, path: &Path, report: &OrderedReport) -> usize {
        if report.accepted.is_empty() && report.complete.is_none() {
            return 0;
        }
        let disk = self.disk_file_index(path);
        let mut count = 0;
        for found in &report.accepted {
            let file = &mut self.files[found.block.file_index as usize];
            let global = file.first_block + found.block.block_index as usize;
            if self.locations[global].is_none() {
                count += 1;
                file.available_blocks += 1;
            }
            self.locations[global] = Some(BlockLocation {
                file: disk,
                offset: found.offset,
            });
        }
        if let Some(fi) = report.complete {
            let file = &mut self.files[fi];
            file.complete_file = Some(path.to_path_buf());
            if file.target_path == path {
                file.status = FileStatus::Complete;
                file.target_exists = true;
            } else {
                file.status = FileStatus::Misnamed;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests;
