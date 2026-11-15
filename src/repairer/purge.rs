//! Verified purge (par2cmdline `-p`): once every protected file is verified complete, remove
//! the backups the repair made (such as `name.1`) and the PAR2 files of the set, reporting
//! every path as removed or kept.

use super::*;

/// Why [`Par2Repairer::purge`] kept a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PurgeKept {
    /// The set is not verified complete: verify found damage or did not hash every target
    /// itself, a repair was not re-verified, or nothing was verified.
    NotVerified,
    /// The path no longer exists.
    Missing,
    /// The path is not a regular file or symbolic link.
    NotAFile,
    /// The path is, or is another name for (same device and inode), a protected file.
    ProtectedTarget,
    /// Removing it failed.
    Failed(String),
}

/// One path considered by [`Par2Repairer::purge`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurgeEntry {
    /// The path.
    pub path: PathBuf,
    /// `None` when removed, otherwise why it was kept.
    pub kept: Option<PurgeKept>,
}

/// Outcome of [`Par2Repairer::purge`]: backups first, then PAR2 files in load order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Every candidate, in the order considered.
    pub entries: Vec<PurgeEntry>,
}

impl PurgeReport {
    /// Paths removed.
    pub fn removed(&self) -> impl Iterator<Item = &Path> + '_ {
        self.entries
            .iter()
            .filter(|e| e.kept.is_none())
            .map(|e| e.path.as_path())
    }

    /// Paths kept, with the reason.
    pub fn kept(&self) -> impl Iterator<Item = (&Path, &PurgeKept)> + '_ {
        self.entries
            .iter()
            .filter_map(|e| e.kept.as_ref().map(|k| (e.path.as_path(), k)))
    }

    /// Every candidate was removed (an empty report counts as complete).
    pub fn all_removed(&self) -> bool {
        self.entries.iter().all(|e| e.kept.is_none())
    }
}

/// Purge bookkeeping kept on the repairer.
#[derive(Clone, Debug, Default)]
pub(crate) struct PurgeState {
    /// Every target was hashed and found complete by the last verify (one that read every
    /// target itself), or by that verify plus a re-verified repair.
    pub(crate) safe: bool,
    /// The last verify hashed every target itself (see `Par2Repairer::verify`).
    pub(crate) fully_hashed: bool,
    /// Backups made by the last successful repair that were not deleted yet.
    pub(crate) backups: Vec<PathBuf>,
    /// Loaded files made solely of this set's packets (not foreign, empty or temporary).
    pub(crate) par_files: Vec<PathBuf>,
}

impl PurgeState {
    /// Forget the verdict (the files may have changed); keep the list of PAR2 files.
    pub(crate) fn reset_verdict(&mut self) {
        self.safe = false;
        self.fully_hashed = false;
        self.backups.clear();
    }
}

/// File identity used to refuse removing another name of a protected file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity(u64, u64);

#[cfg(unix)]
fn identity(meta: &std::fs::Metadata) -> Option<Identity> {
    use std::os::unix::fs::MetadataExt;
    Some(Identity(meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn identity(_meta: &std::fs::Metadata) -> Option<Identity> {
    None
}

impl Par2Repairer {
    /// Paths [`purge`](Self::purge) would consider: the backups the last repair made that were
    /// not deleted yet, then every loaded PAR2 file of this set, without duplicates. Split
    /// fragments, files of other sets (or without packets) and the temporary copies made by
    /// [`load_par2_bytes`](Self::load_par2_bytes) are never candidates.
    pub fn purge_candidates(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        for p in self
            .purge_state
            .backups
            .iter()
            .chain(self.purge_state.par_files.iter())
        {
            if !out.contains(p) {
                out.push(p.clone());
            }
        }
        out
    }

    /// Register `path` as a PAR2 file of this set that [`purge`](Self::purge) may remove,
    /// for files the repairer did not load itself (for example when the caller loaded a
    /// verified private copy of a damaged set). The file is re-read and accepted only when it
    /// looks like a PAR2 file of this set and nothing else:
    ///
    /// - its name ends in `.par2` (any case), as par2cmdline's `-p` expects;
    /// - it starts with a packet, and at least half of its bytes are packets (damaged bytes
    ///   between packets are tolerated, an archive or data file holding a copied packet is not);
    /// - every framed packet carries this set's id, whatever its type or checksum (so a packet
    ///   whose set-id field is damaged, which cannot be told from another set's, refuses it);
    /// - at least one packet of this set is valid.
    ///
    /// Returns whether it was accepted. Pass only paths believed to be PAR2 files of this set:
    /// accepting a path does not make purging safe, and the verdict and identity guards of
    /// `purge` still apply when it runs.
    ///
    /// # Errors
    /// [`RepairError::NoMainPacket`] when no set is loaded yet, or an I/O error reading `path`.
    pub fn add_purge_candidate(&mut self, path: &Path) -> Result<bool, RepairError> {
        let Some(set_id) = self.packets.set_id else {
            return Err(RepairError::NoMainPacket);
        };
        let accepted = par2_file_of_set(path, set_id)
            .map_err(io_ctx(format!("reading {}", path.display())))?;
        if accepted && !self.purge_state.par_files.iter().any(|p| p == path) {
            self.purge_state.par_files.push(path.to_path_buf());
        }
        Ok(accepted)
    }

    /// Remove the repair backups and the PAR2 files once every protected file is verified
    /// complete (par2cmdline `-p`). Every candidate from
    /// [`purge_candidates`](Self::purge_candidates) is reported as removed or kept:
    ///
    /// - nothing is removed unless the last [`verify`](Self::verify) hashed every target
    ///   itself and found it complete, or such a verify was followed by a
    ///   [`repair`](Self::repair) that succeeded with `verify_repaired` on. A verify that skips
    ///   files already marked complete (after quick verification or a repair without
    ///   `verify_repaired`), or that runs with streaming enabled, does not count: verify
    ///   again with a new repairer;
    /// - a path that is a protected file, or another name for one (a hard link, or a spelling
    ///   that resolves to it), is kept, as is anything that is not a regular file or symbolic
    ///   link (a symbolic link itself is removed, never its target).
    ///
    /// Removing PAR2 files drops the set: the verdict is cleared afterwards, so a second call
    /// keeps everything as [`PurgeKept::NotVerified`].
    pub fn purge(&mut self, observer: &mut dyn RepairObserver) -> PurgeReport {
        let candidates = self.purge_candidates();
        let mut report = PurgeReport::default();
        if !self.purge_state.safe {
            report.entries = candidates
                .into_iter()
                .map(|path| PurgeEntry {
                    path,
                    kept: Some(PurgeKept::NotVerified),
                })
                .collect();
            return report;
        }
        let mut target_ids: Vec<Identity> = Vec::new();
        for f in &self.files {
            if let Some(id) = std::fs::metadata(&f.target_path)
                .ok()
                .as_ref()
                .and_then(identity)
            {
                target_ids.push(id);
            }
        }
        let target_paths: Vec<PathBuf> = self
            .files
            .iter()
            .map(|f| {
                std::fs::canonicalize(&f.target_path).unwrap_or_else(|_| f.target_path.clone())
            })
            .collect();
        for path in candidates {
            let kept = match std::fs::symlink_metadata(&path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Some(PurgeKept::Missing),
                Err(e) => Some(PurgeKept::Failed(e.to_string())),
                Ok(meta) => {
                    let ft = meta.file_type();
                    let aliases_target = identity(&meta).is_some_and(|id| target_ids.contains(&id))
                        || (!ft.is_symlink()
                            && std::fs::canonicalize(&path)
                                .is_ok_and(|c| target_paths.contains(&c)));
                    if aliases_target {
                        Some(PurgeKept::ProtectedTarget)
                    } else if !ft.is_file() && !ft.is_symlink() {
                        Some(PurgeKept::NotAFile)
                    } else {
                        match std::fs::remove_file(&path) {
                            Ok(()) => None,
                            Err(e) => Some(PurgeKept::Failed(e.to_string())),
                        }
                    }
                }
            };
            match &kept {
                None => observer.message(Level::Info, &format!("Purged {}", path.display())),
                Some(PurgeKept::Failed(e)) => observer.message(
                    Level::Warning,
                    &format!("Could not purge {}: {e}", path.display()),
                ),
                Some(_) => {}
            }
            report.entries.push(PurgeEntry { path, kept });
        }
        self.purge_state.reset_verdict();
        report
    }
}

/// Whether `path` is a PAR2 file made of `set_id`'s packets only (see
/// [`Par2Repairer::add_purge_candidate`]).
fn par2_file_of_set(path: &Path, set_id: SetId) -> io::Result<bool> {
    let named_par2 = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("par2"));
    if !named_par2 {
        return Ok(false);
    }
    use crate::packet::PacketSource;
    let src = crate::packet::FileSource::open(path)?;
    let len = src.source_len();
    // Framing pass without checksums: every frame, valid or not, must be this set's.
    let mut frames = crate::packet::PacketIter::new(&src, ScanOptions::UNVERIFIED);
    let mut starts_with_packet = false;
    for (i, raw) in frames.by_ref().enumerate() {
        let raw = raw?;
        if i == 0 {
            starts_with_packet = raw.offset == 0;
        }
        if raw.header.set_id != set_id {
            return Ok(false);
        }
    }
    let skipped = frames.stats().skipped_bytes;
    if !starts_with_packet || skipped.saturating_mul(2) > len {
        return Ok(false);
    }
    // Checked pass: at least one valid packet of this set, none of another.
    let mut probe = PacketSet::for_set(set_id);
    let stats = probe.load_source(&src, 0, ScanOptions::METADATA)?;
    Ok(stats.foreign == 0 && stats.added + stats.duplicates > 0)
}

#[cfg(test)]
mod tests;
