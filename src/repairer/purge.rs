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

    /// Remove the repair backups and the PAR2 files once every protected file is verified
    /// complete (par2cmdline `-p`). Every candidate from
    /// [`purge_candidates`](Self::purge_candidates) is reported as removed or kept:
    ///
    /// - nothing is removed unless the last [`verify`](Self::verify) hashed every target
    ///   itself and found it complete, or such a verify was followed by a
    ///   [`repair`](Self::repair) that succeeded with `verify_repaired` on. A verify that skips
    ///   files already marked complete (after streaming, quick verification or a repair
    ///   without `verify_repaired`) does not count: verify again with a new repairer;
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

#[cfg(test)]
mod tests;
