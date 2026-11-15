//! Par-rename: restore original file names from PAR2 metadata (port of nzbget's `ParRenamer`).
//!
//! Usenet posts are frequently obfuscated: data files carry random names and even the `.par2`
//! files may be renamed. The renamer, per directory (destination plus sub-directories):
//!
//! 1. inspects every file's first packet header to find PAR2 files by *content*, and renames
//!    them to `<set-id>.volNNN+01.PAR2` when their names are not usable (no `.par2` extension,
//!    or files of one set carrying different base names);
//! 2. loads the main `.par2` files (and, if any were damaged, every other par2 file) to learn
//!    `(local file name, 16k hash)` pairs;
//! 3. hashes the first 16 KiB of each regular file and renames it to the described name when
//!    the hash matches, the target does not exist and the file is not a split fragment
//!    (`name.000` / `name.001`);
//! 4. reports described files that are still missing (honouring an ignore-extension list);
//! 5. renames unusable par2 files to `*.bad` when something was renamed.
//!
//! All decisions are collected as [`RenamerEvent`]s so a host can log them exactly as nzbget
//! does; a dry-run mode plans the renames without touching the file system.

use crate::filenames::{ascii_lower, find_main_pars, os_str_bytes, parse_par_filename};
use crate::hasher::file_md5_16k;
use crate::packet::{
    FileSource, HEADER_LEN, MAGIC, PacketHeader, PacketSet, PacketSource, ScanOptions, SetId, hex,
};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Host predicate deciding whether a missing described file (local name) may be ignored.
pub type IgnorePredicate = Arc<dyn Fn(&str) -> bool + Send + Sync + std::panic::RefUnwindSafe>;

/// Renamer options.
#[derive(Clone, Default)]
pub struct RenamerOptions {
    /// Report described files that are missing on disk.
    pub detect_missing: bool,
    /// Extensions (with or without leading dot, case-insensitive) of files whose absence is
    /// not an error (nzbget `ParIgnoreExt`). Unused when [`is_ignored`](Self::is_ignored) is set.
    pub ignore_extensions: Vec<String>,
    /// Plan only; do not rename anything.
    pub dry_run: bool,
    /// Host-supplied ignore rule for missing files. When set it replaces the
    /// [`ignore_extensions`](Self::ignore_extensions) suffix match, for example to apply nzbget's
    /// `MatchFileExt` wildcard semantics.
    pub is_ignored: Option<IgnorePredicate>,
}

impl std::fmt::Debug for RenamerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenamerOptions")
            .field("detect_missing", &self.detect_missing)
            .field("ignore_extensions", &self.ignore_extensions)
            .field("dry_run", &self.dry_run)
            .field("is_ignored", &self.is_ignored.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

/// Events emitted while renaming.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RenamerEvent {
    /// Informational message.
    Info(String),
    /// Warning.
    Warning(String),
    /// Error (the run continues).
    Error(String),
    /// A file was (or, in dry-run mode, would be) renamed.
    Renamed {
        /// Old path.
        from: PathBuf,
        /// New path.
        to: PathBuf,
    },
    /// Progress: `(checks done, checks total)`. Every file is checked twice (a par2 pass and a
    /// rename pass), so the total is twice the file count; it grows when a rename moves a file
    /// into a sub-directory still to be scanned. `checks done` always stays below the total.
    /// Emitted right after [`Checking`](Self::Checking) for the same file.
    Progress(usize, usize),
    /// The file about to be checked (emitted just before [`Progress`](Self::Progress)).
    Checking {
        /// Path of the file being checked (its planned name in dry-run mode).
        path: PathBuf,
    },
    /// A loaded par2 file described a file (local name) not described before in this
    /// directory; emitted once per distinct 16k hash.
    Described {
        /// Local filename from the FileDesc packet.
        name: String,
    },
}

/// Summary of a renamer run.
#[derive(Clone, Debug, Default)]
pub struct RenamerReport {
    /// Renames performed (or planned in dry-run mode).
    pub renamed: Vec<(PathBuf, PathBuf)>,
    /// Described files that are missing (local names).
    pub missing: Vec<String>,
    /// Some par2 files could not be loaded.
    pub has_damaged_par_files: bool,
    /// Some described files are missing and not ignored.
    pub has_missed_files: bool,
    /// Par2 files that were loaded successfully.
    pub loaded_par_files: Vec<PathBuf>,
    /// Par2 files that failed to load.
    pub bad_par_files: Vec<PathBuf>,
}

impl RenamerReport {
    /// Number of renames.
    pub fn renamed_count(&self) -> usize {
        self.renamed.len()
    }
}

/// `(local file name, 16k hash)` learned from a par2 set.
#[derive(Clone, Debug)]
struct FileHash {
    filename: String,
    hash16k: [u8; 16],
    exists: bool,
}

/// A file identified as PAR2 by content.
#[derive(Clone, Debug)]
struct ParInfo {
    path: PathBuf,
    set_id: String,
}

/// The renamer.
pub struct ParRenamer {
    dest_dir: PathBuf,
    options: RenamerOptions,
    file_hashes: Vec<FileHash>,
    par_infos: Vec<ParInfo>,
    bad_pars: Vec<PathBuf>,
    loaded_pars: Vec<PathBuf>,
    report: RenamerReport,
    cur_file: usize,
    file_count: usize,
    /// Directories still to be processed after the current one (scanned later).
    pending_dirs: Vec<PathBuf>,
    /// Directories already reported as unreadable (warned about once).
    unreadable_dirs: Vec<PathBuf>,
}

impl ParRenamer {
    /// New renamer for `dest_dir`.
    pub fn new(dest_dir: impl Into<PathBuf>, options: RenamerOptions) -> Self {
        Self {
            dest_dir: dest_dir.into(),
            options,
            file_hashes: Vec::new(),
            par_infos: Vec::new(),
            bad_pars: Vec::new(),
            loaded_pars: Vec::new(),
            report: RenamerReport::default(),
            cur_file: 0,
            file_count: 0,
            pending_dirs: Vec::new(),
            unreadable_dirs: Vec::new(),
        }
    }

    /// Run the renamer, cancelled through an optional flag. Port of `ParRenamer::Execute`;
    /// see [`run_with_stop`](Self::run_with_stop).
    pub fn run(
        self,
        cancel: Option<&AtomicBool>,
        events: &mut dyn FnMut(RenamerEvent),
    ) -> io::Result<RenamerReport> {
        self.run_with_stop(
            &mut || cancel.is_some_and(|c| c.load(Ordering::Relaxed)),
            events,
        )
    }

    /// Run the renamer, polling `stopped` for cancellation. Once it returns `true` the run
    /// checks no further file and starts no further loading or renaming stage. Renames
    /// already made stay; if any were made, par2 files found damaged in the directory in
    /// progress are still renamed to `*.bad` (as nzbget does), so data and par2 names stay
    /// consistent. Missing files are not reported for an interrupted directory. The report
    /// covers the work done so far, including that directory's loaded and bad par2 files.
    ///
    /// A directory that cannot be listed (the destination included: missing, no permission,
    /// removed mid-run) produces one `Warning("Could not read directory …")` and is treated
    /// as empty, so the run carries on and returns `Ok`; the `io::Result` is kept for API
    /// compatibility.
    pub fn run_with_stop(
        mut self,
        stopped: &mut dyn FnMut() -> bool,
        events: &mut dyn FnMut(RenamerEvent),
    ) -> io::Result<RenamerReport> {
        let dirs = self.build_dir_list(stopped, events);
        for (i, dir) in dirs.iter().enumerate() {
            if stopped() {
                break;
            }
            let dir = dir.clone();
            self.pending_dirs = dirs[i + 1..].to_vec();
            self.file_hashes.clear();
            self.par_infos.clear();
            self.bad_pars.clear();
            self.loaded_pars.clear();
            self.check_files(&dir, true, stopped, events);
            let mut stop = stopped();
            if !stop {
                self.rename_par_files(&dir, events);
                self.load_main_par_files(&dir, stopped, events);
                if self.report.has_damaged_par_files && !stopped() {
                    self.load_extra_par_files(&dir, stopped, events);
                }
                stop = stopped();
            }
            if !stop {
                self.check_files(&dir, false, stopped, events);
                stop = stopped();
            }
            if !stop && self.options.detect_missing {
                self.check_missing(events);
            }
            if !self.report.renamed.is_empty() && !self.bad_pars.is_empty() {
                self.rename_bad_par_files(events);
            }
            self.report.loaded_par_files.append(&mut self.loaded_pars);
            self.report.bad_par_files.append(&mut self.bad_pars);
            if stop {
                break;
            }
        }
        Ok(self.report)
    }

    /// Sorted entries of `dir`. A directory that cannot be listed (missing, no permission,
    /// removed mid-run) is treated as empty after one warning, as nzbget does, so it never
    /// aborts the run.
    fn list_dir(&mut self, dir: &Path, events: &mut dyn FnMut(RenamerEvent)) -> Vec<PathBuf> {
        match sorted_entries(dir) {
            Ok(entries) => entries,
            Err(e) => {
                if !self.unreadable_dirs.iter().any(|d| d == dir) {
                    events(RenamerEvent::Warning(format!(
                        "Could not read directory {}: {e}",
                        dir.display()
                    )));
                    self.unreadable_dirs.push(dir.to_path_buf());
                }
                Vec::new()
            }
        }
    }

    /// Destination directory and all sub-directories (recursively); also counts files.
    fn build_dir_list(
        &mut self,
        stopped: &mut dyn FnMut() -> bool,
        events: &mut dyn FnMut(RenamerEvent),
    ) -> Vec<PathBuf> {
        let mut dirs = vec![self.dest_dir.clone()];
        let mut i = 0;
        while i < dirs.len() {
            let dir = dirs[i].clone();
            i += 1;
            for entry in self.list_dir(&dir, events) {
                if stopped() {
                    return dirs;
                }
                if entry.is_dir() {
                    dirs.push(entry);
                } else {
                    // Checked twice: once in the par2 pass, once in the rename pass.
                    self.file_count += 2;
                }
            }
        }
        dirs
    }

    fn check_files(
        &mut self,
        dir: &Path,
        check_pars: bool,
        stopped: &mut dyn FnMut() -> bool,
        events: &mut dyn FnMut(RenamerEvent),
    ) {
        for path in self.list_dir(dir, events) {
            if stopped() {
                break;
            }
            if path.is_dir() {
                continue;
            }
            events(RenamerEvent::Checking {
                path: self.current_path(&path),
            });
            // Safety net for files that appeared after counting (for example created by
            // another process): never report more checks done than the total.
            self.file_count = self.file_count.max(self.cur_file + 1);
            events(RenamerEvent::Progress(self.cur_file, self.file_count));
            self.cur_file += 1;
            if check_pars {
                self.check_par_file(&path, events);
            } else {
                self.check_regular_file(dir, &path, events);
            }
        }
    }

    /// Identify par2 files by their first packet header.
    fn check_par_file(&mut self, path: &Path, events: &mut dyn FnMut(RenamerEvent)) {
        let Ok(src) = FileSource::open(path) else {
            events(RenamerEvent::Error(format!(
                "Could not open file {}",
                path.display()
            )));
            return;
        };
        if src.source_len() < HEADER_LEN as u64 {
            return;
        }
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(0, &mut hdr).is_err() {
            events(RenamerEvent::Error(format!(
                "Could not read file {}",
                path.display()
            )));
            return;
        }
        let Some(header) = PacketHeader::parse(&hdr) else {
            return;
        };
        if hdr[..8] != MAGIC || !header.fits(0, src.source_len()) {
            return;
        }
        self.par_infos.push(ParInfo {
            path: path.to_path_buf(),
            set_id: header.set_id.to_hex(),
        });
    }

    /// Whether par2 files need renaming: a par2 file without `.par2` extension, or files of
    /// one set with different base names.
    fn need_rename_par_files(&self) -> bool {
        for (i, a) in self.par_infos.iter().enumerate() {
            let name_a = file_name_bytes(&a.path);
            let ext_ok = name_a.len() >= 5
                && name_a[name_a.len() - 5..].eq_ignore_ascii_case(b".par2")
                && name_a.iter().rposition(|&b| b == b'.') == Some(name_a.len() - 5);
            if !ext_ok {
                return true;
            }
            let base_a = parse_par_filename(&name_a, true, ascii_lower).map_or(0, |p| p.base_len);
            for b in &self.par_infos[i + 1..] {
                if a.set_id != b.set_id {
                    continue;
                }
                let name_b = file_name_bytes(&b.path);
                let base_b =
                    parse_par_filename(&name_b, true, ascii_lower).map_or(0, |p| p.base_len);
                if base_a != base_b
                    || !name_a[..base_a.min(name_a.len())]
                        .eq_ignore_ascii_case(&name_b[..base_b.min(name_b.len())])
                {
                    return true;
                }
            }
        }
        false
    }

    fn rename_par_files(&mut self, dir: &Path, events: &mut dyn FnMut(RenamerEvent)) {
        if !self.need_rename_par_files() {
            return;
        }
        let infos = std::mem::take(&mut self.par_infos);
        for info in &infos {
            let mut num = 1;
            let mut dest;
            loop {
                dest = dir.join(format!("{}.vol{num:03}+01.PAR2", info.set_id));
                if !dest.exists() && !self.report.renamed.iter().any(|(_, t)| t == &dest) {
                    break;
                }
                num += 1;
            }
            self.rename_file(&info.path, &dest, events);
        }
        self.par_infos = infos;
    }

    fn load_main_par_files(
        &mut self,
        dir: &Path,
        stopped: &mut dyn FnMut() -> bool,
        events: &mut dyn FnMut(RenamerEvent),
    ) {
        let entries = self.list_dir(dir, events);
        // Use the current (possibly just renamed) names.
        let names: Vec<Vec<u8>> = entries
            .iter()
            .filter(|p| !p.is_dir())
            .map(|p| self.current_name(p))
            .collect();
        let mains: Vec<Vec<u8>> = find_main_pars(names.iter().map(std::vec::Vec::as_slice))
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        for name in mains {
            if stopped() {
                break;
            }
            let path = dir.join(bytes_to_os_string(&name));
            self.load_par_file(&path, events);
        }
    }

    fn load_extra_par_files(
        &mut self,
        dir: &Path,
        stopped: &mut dyn FnMut() -> bool,
        events: &mut dyn FnMut(RenamerEvent),
    ) {
        let entries = self.list_dir(dir, events);
        for p in entries.iter().filter(|p| !p.is_dir()) {
            if stopped() {
                break;
            }
            let path = self.current_path(p);
            let name = file_name_bytes(&path);
            if parse_par_filename(&name, true, ascii_lower).is_none() {
                continue;
            }
            if self.bad_pars.contains(&path) || self.loaded_pars.contains(&path) {
                continue;
            }
            self.load_par_file(&path, events);
        }
    }

    /// In dry-run mode files keep their old names on disk; map a path to the name it would
    /// have after the planned renames so later stages see consistent names.
    fn current_path(&self, path: &Path) -> PathBuf {
        if self.options.dry_run
            && let Some((_, to)) = self.report.renamed.iter().find(|(from, _)| from == path)
        {
            return to.clone();
        }
        path.to_path_buf()
    }

    fn current_name(&self, path: &Path) -> Vec<u8> {
        file_name_bytes(&self.current_path(path))
    }

    /// Open path on disk for a (possibly virtually renamed) path.
    fn disk_path(&self, path: &Path) -> PathBuf {
        if self.options.dry_run
            && let Some((from, _)) = self.report.renamed.iter().find(|(_, to)| to == path)
        {
            return from.clone();
        }
        path.to_path_buf()
    }

    fn load_par_file(&mut self, path: &Path, events: &mut dyn FnMut(RenamerEvent)) {
        let disk = self.disk_path(path);
        let mut set = PacketSet::new();
        // Like libpar2's LoadPacketsFromFile, a file counts as loaded when it yielded any
        // usable packet: a Main or at least one FileDesc. A read error leaves the set empty.
        let _ = set.load_file(&disk, 0, ScanOptions::METADATA);
        let loaded = (set.main.is_some() || !set.file_descs.is_empty())
            && std::fs::metadata(&disk).is_ok_and(|m| m.len() > 0);
        if !loaded {
            events(RenamerEvent::Warning(format!(
                "Could not load par2-file {}",
                path.display()
            )));
            self.report.has_damaged_par_files = true;
            self.bad_pars.push(path.to_path_buf());
            return;
        }
        self.loaded_pars.push(path.to_path_buf());
        events(RenamerEvent::Info(format!(
            "Loaded par2-file {} for par-rename",
            base_name(path)
        )));
        // Without a Main packet the file is damaged (extra par2 files get loaded), but its
        // FileDescs still name files: `file_ids_in_main_order` falls back to their ids.
        if set.main.is_none() {
            self.mark_damaged(path, events);
        }
        let ids = set.file_ids_in_main_order();
        for id in ids {
            let Some(fd) = set.file_descs.get(&id) else {
                self.mark_damaged(path, events);
                continue;
            };
            let filename = fd.local_name();
            if filename.is_empty() {
                continue;
            }
            if !self.file_hashes.iter().any(|h| h.hash16k == fd.hash_16k) {
                events(RenamerEvent::Described {
                    name: filename.clone(),
                });
                self.file_hashes.push(FileHash {
                    filename,
                    hash16k: fd.hash_16k,
                    exists: false,
                });
            }
        }
    }

    /// Flag `path` as a damaged par2 file: one warning and one bad-list entry per file, however
    /// often it is found damaged (otherwise it would be renamed to `.bad` twice).
    fn mark_damaged(&mut self, path: &Path, events: &mut dyn FnMut(RenamerEvent)) {
        if !self.bad_pars.iter().any(|p| p == path) {
            events(RenamerEvent::Warning(format!(
                "Damaged par2-file detected: {}",
                base_name(path)
            )));
            self.bad_pars.push(path.to_path_buf());
        }
        self.report.has_damaged_par_files = true;
    }

    fn check_regular_file(
        &mut self,
        dir: &Path,
        path: &Path,
        events: &mut dyn FnMut(RenamerEvent),
    ) {
        let disk = self.disk_path(path);
        let Ok(hash) = file_md5_16k(&disk) else {
            events(RenamerEvent::Error(format!(
                "Could not read file {}",
                path.display()
            )));
            return;
        };
        let Some(pos) = self.file_hashes.iter().position(|h| h.hash16k == hash) else {
            return;
        };
        self.file_hashes[pos].exists = true;
        let correct = self.file_hashes[pos].filename.clone();
        let dest = dir.join(&correct);
        let dest_exists = dest.exists()
            || (self.options.dry_run && self.report.renamed.iter().any(|(_, t)| t == &dest));
        if !dest_exists && !is_split_fragment(&file_name_bytes(path), correct.as_bytes()) {
            self.rename_file(path, &dest, events);
        }
    }

    fn check_missing(&mut self, events: &mut dyn FnMut(RenamerEvent)) {
        for h in &self.file_hashes {
            if h.exists {
                continue;
            }
            let ignored = match &self.options.is_ignored {
                Some(pred) => pred(&h.filename),
                None => matches_ignored_extension(&h.filename, &self.options.ignore_extensions),
            };
            if ignored {
                events(RenamerEvent::Info(format!(
                    "File {} is missing, ignoring",
                    h.filename
                )));
            } else {
                events(RenamerEvent::Info(format!(
                    "File {} is missing",
                    h.filename
                )));
                self.report.has_missed_files = true;
            }
            self.report.missing.push(h.filename.clone());
        }
    }

    fn rename_bad_par_files(&mut self, events: &mut dyn FnMut(RenamerEvent)) {
        let bad = self.bad_pars.clone();
        for p in bad {
            let mut dest = p.clone().into_os_string();
            dest.push(".bad");
            self.rename_file(&p, &PathBuf::from(dest), events);
        }
    }

    fn rename_file(&mut self, from: &Path, to: &Path, events: &mut dyn FnMut(RenamerEvent)) {
        events(RenamerEvent::Info(format!(
            "Renaming {} to {}",
            base_name(from),
            base_name(to)
        )));
        if !self.options.dry_run {
            if let Some(parent) = to.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                events(RenamerEvent::Error(format!(
                    "Failed to rename file {} to {}. Could not create the target directory \"{}\": {e}",
                    base_name(from),
                    base_name(to),
                    parent.display()
                )));
                return;
            }
            if let Err(e) = std::fs::rename(from, to) {
                events(RenamerEvent::Error(format!(
                    "Failed to rename file {} to {}: {e}",
                    from.display(),
                    to.display()
                )));
                return;
            }
        }
        // A FileDesc name with a '/' can move a file into a sub-directory that is scanned
        // later; it is then checked twice more, so count it into the progress total.
        if !self.options.dry_run
            && to
                .parent()
                .is_some_and(|parent| self.pending_dirs.iter().any(|d| d == parent))
        {
            self.file_count += 2;
        }
        self.report
            .renamed
            .push((from.to_path_buf(), to.to_path_buf()));
        events(RenamerEvent::Renamed {
            from: from.to_path_buf(),
            to: to.to_path_buf(),
        });
    }
}

/// Name for a par2 file that must be renamed to its set id, as nzbget's `DirectRenamer::par_name`
/// does: when `old_name` already carries a `.vol…par2` suffix (case-insensitive) and
/// `<set_id><suffix>` does not exist yet, the suffix is kept; otherwise the first free
/// `<set_id>.volNNN+01.PAR2` (`NNN` from `001`) is used. `exists` answers whether a candidate
/// name is already taken.
pub fn direct_par_name(set_id_hex: &str, old_name: &[u8], exists: &dyn Fn(&str) -> bool) -> String {
    let lower: Vec<u8> = old_name.iter().map(u8::to_ascii_lowercase).collect();
    if lower.ends_with(b".par2")
        && let Some(pos) = memchr::memmem::rfind(&lower, b".vol")
    {
        let suffix = String::from_utf8_lossy(&old_name[pos..]).into_owned();
        let candidate = format!("{set_id_hex}{suffix}");
        if !exists(&candidate) {
            return candidate;
        }
    }
    let mut n = 1u32;
    loop {
        let candidate = format!("{set_id_hex}.vol{n:03}+01.PAR2");
        if !exists(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// `name.000` / `name.001` style fragment of `correct_name`? Port of
/// `ParRenamer::IsSplittedFragment`: same base, a purely numeric extension whose value is 0 or 1.
pub fn is_split_fragment(filename: &[u8], correct_name: &[u8]) -> bool {
    let base = correct_name.len();
    if filename.len() <= base
        || !filename[..base].eq_ignore_ascii_case(correct_name)
        || !filename.contains(&b'.')
    {
        return false;
    }
    let rest = &filename[base..];
    if rest.first() != Some(&b'.') {
        return false;
    }
    let digits = &rest[1..];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    crate::filenames::atoi(digits) <= 1
}

/// Port of `ParChecker::MaybeSplittedFragement`: `filename1` looks like a split fragment of
/// `filename2`—either `filename2` plus a numeric extension, or both share a stem and have
/// three-digit numeric extensions.
pub fn maybe_split_fragment(filename1: &[u8], filename2: &[u8]) -> bool {
    let len = filename2.len();
    if filename1.len() > len && filename1[..len].eq_ignore_ascii_case(filename2) {
        let rest = &filename1[len..];
        if rest[0] == b'.' && rest.len() > 1 && rest[1..].iter().all(u8::is_ascii_digit) {
            return true;
        }
    }
    let ext = |f: &[u8]| f.iter().rposition(|&b| b == b'.');
    if let (Some(e1), Some(e2)) = (ext(filename1), ext(filename2)) {
        let x1 = &filename1[e1..];
        let x2 = &filename2[e2..];
        if x1.len() == 4
            && x2.len() == 4
            && e1 == e2
            && filename1[..e1].eq_ignore_ascii_case(&filename2[..e2])
        {
            return x1[1..].iter().all(u8::is_ascii_digit)
                && x2[1..].iter().all(u8::is_ascii_digit);
        }
    }
    false
}

/// Whether `filename` ends with one of `exts` (`,`/`;` separated lists are accepted too,
/// entries may carry a leading dot; comparison is case-insensitive).
pub fn matches_ignored_extension(filename: &str, exts: &[String]) -> bool {
    let lower = filename.to_ascii_lowercase();
    exts.iter()
        .flat_map(|e| e.split([',', ';']))
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .any(|e| {
            let e = e.to_ascii_lowercase();
            let e = if e.starts_with('.') {
                e
            } else {
                format!(".{e}")
            };
            lower.ends_with(&e)
        })
}

fn sorted_entries(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    v.sort();
    Ok(v)
}

fn file_name_bytes(path: &Path) -> Vec<u8> {
    path.file_name().map_or_default(os_str_bytes)
}

fn base_name(path: &Path) -> String {
    path.file_name()
        .map_or_default(|n| n.to_string_lossy().into_owned())
}

fn bytes_to_os_string(b: &[u8]) -> std::ffi::OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(b.to_vec())
    }
    #[cfg(not(unix))]
    {
        std::ffi::OsString::from(String::from_utf8_lossy(b).into_owned())
    }
}

/// Lower-case hex set id as used in generated par2 names.
pub fn set_id_name(set_id: &SetId) -> String {
    hex(&set_id.0)
}

/// Collect the distinct set ids of par2 files in a directory (by content).
pub fn par2_set_ids_in_dir(dir: &Path) -> io::Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for p in sorted_entries(dir)? {
        if p.is_dir() {
            continue;
        }
        let Ok(src) = FileSource::open(&p) else {
            continue;
        };
        if src.source_len() < HEADER_LEN as u64 {
            continue;
        }
        let mut hdr = [0u8; HEADER_LEN];
        if src.read_at(0, &mut hdr).is_ok()
            && let Some(h) = PacketHeader::parse(&hdr)
            && h.fits(0, src.source_len())
        {
            out.insert(h.set_id.to_hex());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::create_in_memory;
    use crate::gf16::simd::Kernel;

    fn rnd(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 31) as u8
            })
            .collect()
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("par-rs-renamer-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Split a single-buffer set into an index (critical packets) and one volume per recovery packet.
    fn split_set(bytes: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let raws: Vec<_> = crate::packet::PacketIter::new(bytes, ScanOptions::UNVERIFIED)
            .map(|r| r.unwrap())
            .collect();
        let mut index = Vec::new();
        let mut vols = Vec::new();
        for r in raws {
            let s = r.offset as usize;
            let e = s + r.header.length as usize;
            if r.header.kind() == crate::packet::PacketType::RecoverySlice {
                let mut v = bytes[s..e].to_vec();
                v.extend_from_slice(&index); // volumes carry the critical packets too
                vols.push(v);
            } else {
                index.extend_from_slice(&bytes[s..e]);
            }
        }
        (index, vols)
    }

    #[test]
    fn split_fragment_and_extension_helpers() {
        assert!(is_split_fragment(b"movie.mkv.001", b"movie.mkv"));
        assert!(is_split_fragment(b"MOVIE.MKV.000", b"movie.mkv"));
        assert!(!is_split_fragment(b"movie.mkv.002", b"movie.mkv"));
        assert!(!is_split_fragment(b"movie.mkv", b"movie.mkv"));
        assert!(!is_split_fragment(b"movie.mkvx001", b"movie.mkv"));
        assert!(!is_split_fragment(b"movie.mkv.0a1", b"movie.mkv"));
        assert!(!is_split_fragment(b"other.mkv.001", b"movie.mkv"));
        assert!(!is_split_fragment(b"movie.mkv.", b"movie.mkv"));

        assert!(maybe_split_fragment(b"file.bin.007", b"file.bin"));
        assert!(maybe_split_fragment(b"file.001", b"file.000"));
        assert!(maybe_split_fragment(b"FILE.001", b"file.000"));
        assert!(!maybe_split_fragment(b"file.0001", b"file.000"));
        assert!(!maybe_split_fragment(b"file.bin", b"file.bin"));
        assert!(!maybe_split_fragment(b"other.001", b"file.000"));
        assert!(!maybe_split_fragment(b"file.00x", b"file.000"));
        assert!(!maybe_split_fragment(b"file", b"other"));

        assert!(matches_ignored_extension("a.nfo", &["nfo".into()]));
        assert!(matches_ignored_extension("a.NFO", &[".nfo,.sfv".into()]));
        assert!(matches_ignored_extension("a.sfv", &["nfo;sfv".into()]));
        assert!(!matches_ignored_extension("a.mkv", &["nfo".into()]));
        assert!(!matches_ignored_extension("a.mkv", &[]));
        assert!(!matches_ignored_extension("a.mkv", &["".into()]));
        assert_eq!(set_id_name(&SetId([0xAB; 16])), "ab".repeat(16));
    }

    #[test]
    fn renames_obfuscated_data_and_par_files() {
        let dir = tmpdir("obf");
        let a = rnd(40_000, 1);
        let b = rnd(20_000, 2);
        let c = rnd(500, 3);
        let (bytes, set_id) = create_in_memory(
            &[(b"movie.mkv", &a), (b"sample.mkv", &b), (b"readme.nfo", &c)],
            4096,
            &[0, 1],
            Kernel::detect(),
        )
        .unwrap();
        let (index, vols) = split_set(&bytes);
        // Obfuscated data files; readme missing; par2 files obfuscated too.
        std::fs::write(dir.join("x1y2z3"), &a).unwrap();
        std::fs::write(dir.join("q9w8e7"), &b).unwrap();
        std::fs::write(dir.join("abc.par2"), &index).unwrap();
        std::fs::write(dir.join("zzz.dat"), &vols[0]).unwrap();
        std::fs::write(dir.join("other.par2"), &vols[1]).unwrap();
        std::fs::write(dir.join("unrelated.txt"), b"hello").unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("x"), b"x").unwrap();

        let opts = RenamerOptions {
            detect_missing: true,
            ignore_extensions: vec!["nfo".into()],
            dry_run: false,
            is_ignored: None,
        };
        let mut events = Vec::new();
        let rep = ParRenamer::new(&dir, opts)
            .run(None, &mut |e| events.push(e))
            .unwrap();
        // All three par2 files have the same set id but different base names → renamed to <setid>.volNNN+01.PAR2.
        let sid = set_id.to_hex();
        for n in 1..=3 {
            assert!(
                dir.join(format!("{sid}.vol{n:03}+01.PAR2")).exists(),
                "volume {n}"
            );
        }
        assert!(dir.join("movie.mkv").exists());
        assert!(dir.join("sample.mkv").exists());
        assert!(dir.join("unrelated.txt").exists());
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), a);
        assert_eq!(rep.renamed_count(), 3 + 2);
        assert!(!rep.has_damaged_par_files);
        // readme.nfo is missing but ignored.
        assert_eq!(rep.missing, vec!["readme.nfo".to_string()]);
        assert!(!rep.has_missed_files);
        assert_eq!(rep.loaded_par_files.len(), 1);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RenamerEvent::Info(m) if m.contains("is missing, ignoring")))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RenamerEvent::Progress(_, _)))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RenamerEvent::Renamed { .. }))
        );

        // Second run: nothing left to do.
        let rep2 = ParRenamer::new(
            &dir,
            RenamerOptions {
                detect_missing: true,
                ..Default::default()
            },
        )
        .run(None, &mut |_| {})
        .unwrap();
        assert_eq!(rep2.renamed_count(), 0);
        assert!(rep2.has_missed_files);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dry_run_plans_without_touching_disk() {
        let dir = tmpdir("dry");
        let a = rnd(10_000, 5);
        let (bytes, _) =
            create_in_memory(&[(b"data.bin", &a)], 1024, &[0], Kernel::detect()).unwrap();
        let (index, vols) = split_set(&bytes);
        std::fs::write(dir.join("set.par2"), &index).unwrap();
        std::fs::write(dir.join("set.vol00+01.par2"), &vols[0]).unwrap();
        std::fs::write(dir.join("garbled"), &a).unwrap();
        let mut checking = Vec::new();
        let rep = ParRenamer::new(
            &dir,
            RenamerOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .run(None, &mut |e| {
            if let RenamerEvent::Checking { path } = e {
                checking.push(path);
            }
        })
        .unwrap();
        // The data file is checked under its disk name in both passes (its rename is
        // planned during the second check).
        assert_eq!(
            checking
                .iter()
                .filter(|p| *p == &dir.join("garbled"))
                .count(),
            2
        );
        assert_eq!(
            rep.renamed,
            vec![(dir.join("garbled"), dir.join("data.bin"))]
        );
        assert!(dir.join("garbled").exists());
        assert!(!dir.join("data.bin").exists());
        // Real run.
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run(None, &mut |_| {})
            .unwrap();
        assert_eq!(rep.renamed_count(), 1);
        assert!(dir.join("data.bin").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn split_fragments_are_not_renamed_and_existing_targets_are_kept() {
        let dir = tmpdir("frag");
        let a = rnd(30_000, 6);
        let (bytes, _) =
            create_in_memory(&[(b"big.bin", &a)], 4096, &[], Kernel::detect()).unwrap();
        std::fs::write(dir.join("big.par2"), &bytes).unwrap();
        // Fragment .001 starts with the same first 16 KiB → same 16k hash; must not be renamed.
        std::fs::write(dir.join("big.bin.001"), &a[..20_000]).unwrap();
        let rep = ParRenamer::new(
            &dir,
            RenamerOptions {
                detect_missing: true,
                ..Default::default()
            },
        )
        .run(None, &mut |_| {})
        .unwrap();
        assert_eq!(rep.renamed_count(), 0);
        assert!(dir.join("big.bin.001").exists());
        // File "exists" (hash matched) → not reported missing.
        assert!(rep.missing.is_empty());

        // Existing correct file: a second copy under a bogus name stays.
        std::fs::write(dir.join("big.bin"), &a).unwrap();
        std::fs::write(dir.join("copy.tmp"), &a).unwrap();
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run(None, &mut |_| {})
            .unwrap();
        assert_eq!(rep.renamed_count(), 0);
        assert!(dir.join("copy.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_par_files_fall_back_to_extra_pars_and_get_marked_bad() {
        let dir = tmpdir("bad");
        let a = rnd(12_000, 7);
        let (bytes, _) =
            create_in_memory(&[(b"good.bin", &a)], 1024, &[0], Kernel::detect()).unwrap();
        let (index, vols) = split_set(&bytes);
        // The main par2 file contains only truncated garbage. The volume remains intact and loadable.
        std::fs::write(dir.join("set.par2"), &index[..40]).unwrap();
        std::fs::write(dir.join("set.vol00+01.par2"), &vols[0]).unwrap();
        std::fs::write(dir.join("renamed_data"), &a).unwrap();
        let mut events = Vec::new();
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run(None, &mut |e| events.push(e))
            .unwrap();
        assert!(rep.has_damaged_par_files);
        assert_eq!(rep.renamed_count(), 2); // data file + bad par2 → .bad
        assert!(dir.join("good.bin").exists());
        assert!(dir.join("set.par2.bad").exists());
        assert_eq!(rep.bad_par_files, vec![dir.join("set.par2")]);
        assert_eq!(rep.loaded_par_files, vec![dir.join("set.vol00+01.par2")]);
        assert!(events.iter().any(
            |e| matches!(e, RenamerEvent::Warning(m) if m.contains("Could not load par2-file"))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn subdirectories_cancellation_and_set_ids() {
        let dir = tmpdir("sub");
        let a = rnd(5000, 8);
        let (bytes, set_id) =
            create_in_memory(&[(b"f.bin", &a)], 1024, &[0], Kernel::detect()).unwrap();
        let sub = dir.join("inner");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("f.par2"), &bytes).unwrap();
        std::fs::write(sub.join("blob"), &a).unwrap();
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run(None, &mut |_| {})
            .unwrap();
        assert_eq!(rep.renamed, vec![(sub.join("blob"), sub.join("f.bin"))]);
        let ids = par2_set_ids_in_dir(&sub).unwrap();
        assert_eq!(ids.into_iter().collect::<Vec<_>>(), vec![set_id.to_hex()]);
        assert!(par2_set_ids_in_dir(&dir).unwrap().is_empty());
        // Cancelled run does nothing.
        std::fs::write(sub.join("blob2"), &a).unwrap();
        let cancel = AtomicBool::new(true);
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run(Some(&cancel), &mut |_| {})
            .unwrap();
        assert_eq!(rep.renamed_count(), 0);
        // Missing directory: one warning, empty report.
        let mut events = Vec::new();
        let rep = ParRenamer::new(dir.join("nope"), RenamerOptions::default())
            .run(None, &mut |e| events.push(e))
            .unwrap();
        assert_eq!(rep.renamed_count(), 0);
        assert!(rep.missing.is_empty() && rep.loaded_par_files.is_empty());
        assert!(!rep.has_damaged_par_files && !rep.has_missed_files);
        assert_eq!(
            events,
            vec![RenamerEvent::Warning(format!(
                "Could not read directory {}: {}",
                dir.join("nope").display(),
                std::fs::read_dir(dir.join("nope")).unwrap_err()
            ))]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Main par2 file whose Main packet lists file ids without a FileDesc packet.
    fn index_without_descs(bytes: &[u8], drop: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut dropped = 0;
        for r in crate::packet::PacketIter::new(bytes, ScanOptions::UNVERIFIED).map(|r| r.unwrap())
        {
            let s = r.offset as usize;
            let e = s + r.header.length as usize;
            match r.header.kind() {
                crate::packet::PacketType::RecoverySlice => continue,
                crate::packet::PacketType::FileDesc if dropped < drop => dropped += 1,
                _ => out.extend_from_slice(&bytes[s..e]),
            }
        }
        assert_eq!(dropped, drop);
        out
    }

    #[test]
    fn par_missing_several_descs_is_marked_bad_once() {
        let dir = tmpdir("multidesc");
        let a = rnd(9_000, 11);
        let b = rnd(7_000, 12);
        let c = rnd(5_000, 13);
        let (bytes, _) = create_in_memory(
            &[(b"a.bin", &a), (b"b.bin", &b), (b"c.bin", &c)],
            1024,
            &[0],
            Kernel::detect(),
        )
        .unwrap();
        let (_, vols) = split_set(&bytes);
        std::fs::write(dir.join("set.par2"), index_without_descs(&bytes, 2)).unwrap();
        std::fs::write(dir.join("set.vol00+01.par2"), &vols[0]).unwrap();
        std::fs::write(dir.join("o1"), &a).unwrap();
        std::fs::write(dir.join("o2"), &b).unwrap();
        std::fs::write(dir.join("o3"), &c).unwrap();
        let mut events = Vec::new();
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run(None, &mut |e| events.push(e))
            .unwrap();
        let damaged = events
            .iter()
            .filter(|e| matches!(e, RenamerEvent::Warning(m) if m.contains("Damaged par2-file detected")))
            .count();
        assert_eq!(damaged, 1, "{events:?}");
        assert!(
            !events.iter().any(|e| matches!(e, RenamerEvent::Error(_))),
            "{events:?}"
        );
        let bad_renames = rep
            .renamed
            .iter()
            .filter(|(_, to)| to.to_string_lossy().ends_with(".bad"))
            .count();
        assert_eq!(bad_renames, 1);
        assert!(rep.has_damaged_par_files);
        assert_eq!(rep.bad_par_files, vec![dir.join("set.par2")]);
        assert!(dir.join("set.par2.bad").exists());
        for n in ["a.bin", "b.bin", "c.bin"] {
            assert!(dir.join(n).exists(), "{n}");
        }
        // Main described one file, the extra volume the same file again plus two new ones:
        // one Described per distinct 16k hash, the repeat suppressed.
        let mut described: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RenamerEvent::Described { name } => Some(name.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(described.len(), 3, "{described:?}");
        described.sort();
        assert_eq!(described, ["a.bin", "b.bin", "c.bin"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn described_fires_once_per_distinct_hash16k() {
        let dir = tmpdir("described");
        let same = rnd(20_000, 21);
        let other = rnd(20_000, 22);
        let (bytes, _) = create_in_memory(
            &[
                (b"one.bin", &same),
                (b"two.bin", &same),
                (b"three.bin", &other),
            ],
            4096,
            &[],
            Kernel::detect(),
        )
        .unwrap();
        std::fs::write(dir.join("set.par2"), &bytes).unwrap();
        let mut described = Vec::new();
        let mut checking = Vec::new();
        let mut progress = Vec::new();
        ParRenamer::new(&dir, RenamerOptions::default())
            .run(None, &mut |e| match e {
                RenamerEvent::Described { name } => described.push(name),
                RenamerEvent::Checking { path } => checking.push(path),
                RenamerEvent::Progress(cur, total) => progress.push((cur, total)),
                _ => {}
            })
            .unwrap();
        // One file, checked in both passes: progress runs 0/2, 1/2 and never past the total.
        assert_eq!(progress, [(0, 2), (1, 2)]);
        let progress = progress.len();
        assert_eq!(described.len(), 2, "{described:?}");
        assert!(described.contains(&"three.bin".to_string()));
        // One Checking event (with the path) per Progress event.
        assert_eq!(checking.len(), progress);
        assert!(checking.iter().all(|p| p == &dir.join("set.par2")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stop_callback_stops_after_first_file() {
        let dir = tmpdir("stopcb");
        let a = rnd(6_000, 31);
        let b = rnd(6_000, 32);
        let (bytes, _) = create_in_memory(
            &[(b"a.bin", &a), (b"b.bin", &b)],
            1024,
            &[],
            Kernel::detect(),
        )
        .unwrap();
        std::fs::write(dir.join("0set.par2"), &bytes).unwrap();
        std::fs::write(dir.join("x1"), &a).unwrap();
        std::fs::write(dir.join("x2"), &b).unwrap();
        let checked = std::cell::Cell::new(0usize);
        let mut events = Vec::new();
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run_with_stop(&mut || checked.get() >= 1, &mut |e| {
                if matches!(e, RenamerEvent::Progress(..)) {
                    checked.set(checked.get() + 1);
                }
                events.push(e);
            })
            .unwrap();
        assert_eq!(checked.get(), 1, "{events:?}");
        assert_eq!(rep.renamed_count(), 0);
        assert!(dir.join("x1").exists() && dir.join("x2").exists());
        // Without the stop the same directory is renamed.
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run_with_stop(&mut || false, &mut |_| {})
            .unwrap();
        assert_eq!(rep.renamed_count(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn host_ignore_predicate_replaces_extension_list() {
        let dir = tmpdir("ignorepred");
        let a = rnd(3_000, 41);
        let b = rnd(3_000, 42);
        let (bytes, _) = create_in_memory(
            &[(b"readme.nfo", &a), (b"sample-x.mkv", &b)],
            1024,
            &[],
            Kernel::detect(),
        )
        .unwrap();
        std::fs::write(dir.join("set.par2"), &bytes).unwrap();
        let opts = RenamerOptions {
            detect_missing: true,
            ignore_extensions: vec!["nfo".into()],
            is_ignored: Some(Arc::new(|n: &str| n.starts_with("sample"))),
            ..Default::default()
        };
        let mut events = Vec::new();
        let rep = ParRenamer::new(&dir, opts)
            .run(None, &mut |e| events.push(e))
            .unwrap();
        assert!(rep.has_missed_files); // readme.nfo no longer ignored
        assert!(events.contains(&RenamerEvent::Info(
            "File sample-x.mkv is missing, ignoring".into()
        )));
        assert!(events.contains(&RenamerEvent::Info("File readme.nfo is missing".into())));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stop_during_rename_pass_keeps_bookkeeping_and_marks_bad() {
        let dir = tmpdir("stopmid");
        let a = rnd(9_000, 51);
        let b = rnd(7_000, 52);
        let c = rnd(5_000, 53);
        let (bytes, _) = create_in_memory(
            &[(b"a.bin", &a), (b"b.bin", &b), (b"c.bin", &c)],
            1024,
            &[0],
            Kernel::detect(),
        )
        .unwrap();
        let (_, vols) = split_set(&bytes);
        std::fs::write(dir.join("set.par2"), index_without_descs(&bytes, 2)).unwrap();
        std::fs::write(dir.join("set.vol00+01.par2"), &vols[0]).unwrap();
        std::fs::write(dir.join("o1"), &a).unwrap();
        std::fs::write(dir.join("o2"), &b).unwrap();
        std::fs::write(dir.join("o3"), &c).unwrap();
        let renamed = std::cell::Cell::new(false);
        let mut events = Vec::new();
        let rep = ParRenamer::new(
            &dir,
            RenamerOptions {
                detect_missing: true,
                ..Default::default()
            },
        )
        .run_with_stop(&mut || renamed.get(), &mut |e| {
            if matches!(e, RenamerEvent::Renamed { .. }) {
                renamed.set(true);
            }
            events.push(e);
        })
        .unwrap();
        // Stopped after o1 → a.bin; o2/o3 untouched, damaged main still marked bad.
        assert_eq!(
            rep.renamed,
            vec![
                (dir.join("o1"), dir.join("a.bin")),
                (dir.join("set.par2"), dir.join("set.par2.bad")),
            ],
            "{events:?}"
        );
        assert!(dir.join("o2").exists() && dir.join("o3").exists());
        assert_eq!(rep.bad_par_files, vec![dir.join("set.par2")]);
        assert_eq!(
            rep.loaded_par_files,
            vec![dir.join("set.par2"), dir.join("set.vol00+01.par2")]
        );
        // Unchecked files are not reported missing.
        assert!(rep.missing.is_empty());
        assert!(!rep.has_missed_files);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dry_run_checking_reports_planned_par_names() {
        let dir = tmpdir("drypar");
        let a = rnd(4_000, 61);
        let (bytes, set_id) =
            create_in_memory(&[(b"d.bin", &a)], 1024, &[], Kernel::detect()).unwrap();
        // A par2 file without a .par2 extension gets renamed to its set id in pass 1.
        std::fs::write(dir.join("idx.dat"), &bytes).unwrap();
        let mut checking = Vec::new();
        let rep = ParRenamer::new(
            &dir,
            RenamerOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .run(None, &mut |e| {
            if let RenamerEvent::Checking { path } = e {
                checking.push(path);
            }
        })
        .unwrap();
        let planned = dir.join(format!("{}.vol001+01.PAR2", set_id.to_hex()));
        assert_eq!(rep.renamed, vec![(dir.join("idx.dat"), planned.clone())]);
        assert_eq!(checking, vec![dir.join("idx.dat"), planned]);
        assert!(dir.join("idx.dat").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn progress_stays_within_total_when_renaming_into_pending_subdir() {
        let dir = tmpdir("subprog");
        let a = rnd(8_000, 71);
        let (bytes, _) =
            create_in_memory(&[(b"sub/a.bin", &a)], 1024, &[], Kernel::detect()).unwrap();
        std::fs::write(dir.join("set.par2"), &bytes).unwrap();
        std::fs::write(dir.join("obf"), &a).unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("keep.txt"), b"k").unwrap();
        let mut progress = Vec::new();
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run(None, &mut |e| {
                if let RenamerEvent::Progress(cur, total) = e {
                    progress.push((cur, total));
                }
            })
            .unwrap();
        assert_eq!(rep.renamed, vec![(dir.join("obf"), dir.join("sub/a.bin"))]);
        // 3 files counted up front (6 checks); the moved file is checked twice more in sub/.
        assert_eq!(progress.len(), 8, "{progress:?}");
        assert!(
            progress.iter().all(|&(cur, total)| cur < total),
            "{progress:?}"
        );
        // The total is raised when the file moves, not clamped up one check at a time.
        assert_eq!(&progress[6..], &[(6, 8), (7, 8)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_subdirectory_does_not_abort_run() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("unreadable");
        let locked = dir.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::write(locked.join("inside"), b"x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            // Running as root: permissions are not enforced, nothing to test.
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
            return;
        }
        let a = rnd(6_000, 81);
        let (bytes, _) =
            create_in_memory(&[(b"real.bin", &a)], 1024, &[], Kernel::detect()).unwrap();
        std::fs::write(dir.join("set.par2"), &bytes).unwrap();
        std::fs::write(dir.join("obf"), &a).unwrap();
        let mut events = Vec::new();
        let rep = ParRenamer::new(
            &dir,
            RenamerOptions {
                detect_missing: true,
                ..Default::default()
            },
        )
        .run(None, &mut |e| events.push(e));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rep = rep.unwrap();
        assert_eq!(rep.renamed, vec![(dir.join("obf"), dir.join("real.bin"))]);
        assert!(!rep.has_missed_files);
        let warnings: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, RenamerEvent::Warning(m) if m.starts_with("Could not read directory")))
            .collect();
        assert_eq!(warnings.len(), 1, "{events:?}");
        assert!(
            matches!(warnings[0], RenamerEvent::Warning(m) if m.contains(&locked.display().to_string()))
        );
        assert!(!events.iter().any(|e| matches!(e, RenamerEvent::Error(_))));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn index_without_main_still_names_files_and_reports_damage() {
        let dir = tmpdir("nomain");
        let a = rnd(9_000, 91);
        let b = rnd(4_000, 92);
        let (bytes, _) = create_in_memory(
            &[(b"first.bin", &a), (b"second.bin", &b)],
            1024,
            &[0],
            Kernel::detect(),
        )
        .unwrap();
        // Index with every critical packet, its Main corrupted (packet hash no longer matches).
        let mut index = Vec::new();
        for r in crate::packet::PacketIter::new(&bytes, ScanOptions::UNVERIFIED).map(|r| r.unwrap())
        {
            let s = r.offset as usize;
            let e = s + r.header.length as usize;
            match r.header.kind() {
                crate::packet::PacketType::RecoverySlice => {}
                crate::packet::PacketType::Main => {
                    let mut p = bytes[s..e].to_vec();
                    let last = p.len() - 1;
                    p[last] ^= 0xFF;
                    index.extend_from_slice(&p);
                }
                _ => index.extend_from_slice(&bytes[s..e]),
            }
        }
        std::fs::write(dir.join("set.par2"), &index).unwrap();
        std::fs::write(dir.join("obf1"), &a).unwrap();
        std::fs::write(dir.join("obf2"), &b).unwrap();
        let mut events = Vec::new();
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run(None, &mut |e| events.push(e))
            .unwrap();
        assert!(dir.join("first.bin").exists() && dir.join("second.bin").exists());
        assert!(rep.has_damaged_par_files);
        assert_eq!(rep.loaded_par_files, vec![dir.join("set.par2")]);
        assert_eq!(rep.bad_par_files, vec![dir.join("set.par2")]);
        // Renames happened, so the Main-less index is marked bad, once.
        assert!(dir.join("set.par2.bad").exists());
        let damaged = events
            .iter()
            .filter(|e| matches!(e, RenamerEvent::Warning(m) if m.contains("Damaged par2-file detected")))
            .count();
        assert_eq!(damaged, 1, "{events:?}");
        let mut described: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RenamerEvent::Described { name } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        described.sort();
        assert_eq!(described, ["first.bin", "second.bin"]);
        assert!(!events.iter().any(|e| matches!(e, RenamerEvent::Error(_))));
        assert!(!events.iter().any(
            |e| matches!(e, RenamerEvent::Warning(m) if m.contains("Could not load par2-file"))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn par_file_without_main_or_descs_is_not_loaded() {
        let dir = tmpdir("nodescs");
        let a = rnd(3_000, 93);
        let (bytes, _) = create_in_memory(&[(b"x.bin", &a)], 1024, &[0], Kernel::detect()).unwrap();
        // Only recovery and IFSC/creator packets: nothing to learn names from.
        let mut only = Vec::new();
        for r in crate::packet::PacketIter::new(&bytes, ScanOptions::UNVERIFIED).map(|r| r.unwrap())
        {
            let s = r.offset as usize;
            let e = s + r.header.length as usize;
            if !matches!(
                r.header.kind(),
                crate::packet::PacketType::Main | crate::packet::PacketType::FileDesc
            ) {
                only.extend_from_slice(&bytes[s..e]);
            }
        }
        std::fs::write(dir.join("set.par2"), &only).unwrap();
        std::fs::write(dir.join("obf"), &a).unwrap();
        let mut events = Vec::new();
        let rep = ParRenamer::new(&dir, RenamerOptions::default())
            .run(None, &mut |e| events.push(e))
            .unwrap();
        assert_eq!(rep.renamed_count(), 0);
        assert!(rep.has_damaged_par_files);
        assert!(rep.loaded_par_files.is_empty());
        assert_eq!(rep.bad_par_files, vec![dir.join("set.par2")]);
        assert!(events.iter().any(
            |e| matches!(e, RenamerEvent::Warning(m) if m.contains("Could not load par2-file"))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
