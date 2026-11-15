use super::*;
use crate::create::{SetOptions, build_set};

struct Fx {
    dir: PathBuf,
    a: Vec<u8>,
    b: Vec<u8>,
}

impl Fx {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("par-rs-purge-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + 3) as u8).collect();
        let b: Vec<u8> = (0..9_000u32).map(|i| (i * 13 + 1) as u8).collect();
        build_set(
            "set",
            &[("a.bin", &a), ("b.bin", &b)],
            &SetOptions {
                slice_size: 1024,
                recovery_blocks: 8,
                ..Default::default()
            },
        )
        .unwrap()
        .write_to(&dir, "set")
        .unwrap();
        std::fs::write(dir.join("a.bin"), &a).unwrap();
        std::fs::write(dir.join("b.bin"), &b).unwrap();
        Self { dir, a, b }
    }

    fn repairer(&self, options: RepairOptions) -> Par2Repairer {
        let mut r = Par2Repairer::new(&self.dir, options);
        r.load_par2_set(&self.dir.join("set.par2")).unwrap();
        r.finalize().unwrap();
        r
    }

    fn par_files(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.to_string_lossy().to_ascii_lowercase().ends_with(".par2"))
            .collect();
        v.sort();
        v
    }

    fn damage_a(&self) {
        let mut a = self.a.clone();
        a[5000] ^= 0xFF;
        std::fs::write(self.dir.join("a.bin"), a).unwrap();
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn kept_all(report: &PurgeReport, why: &PurgeKept) -> bool {
    !report.entries.is_empty()
        && report.kept().all(|(_, k)| k == why)
        && report.removed().count() == 0
}

#[test]
fn nothing_is_removed_before_a_complete_verify() {
    let fx = Fx::new("unverified");
    let pars = fx.par_files();
    assert!(pars.len() > 1);
    let mut r = fx.repairer(RepairOptions::default());
    let report = r.purge(&mut NullObserver);
    assert!(kept_all(&report, &PurgeKept::NotVerified), "{report:?}");
    assert_eq!(fx.par_files(), pars);

    // A damaged set stays unpurgeable after verify.
    fx.damage_a();
    let mut r = fx.repairer(RepairOptions::default());
    assert!(!r.verify(None, &mut NullObserver).unwrap().all_complete);
    assert!(kept_all(
        &r.purge(&mut NullObserver),
        &PurgeKept::NotVerified
    ));
    assert_eq!(fx.par_files(), pars);
}

#[test]
fn complete_verify_purges_par_files_once() {
    let fx = Fx::new("complete");
    let pars = fx.par_files();
    let mut r = fx.repairer(RepairOptions::default());
    assert!(r.verify(None, &mut NullObserver).unwrap().all_complete);
    assert_eq!(r.purge_candidates(), r.par_files);
    let report = r.purge(&mut NullObserver);
    assert!(report.all_removed(), "{report:?}");
    let mut removed: Vec<_> = report.removed().map(Path::to_path_buf).collect();
    removed.sort();
    assert_eq!(removed, pars);
    assert!(fx.par_files().is_empty());
    assert_eq!(std::fs::read(fx.dir.join("a.bin")).unwrap(), fx.a);
    assert_eq!(std::fs::read(fx.dir.join("b.bin")).unwrap(), fx.b);
    // The set is gone: a second purge removes nothing.
    assert!(kept_all(
        &r.purge(&mut NullObserver),
        &PurgeKept::NotVerified
    ));
}

#[test]
fn verified_repair_purges_backups_and_par_files() {
    let fx = Fx::new("repair");
    fx.damage_a();
    let mut r = fx.repairer(RepairOptions {
        backup: BackupPolicy::RenameNumbered,
        ..RepairOptions::default()
    });
    r.verify(None, &mut NullObserver).unwrap();
    let RepairResult::Repaired { leftovers, .. } = r.repair(&mut NullObserver).unwrap() else {
        panic!("expected a repair");
    };
    assert_eq!(leftovers, vec![fx.dir.join("a.bin.1")]);
    assert_eq!(r.purge_candidates()[0], fx.dir.join("a.bin.1"));
    let report = r.purge(&mut NullObserver);
    assert!(report.all_removed(), "{report:?}");
    assert!(!fx.dir.join("a.bin.1").exists());
    assert!(fx.par_files().is_empty());
    assert_eq!(std::fs::read(fx.dir.join("a.bin")).unwrap(), fx.a);
}

#[test]
fn unverified_repair_needs_a_fresh_verify() {
    let fx = Fx::new("noverify");
    fx.damage_a();
    let mut r = fx.repairer(RepairOptions {
        verify_repaired: false,
        ..RepairOptions::default()
    });
    assert!(matches!(
        r.repair(&mut NullObserver).unwrap(),
        RepairResult::Repaired { .. }
    ));
    assert!(kept_all(
        &r.purge(&mut NullObserver),
        &PurgeKept::NotVerified
    ));
    assert!(fx.dir.join("a.bin.1").exists());
    assert!(r.verify(None, &mut NullObserver).unwrap().all_complete);
    let report = r.purge(&mut NullObserver);
    assert!(report.all_removed(), "{report:?}");
    assert!(!fx.dir.join("a.bin.1").exists());
}

#[test]
fn guards_keep_targets_aliases_directories_and_missing_paths() {
    let fx = Fx::new("guards");
    let mut r = fx.repairer(RepairOptions::default());
    assert!(r.verify(None, &mut NullObserver).unwrap().all_complete);
    let spelled = fx.dir.join(".").join("a.bin");
    let subdir = fx.dir.join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    let missing = fx.dir.join("gone.1");
    let mut expected: Vec<(PathBuf, Option<PurgeKept>)> = vec![
        (spelled.clone(), Some(PurgeKept::ProtectedTarget)),
        (subdir.clone(), Some(PurgeKept::NotAFile)),
        (missing.clone(), Some(PurgeKept::Missing)),
    ];
    r.purge_state.leftovers = vec![spelled, subdir.clone(), missing];
    #[cfg(unix)]
    {
        let hard = fx.dir.join("b.hardlink");
        std::fs::hard_link(fx.dir.join("b.bin"), &hard).unwrap();
        let link = fx.dir.join("a.symlink");
        std::os::unix::fs::symlink(fx.dir.join("a.bin"), &link).unwrap();
        r.purge_state.leftovers.push(hard.clone());
        r.purge_state.leftovers.push(link.clone());
        expected.push((hard, Some(PurgeKept::ProtectedTarget)));
        // The link itself goes; its target stays.
        expected.push((link, None));
    }
    let report = r.purge(&mut NullObserver);
    for (path, kept) in &expected {
        let entry = report
            .entries
            .iter()
            .find(|e| &e.path == path)
            .unwrap_or_else(|| panic!("{path:?} not in {report:?}"));
        assert_eq!(&entry.kept, kept, "{path:?}");
    }
    assert!(subdir.is_dir());
    assert_eq!(std::fs::read(fx.dir.join("a.bin")).unwrap(), fx.a);
    assert_eq!(std::fs::read(fx.dir.join("b.bin")).unwrap(), fx.b);
    #[cfg(unix)]
    assert!(fx.dir.join("b.hardlink").exists() && !fx.dir.join("a.symlink").exists());
    // The par2 files themselves were purged.
    assert!(fx.par_files().is_empty());
}
