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
    assert_eq!(r.purge_state.par_files, r.par_files);
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
fn unverified_repair_is_never_purgeable_by_the_same_repairer() {
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
    // Damage the rebuilt file again: a re-verify skips files already marked complete, so it
    // must not make purging safe.
    fx.damage_a();
    assert!(r.verify(None, &mut NullObserver).unwrap().all_complete);
    assert!(kept_all(
        &r.purge(&mut NullObserver),
        &PurgeKept::NotVerified
    ));
    assert!(fx.dir.join("a.bin.1").exists());
    assert!(!fx.par_files().is_empty());
    // A fresh repairer hashes everything and sees the damage.
    let mut fresh = fx.repairer(RepairOptions::default());
    assert!(!fresh.verify(None, &mut NullObserver).unwrap().all_complete);
    assert!(kept_all(
        &fresh.purge(&mut NullObserver),
        &PurgeKept::NotVerified
    ));
    // Once the target is good again, a fresh full verify allows the purge.
    std::fs::write(fx.dir.join("a.bin"), &fx.a).unwrap();
    let mut fresh = fx.repairer(RepairOptions::default());
    assert!(fresh.verify(None, &mut NullObserver).unwrap().all_complete);
    let report = fresh.purge(&mut NullObserver);
    assert!(report.all_removed(), "{report:?}");
    assert!(fx.par_files().is_empty());
    // A fresh repairer does not know the old backup; it stays.
    assert!(fx.dir.join("a.bin.1").exists());
}

#[test]
fn second_verify_is_not_a_full_hash() {
    let fx = Fx::new("reverify");
    let mut r = fx.repairer(RepairOptions::default());
    assert!(r.verify(None, &mut NullObserver).unwrap().all_complete);
    // Corrupt after the first verify; the second one skips complete files.
    fx.damage_a();
    assert!(r.verify(None, &mut NullObserver).unwrap().all_complete);
    assert!(kept_all(
        &r.purge(&mut NullObserver),
        &PurgeKept::NotVerified
    ));
    assert!(!fx.par_files().is_empty());
}

#[test]
fn foreign_empty_and_temporary_par_files_are_never_candidates() {
    let fx = Fx::new("foreign");
    // A volume of another set and an empty file named like volumes of this set.
    let other = build_set(
        "other",
        &[("z.bin", &[9u8; 3000][..])],
        &SetOptions {
            slice_size: 1024,
            recovery_blocks: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let odir = fx.dir.join("other");
    std::fs::create_dir(&odir).unwrap();
    let written = other.write_to(&odir, "other").unwrap();
    let vol = written
        .iter()
        .find(|p| p.to_string_lossy().contains(".vol"))
        .unwrap();
    std::fs::copy(vol, fx.dir.join("set.vol99+02.par2")).unwrap();
    std::fs::write(fx.dir.join("set.vol98+01.par2"), b"").unwrap();
    let mut r = fx.repairer(RepairOptions::default());
    let first_index = std::fs::read(fx.dir.join("set.par2")).unwrap();
    r.load_par2_bytes(first_index, "in-memory index").unwrap();
    assert!(r.verify(None, &mut NullObserver).unwrap().all_complete);
    let candidates = r.purge_candidates();
    assert!(!candidates.contains(&fx.dir.join("set.vol99+02.par2")));
    assert!(!candidates.contains(&fx.dir.join("set.vol98+01.par2")));
    assert!(
        candidates.iter().all(|p| p.starts_with(&fx.dir)),
        "{candidates:?}"
    );
    let report = r.purge(&mut NullObserver);
    assert!(report.all_removed(), "{report:?}");
    assert!(fx.dir.join("set.vol99+02.par2").exists());
    assert!(fx.dir.join("set.vol98+01.par2").exists());
}

#[test]
fn split_fragments_are_not_purged() {
    let fx = Fx::new("fragments");
    std::fs::remove_file(fx.dir.join("b.bin")).unwrap();
    std::fs::write(fx.dir.join("b.bin.001"), &fx.b[..4096]).unwrap();
    std::fs::write(fx.dir.join("b.bin.002"), &fx.b[4096..]).unwrap();
    let mut r = fx.repairer(RepairOptions::default());
    r.verify(None, &mut NullObserver).unwrap();
    r.add_split_fragments(&fx.dir.clone(), &mut NullObserver)
        .unwrap();
    let RepairResult::Repaired { leftovers, .. } = r.repair(&mut NullObserver).unwrap() else {
        panic!("expected a repair");
    };
    // Fragments the repair used are user input: never purge candidates, whether or not the
    // repair lists them as leftovers.
    let candidates = r.purge_candidates();
    for frag in ["b.bin.001", "b.bin.002"] {
        assert!(!candidates.contains(&fx.dir.join(frag)), "{candidates:?}");
        if leftovers.contains(&fx.dir.join(frag)) {
            assert!(!r.purge_state.backups.contains(&fx.dir.join(frag)));
        }
    }
    assert!(r.purge(&mut NullObserver).all_removed());
    assert!(fx.dir.join("b.bin.001").exists() && fx.dir.join("b.bin.002").exists());
    assert_eq!(std::fs::read(fx.dir.join("b.bin")).unwrap(), fx.b);
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
    r.purge_state.backups = vec![spelled, subdir.clone(), missing];
    #[cfg(unix)]
    {
        let hard = fx.dir.join("b.hardlink");
        std::fs::hard_link(fx.dir.join("b.bin"), &hard).unwrap();
        let link = fx.dir.join("a.symlink");
        std::os::unix::fs::symlink(fx.dir.join("a.bin"), &link).unwrap();
        r.purge_state.backups.push(hard.clone());
        r.purge_state.backups.push(link.clone());
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
