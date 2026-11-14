//! Complete-copy movement through the public repair API.
use par_rs::{
    BackupPolicy, ExtraFileScanPolicy, FileStatus, Level, NullObserver, Par2Repairer, RepairError,
    RepairObserver, RepairOptions, RepairResult, SetOptions, build_set,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
const A: &[u8] = b"abcdefghABCDEFGH";
const B: &[u8] = b"12345678!@#$%^&*";
const C: &[u8] = b"QWERTYUIOPasdfgh";
const SOURCES: [(&str, &[u8]); 3] = [("a.bin", A), ("b.bin", B), ("c.bin", C)];
fn options(rename: bool, backup: BackupPolicy) -> RepairOptions {
    RepairOptions {
        rename_misnamed: rename,
        backup,
        full_file_md5: true,
        num_threads: 1,
        ..RepairOptions::default()
    }
}
fn leftovers(result: RepairResult) -> Vec<PathBuf> {
    let RepairResult::Repaired { leftovers, .. } = result else {
        panic!("repair expected")
    };
    leftovers
}
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    dir: PathBuf,
    engine: Par2Repairer,
}
impl Fixture {
    fn new(
        files: &[(&str, &[u8])],
        present: &[(&str, &[u8])],
        options: RepairOptions,
        recovery: u32,
    ) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "par-rs-cycle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let set = build_set(
            "set",
            files,
            &SetOptions {
                slice_size: 16,
                recovery_blocks: recovery,
                ..SetOptions::default()
            },
        )
        .unwrap();
        set.write_to(&dir, "set").unwrap();
        for (name, bytes) in present {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let mut engine = Par2Repairer::new(&dir, options);
        engine.load_par2_set(&dir.join("set.par2")).unwrap();
        engine.finalize().unwrap();
        engine.verify(None, &mut NullObserver).unwrap();
        Self { dir, engine }
    }
    fn swap() -> Self {
        Self::new(
            &SOURCES[..2],
            &[("a.bin", B), ("b.bin", A)],
            options(true, BackupPolicy::RenameNumbered),
            0,
        )
    }
    fn bytes(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(name)).unwrap()
    }
    fn complete(&self, files: &[(&str, &[u8])]) {
        for (name, bytes) in files {
            assert_eq!(self.bytes(name), *bytes, "{name}");
        }
        for state in self.engine.source_files() {
            assert_eq!(state.status, FileStatus::Complete);
            assert_eq!(state.complete_file.as_ref(), Some(&state.target_path));
        }
        for state in self.engine.source_files() {
            for block in 0..state.block_count as usize {
                let loc = self.engine.block_locations()[state.first_block + block]
                    .as_ref()
                    .unwrap();
                let data = std::fs::read(&self.engine.disk_files()[loc.file]).unwrap();
                let expected = files
                    .iter()
                    .find(|(n, _)| *n == state.target_filename)
                    .unwrap()
                    .1;
                let offset = loc.offset as usize;
                let len = (expected.len() - block * 16).min(16);
                assert_eq!(
                    &data[offset..offset + len],
                    &expected[block * 16..block * 16 + len]
                );
            }
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}
#[test]
fn swap_consumes_own_backup_and_reports_no_leftovers() {
    let mut fixture = Fixture::swap();
    let result = fixture.engine.repair(&mut NullObserver).unwrap();
    assert_eq!(
        std::fs::read(fixture.dir.join("a.bin")).unwrap(),
        b"abcdefghABCDEFGH"
    );
    assert_eq!(
        std::fs::read(fixture.dir.join("b.bin")).unwrap(),
        b"12345678!@#$%^&*"
    );
    let RepairResult::Repaired { leftovers, .. } = result else {
        panic!("repair expected")
    };
    assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    let mut names: Vec<_> = std::fs::read_dir(&fixture.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["a.bin", "b.bin", "set.par2"]);
}

#[test]
fn cycles_in_both_directions_preserve_preexisting_backups_under_all_policies() {
    for policy in [
        BackupPolicy::RenameNumbered,
        BackupPolicy::RenameBak,
        BackupPolicy::DeleteAfterRepair,
    ] {
        for originals in [SOURCES, [("a.bin", B), ("b.bin", A), ("c.bin", C)]] {
            for count in [2, 3] {
                for step in 1..count {
                    let files = &originals[..count];
                    let present: Vec<_> = (0..count)
                        .map(|i| (files[i].0, files[(i + step) % count].1))
                        .collect();
                    let mut fixture = Fixture::new(files, &present, options(true, policy), 0);
                    for (name, bytes) in [
                        ("a.bin.1", A),
                        ("a.bin.2", C),
                        ("b.bin.1", B),
                        ("b.bin.2", A),
                        ("c.bin.bak", B),
                    ] {
                        std::fs::write(fixture.dir.join(name), bytes).unwrap();
                    }
                    let before: Vec<_> = std::fs::read_dir(&fixture.dir)
                        .unwrap()
                        .map(|e| e.unwrap().file_name())
                        .collect();
                    let result = fixture.engine.repair(&mut NullObserver).unwrap();
                    assert!(leftovers(result).is_empty());
                    fixture.complete(files);
                    let mut after: Vec<_> = std::fs::read_dir(&fixture.dir)
                        .unwrap()
                        .map(|e| e.unwrap().file_name())
                        .collect();
                    let mut before = before;
                    before.sort();
                    after.sort();
                    assert_eq!(before, after);
                    assert_eq!(fixture.bytes("a.bin.1"), A);
                    assert_eq!(fixture.bytes("a.bin.2"), C);
                    assert_eq!(fixture.bytes("b.bin.1"), B);
                    assert_eq!(fixture.bytes("b.bin.2"), A);
                    assert_eq!(fixture.bytes("c.bin.bak"), B);
                }
            }
        }
    }
}

#[test]
fn rename_false_keeps_copy_backups_and_reports_them() {
    let mut fixture = Fixture::new(
        &SOURCES[..2],
        &[("a.bin", B), ("b.bin", A)],
        options(false, BackupPolicy::RenameNumbered),
        0,
    );
    std::fs::write(fixture.dir.join("b.bin.1"), C).unwrap();
    let mut got = leftovers(fixture.engine.repair(&mut NullObserver).unwrap());
    got.sort();
    assert_eq!(
        got,
        [fixture.dir.join("a.bin.1"), fixture.dir.join("b.bin.2")]
    );
    fixture.complete(&SOURCES[..2]);
    assert_eq!(fixture.bytes("a.bin.1"), B);
    assert_eq!(fixture.bytes("b.bin.2"), A);
    assert_eq!(fixture.bytes("b.bin.1"), C);
}

#[derive(Default)]
struct Messages(Vec<String>);
impl RepairObserver for Messages {
    fn message(&mut self, _: Level, text: &str) {
        self.0.push(text.to_owned());
    }
}
#[test]
fn mixed_cycle_retains_genuine_damage_even_when_it_matches_a_correct_source() {
    let files = [
        ("a.bin", A),
        ("b.bin", B),
        ("c.bin", C),
        ("d.bin", b"unique0123456789".as_slice()),
    ];
    for policy in [
        BackupPolicy::RenameNumbered,
        BackupPolicy::RenameBak,
        BackupPolicy::DeleteAfterRepair,
    ] {
        let mut fixture = Fixture::new(
            &files,
            &[("a.bin", B), ("b.bin", A), ("c.bin", C), ("d.bin", C)],
            options(true, policy),
            1,
        );
        let mut messages = Messages::default();
        let got = leftovers(fixture.engine.repair(&mut messages).unwrap());
        fixture.complete(&files);
        let name = if policy == BackupPolicy::RenameBak {
            "d.bin.bak"
        } else {
            "d.bin.1"
        };
        assert_eq!(got, [fixture.dir.join(name)]);
        if policy == BackupPolicy::DeleteAfterRepair {
            assert!(!fixture.dir.join(name).exists());
        } else {
            assert_eq!(fixture.bytes(name), C);
        }
        assert!(!messages.0.iter().any(|m| m.contains("Could not delete")));
        assert!(!fixture.dir.join("a.bin.1").exists());
        assert!(!fixture.dir.join("b.bin.1").exists());
    }
}

#[test]
fn shared_equal_complete_copies_and_empty_aliases_keep_every_target() {
    for bytes in [A, b"".as_slice()] {
        for explicit in [false, true] {
            let files = [("a.bin", bytes), ("b.bin", bytes)];
            let mut fixture =
                Fixture::new(&files, &[], options(true, BackupPolicy::RenameNumbered), 0);
            let donor = fixture.dir.join("D");
            std::fs::write(&donor, bytes).unwrap();
            if explicit {
                fixture
                    .engine
                    .add_extra_file_with_policy(
                        &donor,
                        ExtraFileScanPolicy::Full,
                        &mut NullObserver,
                    )
                    .unwrap();
            } else {
                fixture
                    .engine
                    .add_extra_file(&donor, &mut NullObserver)
                    .unwrap();
            }
            assert!(leftovers(fixture.engine.repair(&mut NullObserver).unwrap()).is_empty());
            fixture.complete(&files);
            // A block-shared donor is retained. A zero-block donor may move once, but the
            // resulting correct target cannot be moved away to satisfy its equal sibling.
            if !bytes.is_empty() {
                assert_eq!(std::fs::read(&donor).unwrap(), bytes);
            }
        }
    }
}

#[test]
fn external_complete_donor_plus_parity_preserves_damage_for_all_admission_paths() {
    for admission in 0..3 {
        for rename in [false, true] {
            let mut fixture = Fixture::new(
                &SOURCES[..2],
                &[("b.bin", C)],
                options(rename, BackupPolicy::RenameNumbered),
                1,
            );
            let donor = fixture.dir.join("D");
            std::fs::write(&donor, A).unwrap();
            match admission {
                0 => {
                    fixture
                        .engine
                        .add_extra_file(&donor, &mut NullObserver)
                        .unwrap();
                }
                n => {
                    fixture
                        .engine
                        .add_extra_file_with_policy(
                            &donor,
                            if n == 1 {
                                ExtraFileScanPolicy::Full
                            } else {
                                ExtraFileScanPolicy::OrderedPrefix
                            },
                            &mut NullObserver,
                        )
                        .unwrap();
                }
            }
            let got = leftovers(fixture.engine.repair(&mut NullObserver).unwrap());
            fixture.complete(&SOURCES[..2]);
            assert_eq!(got, [fixture.dir.join("b.bin.1")]);
            assert_eq!(fixture.bytes("b.bin.1"), C);
            assert_eq!(donor.exists(), !rename);
            if !rename {
                assert_eq!(std::fs::read(donor).unwrap(), A);
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn moving_hard_linked_complete_source_keeps_survivor_bytes_and_link_count() {
    use std::os::unix::fs::MetadataExt;
    for rename in [false, true] {
        let mut fixture = Fixture::new(
            &SOURCES[..1],
            &[],
            options(rename, BackupPolicy::RenameNumbered),
            0,
        );
        let donor = fixture.dir.join("D");
        let survivor = fixture.dir.join("survivor");
        std::fs::write(&donor, A).unwrap();
        std::fs::hard_link(&donor, &survivor).unwrap();
        let inode = std::fs::metadata(&survivor).unwrap().ino();
        fixture
            .engine
            .add_extra_file_with_policy(
                &donor,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver,
            )
            .unwrap();
        assert!(leftovers(fixture.engine.repair(&mut NullObserver).unwrap()).is_empty());
        fixture.complete(&SOURCES[..1]);
        assert_eq!(std::fs::read(&survivor).unwrap(), A);
        let metadata = std::fs::metadata(&survivor).unwrap();
        assert_eq!(metadata.nlink(), 2);
        assert_eq!(metadata.ino(), inode);
        assert_eq!(donor.exists(), !rename);
        if rename {
            assert_eq!(
                std::fs::metadata(fixture.dir.join("a.bin")).unwrap().ino(),
                inode
            );
        }
    }
}

struct Interrupt {
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    block: Option<PathBuf>,
    fired: bool,
}
impl RepairObserver for Interrupt {
    fn message(&mut self, _: Level, text: &str) {
        if !self.fired && text.starts_with("Renamed ") {
            self.fired = true;
            if let Some(cancel) = &self.cancel {
                cancel.store(true, Ordering::Relaxed);
            }
            if let Some(path) = &self.block {
                std::fs::create_dir(path).unwrap();
            }
        }
    }
}
#[test]
fn cancellation_after_first_move_keeps_coherent_partial_state_and_backup() {
    let mut fixture = Fixture::swap();
    assert_eq!(fixture.engine.source_files()[0].target_filename, "b.bin");
    let mut observer = Interrupt {
        cancel: Some(fixture.engine.cancel_token()),
        block: None,
        fired: false,
    };
    assert!(matches!(
        fixture.engine.repair(&mut observer),
        Err(RepairError::Cancelled)
    ));
    assert!(observer.fired);
    assert_eq!(fixture.bytes("b.bin"), B);
    assert_eq!(fixture.bytes("b.bin.1"), A);
    assert!(!fixture.dir.join("a.bin").exists());
    let a = fixture
        .engine
        .source_files()
        .iter()
        .find(|f| f.target_filename == "a.bin")
        .unwrap();
    assert_eq!(a.complete_file, Some(fixture.dir.join("b.bin.1")));
    assert_eq!(
        fixture.engine.source_files()[0].status,
        FileStatus::Complete
    );
}
#[test]
fn failed_second_move_keeps_unconsumed_backup_and_reports_io_error() {
    let mut fixture = Fixture::swap();
    let mut observer = Interrupt {
        cancel: None,
        block: Some(fixture.dir.join("a.bin")),
        fired: false,
    };
    assert!(matches!(
        fixture.engine.repair(&mut observer),
        Err(RepairError::Io { .. })
    ));
    assert!(observer.fired);
    assert_eq!(fixture.bytes("b.bin"), B);
    assert_eq!(fixture.bytes("b.bin.1"), A);
    assert!(fixture.dir.join("a.bin").is_dir());
    let a = fixture
        .engine
        .source_files()
        .iter()
        .find(|f| f.target_filename == "a.bin")
        .unwrap();
    assert_eq!(a.complete_file, Some(fixture.dir.join("b.bin.1")));
    assert_ne!(a.status, FileStatus::Complete);
}

#[test]
fn cycles_with_longer_target_paths_keep_complete_references_coherent() {
    let files = [
        ("a", A),
        ("a-much-longer-target-name.bin", B),
        ("nested/another-target.bin", C),
    ];
    let mut fixture = Fixture::new(
        &files,
        &[("a", B), ("a-much-longer-target-name.bin", C)],
        options(true, BackupPolicy::RenameNumbered),
        0,
    );
    std::fs::create_dir(fixture.dir.join("nested")).unwrap();
    std::fs::write(fixture.dir.join("nested/another-target.bin"), A).unwrap();
    fixture.engine.verify(None, &mut NullObserver).unwrap();
    assert!(leftovers(fixture.engine.repair(&mut NullObserver).unwrap()).is_empty());
    fixture.complete(&files);
}

#[cfg(unix)]
#[test]
fn cycle_rotations_preserve_hard_linked_source_survivors() {
    use std::os::unix::fs::MetadataExt;
    let mut fixture = Fixture::swap();
    let survivor_a = fixture.dir.join("survivor-a");
    let survivor_b = fixture.dir.join("survivor-b");
    std::fs::hard_link(fixture.dir.join("b.bin"), &survivor_a).unwrap();
    std::fs::hard_link(fixture.dir.join("a.bin"), &survivor_b).unwrap();
    let inode_a = std::fs::metadata(&survivor_a).unwrap().ino();
    let inode_b = std::fs::metadata(&survivor_b).unwrap().ino();
    assert_eq!(std::fs::metadata(&survivor_a).unwrap().nlink(), 2);
    assert_eq!(std::fs::metadata(&survivor_b).unwrap().nlink(), 2);
    assert!(leftovers(fixture.engine.repair(&mut NullObserver).unwrap()).is_empty());
    fixture.complete(&SOURCES[..2]);
    assert_eq!(std::fs::read(&survivor_a).unwrap(), A);
    assert_eq!(std::fs::read(&survivor_b).unwrap(), B);
    let a = std::fs::metadata(&survivor_a).unwrap();
    let b = std::fs::metadata(&survivor_b).unwrap();
    assert_eq!(a.ino(), inode_a);
    assert_eq!(b.ino(), inode_b);
    // The old b.bin link was replaced; its pristine backup was a separate copy.
    assert_eq!(a.nlink(), 1);
    assert_eq!(b.nlink(), 2);
    assert_eq!(
        std::fs::metadata(fixture.dir.join("b.bin")).unwrap().ino(),
        inode_b
    );
}
