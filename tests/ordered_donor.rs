//! Integrated donor admission through public repairer APIs.

use par_rs::packet::{PacketIter, ScanOptions, TYPE_IFSC, compute_file_id};
use par_rs::{
    ExtraFileScanPolicy, NullObserver, Par2Repairer, RepairOptions, SetOptions, build_set,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    dir: PathBuf,
    engine: Par2Repairer,
}
impl Fixture {
    fn new(files: &[(&str, &[u8])]) -> Self {
        Self::with_ifsc(files, &[])
    }

    fn with_ifsc(files: &[(&str, &[u8])], absent: &[&str]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "par-rs-ordered-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        let set = build_set(
            "set",
            files,
            &SetOptions {
                slice_size: 4,
                recovery_blocks: 0,
                ..SetOptions::default()
            },
        )
        .unwrap();
        let index = dir.join("set.par2");
        let absent_ids: Vec<_> = files
            .iter()
            .filter(|(name, _)| absent.contains(name))
            .map(|(name, bytes)| {
                compute_file_id(
                    &par_rs::hasher::md5_16k(bytes),
                    bytes.len() as u64,
                    name.as_bytes(),
                )
            })
            .collect();
        let mut metadata = Vec::new();
        for packet in PacketIter::new(set.index.as_slice(), ScanOptions::FULL) {
            let packet = packet.unwrap();
            let start = packet.offset as usize;
            let end = start + packet.header.length as usize;
            let omitted = packet.header.packet_type == TYPE_IFSC
                && absent_ids
                    .iter()
                    .any(|id| id.0 == set.index[start + 64..start + 80]);
            if !omitted {
                metadata.extend_from_slice(&set.index[start..end]);
            }
        }
        std::fs::write(&index, metadata).unwrap();
        let mut engine = Par2Repairer::new(&dir, RepairOptions::default());
        engine.load_par2_file(&index).unwrap();
        engine.finalize().unwrap();
        engine.verify(None, &mut NullObserver).unwrap();
        Self { dir, engine }
    }

    fn donor(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, data).unwrap();
        path
    }

    fn locations(&self) -> Vec<Option<(PathBuf, u64)>> {
        self.engine
            .block_locations()
            .iter()
            .map(|location| {
                location.as_ref().map(|location| {
                    (
                        self.engine.disk_files()[location.file].clone(),
                        location.offset,
                    )
                })
            })
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[test]
fn ordered_prefix_stops_before_out_of_order_block() {
    let mut fixture = Fixture::new(&[("a.bin", b"abcdefghijkl")]);
    let donor = fixture.donor("donor", b"abcdijklefgh");
    let count = fixture
        .engine
        .add_extra_file_with_policy(
            &donor,
            ExtraFileScanPolicy::OrderedPrefix,
            &mut NullObserver,
        )
        .unwrap();
    // Only the first block belongs to the ordered prefix.
    assert_eq!(count, 1);
    assert_eq!(
        fixture.locations(),
        vec![Some((donor.clone(), 0)), None, None]
    );
    assert!(fixture.engine.source_files()[0].complete_file.is_none());
    assert_eq!(std::fs::read(donor).unwrap(), b"abcdijklefgh");
    assert!(!fixture.dir.join(Path::new("a.bin")).exists());
}

#[test]
fn explicit_full_preserves_all_match_and_first_location_behavior() {
    let mut equal = Fixture::new(&[("a.bin", b"abcdefgh"), ("b.bin", b"abcdefgh")]);
    let donor = equal.donor("D", b"abcdefgh");
    assert_eq!(
        equal
            .engine
            .add_extra_file_with_policy(&donor, ExtraFileScanPolicy::Full, &mut NullObserver)
            .unwrap(),
        4
    );
    assert_eq!(
        equal.locations(),
        vec![
            Some((donor.clone(), 0)),
            Some((donor.clone(), 4)),
            Some((donor.clone(), 0)),
            Some((donor, 4))
        ]
    );
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        let mut fixture = Fixture::new(&[("a.bin", b"abcdefghijkl")]);
        let old = fixture.donor("E", b"zzzzefghzzzz");
        assert_eq!(
            fixture
                .engine
                .add_extra_file(&old, &mut NullObserver)
                .unwrap(),
            1
        );
        let donor = fixture.donor("D", b"abcdefghijkl");
        assert_eq!(
            fixture
                .engine
                .add_extra_file_with_policy(&donor, policy, &mut NullObserver)
                .unwrap(),
            2
        );
        let middle = if policy == ExtraFileScanPolicy::Full {
            old.clone()
        } else {
            donor.clone()
        };
        assert_eq!(
            fixture.locations(),
            vec![
                Some((donor.clone(), 0)),
                Some((middle, 4)),
                Some((donor.clone(), 8))
            ]
        );
        assert_eq!(std::fs::read(old).unwrap(), b"zzzzefghzzzz");
        assert_eq!(std::fs::read(donor).unwrap(), b"abcdefghijkl");
    }
}

#[test]
fn ordered_equal_files_select_only_the_first_main_identity() {
    let mut fixture = Fixture::new(&[("a.bin", b"abcdefgh"), ("b.bin", b"abcdefgh")]);
    let donor = fixture.donor("D", b"abcdefgh");
    assert_eq!(
        fixture
            .engine
            .add_extra_file_with_policy(
                &donor,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver
            )
            .unwrap(),
        2
    );
    assert_eq!(
        fixture.locations(),
        vec![
            Some((donor.clone(), 0)),
            Some((donor.clone(), 4)),
            None,
            None
        ]
    );
    assert_eq!(fixture.engine.source_files()[0].complete_file, Some(donor));
    assert!(fixture.engine.source_files()[1].complete_file.is_none());
}

#[test]
fn checksum_absent_fallback_selects_one_identity_per_new_donor() {
    let mut fixture = Fixture::with_ifsc(
        &[("a.bin", b"abcdefgh"), ("b.bin", b"abcdefgh")],
        &["a.bin", "b.bin"],
    );
    let first = fixture.donor("D", b"abcdefgh");
    assert_eq!(
        fixture
            .engine
            .add_extra_file_with_policy(
                &first,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver
            )
            .unwrap(),
        2
    );
    assert_eq!(
        fixture.locations(),
        vec![
            Some((first.clone(), 0)),
            Some((first.clone(), 4)),
            None,
            None
        ]
    );
    assert_eq!(
        fixture.engine.source_files()[0].complete_file,
        Some(first.clone())
    );
    assert!(fixture.engine.source_files()[1].complete_file.is_none());
    let second = fixture.donor("E", b"abcdefgh");
    assert_eq!(
        fixture
            .engine
            .add_extra_file_with_policy(
                &second,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver
            )
            .unwrap(),
        2
    );
    assert_eq!(
        fixture.locations(),
        vec![
            Some((first.clone(), 0)),
            Some((first.clone(), 4)),
            Some((second.clone(), 0)),
            Some((second.clone(), 4))
        ]
    );
    assert_eq!(std::fs::read(first).unwrap(), b"abcdefgh");
    assert_eq!(std::fs::read(second).unwrap(), b"abcdefgh");
}

#[test]
fn mixed_metadata_partial_result_does_not_use_whole_file_fallback() {
    for original in [b"abcdijkl".as_slice(), b"ijklijkl".as_slice()] {
        let mut fixture =
            Fixture::with_ifsc(&[("a.bin", original), ("b.bin", b"abcdefgh")], &["b.bin"]);
        let donor = fixture.donor("D", b"abcdefgh");
        let count = fixture
            .engine
            .add_extra_file_with_policy(
                &donor,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver,
            )
            .unwrap();
        assert_eq!(count, usize::from(original.starts_with(b"abcd")));
        let absent = fixture
            .engine
            .source_files()
            .iter()
            .find(|file| file.target_filename == "b.bin")
            .unwrap();
        assert_eq!(absent.available_blocks, 0);
        assert!(absent.complete_file.is_none());
        assert!(!fixture.dir.join("b.bin").exists());
        assert_eq!(std::fs::read(donor).unwrap(), b"abcdefgh");
    }
}

#[test]
fn short_terminal_trailing_bytes_and_absent_actual_zero_are_distinct() {
    for (original, donor, want, complete) in [
        (b"abcdYZ".as_slice(), b"abcdYZ".as_slice(), 2, true),
        (b"abcdYZ".as_slice(), b"abcdYZ!!".as_slice(), 2, false),
        (b"abcdq\0".as_slice(), b"abcdq".as_slice(), 1, false),
    ] {
        let mut fixture = Fixture::new(&[("a.bin", original)]);
        let path = fixture.donor("D", donor);
        assert_eq!(
            fixture
                .engine
                .add_extra_file_with_policy(
                    &path,
                    ExtraFileScanPolicy::OrderedPrefix,
                    &mut NullObserver
                )
                .unwrap(),
            want
        );
        assert_eq!(
            fixture.engine.source_files()[0].complete_file.is_some(),
            complete
        );
        assert_eq!(std::fs::read(path).unwrap(), donor);
    }
}

#[test]
fn empty_donor_can_supply_empty_identity_without_a_block_or_movement() {
    let mut fixture = Fixture::new(&[("empty.bin", b"")]);
    let donor = fixture.donor("D", b"");
    assert_eq!(
        fixture
            .engine
            .add_extra_file_with_policy(
                &donor,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver
            )
            .unwrap(),
        0
    );
    assert_eq!(
        fixture.engine.source_files()[0].complete_file,
        Some(donor.clone())
    );
    assert!(fixture.locations().is_empty());
    assert!(donor.exists());
    assert!(!fixture.dir.join("empty.bin").exists());
}

#[test]
fn failed_admission_can_retry_but_successful_path_is_idempotent() {
    let mut fixture = Fixture::new(&[("a.bin", b"abcdefgh")]);
    let path = fixture.dir.join("D");
    assert!(
        fixture
            .engine
            .add_extra_file_with_policy(
                &path,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver
            )
            .is_err()
    );
    assert_eq!(fixture.locations(), vec![None, None]);
    std::fs::write(&path, b"abcdefgh").unwrap();
    assert_eq!(
        fixture
            .engine
            .add_extra_file_with_policy(
                &path,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver
            )
            .unwrap(),
        2
    );
    let previous = fixture.locations();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        fixture
            .engine
            .add_extra_file_with_policy(
                &path,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver
            )
            .unwrap(),
        0
    );
    assert_eq!(fixture.locations(), previous);
}

#[test]
fn finalization_and_early_complete_controls_are_preserved() {
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        let mut unfinalized = Par2Repairer::new(".", RepairOptions::default());
        assert!(matches!(
            unfinalized.add_extra_file_with_policy(Path::new("missing"), policy, &mut NullObserver),
            Err(par_rs::RepairError::NotFinalized)
        ));
        let mut fixture = Fixture::new(&[("a.bin", b"abcdefgh")]);
        std::fs::write(fixture.dir.join("a.bin"), b"abcdefgh").unwrap();
        fixture.engine.verify(None, &mut NullObserver).unwrap();
        assert_eq!(
            fixture
                .engine
                .add_extra_file_with_policy(&fixture.dir.join("missing"), policy, &mut NullObserver)
                .unwrap(),
            0
        );
    }
}

#[test]
fn public_cancellation_preserves_locations_and_allows_retry() {
    let mut fixture = Fixture::new(&[("a.bin", b"abcdefgh")]);
    let donor = fixture.donor("D", b"abcdefgh");
    let cancel = fixture.engine.cancel_token();
    cancel.store(true, Ordering::Relaxed);
    assert!(matches!(
        fixture.engine.add_extra_file_with_policy(
            &donor,
            ExtraFileScanPolicy::OrderedPrefix,
            &mut NullObserver
        ),
        Err(par_rs::RepairError::Cancelled)
    ));
    assert_eq!(fixture.locations(), vec![None, None]);
    cancel.store(false, Ordering::Relaxed);
    assert_eq!(
        fixture
            .engine
            .add_extra_file_with_policy(
                &donor,
                ExtraFileScanPolicy::OrderedPrefix,
                &mut NullObserver
            )
            .unwrap(),
        2
    );
    assert_eq!(std::fs::read(donor).unwrap(), b"abcdefgh");
}

#[test]
fn parity_repair_and_donor_movement_follow_existing_repair_options() {
    for rename in [false, true] {
        let files = [
            ("a.bin", b"abcdefghABCDEFGH".as_slice()),
            ("b.bin", b"12345678!@#$%^&*".as_slice()),
        ];
        let mut fixture = Fixture::new(&files);
        let set = build_set(
            "set",
            &files,
            &SetOptions {
                slice_size: 16,
                recovery_blocks: 1,
                ..SetOptions::default()
            },
        )
        .unwrap();
        set.write_to(&fixture.dir, "set").unwrap();
        fixture.engine = Par2Repairer::new(
            &fixture.dir,
            RepairOptions {
                rename_misnamed: rename,
                full_file_md5: true,
                num_threads: 1,
                ..RepairOptions::default()
            },
        );
        fixture
            .engine
            .load_par2_set(&fixture.dir.join("set.par2"))
            .unwrap();
        fixture.engine.finalize().unwrap();
        let donor = fixture.donor("D", files[0].1);
        std::fs::write(fixture.dir.join("b.bin"), vec![255; 16]).unwrap();
        fixture.engine.verify(None, &mut NullObserver).unwrap();
        assert_eq!(
            fixture
                .engine
                .add_extra_file_with_policy(
                    &donor,
                    ExtraFileScanPolicy::OrderedPrefix,
                    &mut NullObserver
                )
                .unwrap(),
            1
        );
        assert!(donor.exists());
        assert!(!fixture.dir.join("a.bin").exists());
        fixture.engine.repair(&mut NullObserver).unwrap();
        for (name, bytes) in files {
            assert_eq!(std::fs::read(fixture.dir.join(name)).unwrap(), bytes);
        }
        assert_eq!(donor.exists(), !rename);
        if !rename {
            assert_eq!(std::fs::read(donor).unwrap(), files[0].1);
        }
        assert_eq!(
            std::fs::read(fixture.dir.join("b.bin.1")).unwrap(),
            vec![255; 16]
        );
    }
}
