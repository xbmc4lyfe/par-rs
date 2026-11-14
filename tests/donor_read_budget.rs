// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! Budgeted admission through the public API using real files.
use par_rs::{
    DonorReadBudget, DonorReadError, ExtraFileScanPolicy, NullObserver, Par2Repairer,
    RepairOptions, SetOptions, build_set,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    dir: PathBuf,
    engine: Par2Repairer,
    retain: bool,
    external: Vec<PathBuf>,
}
impl Fixture {
    fn new() -> Self {
        let f = Self::with(
            &[("a.bin", b"abcdefghABCDEFGH")],
            16,
            0,
            RepairOptions::default(),
        );
        std::fs::write(f.dir.join("D"), b"abcdefghABCDEFGH").unwrap();
        f
    }
    fn with(files: &[(&str, &[u8])], slice: usize, recovery: u32, options: RepairOptions) -> Self {
        let retained = std::env::var_os("PAR2_BUDGET_ARTIFACT_DIR");
        let parent = retained
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        std::fs::create_dir_all(&parent).unwrap();
        let dir = parent.join(format!(
            "par-rs-read-budget-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        build_set(
            "set",
            files,
            &SetOptions {
                slice_size: slice,
                recovery_blocks: recovery,
                ..Default::default()
            },
        )
        .unwrap()
        .write_to(&dir, "set")
        .unwrap();
        let mut engine = Par2Repairer::new(&dir, options);
        engine.load_par2_set(&dir.join("set.par2")).unwrap();
        engine.finalize().unwrap();
        engine.verify(None, &mut NullObserver).unwrap();
        Self {
            dir,
            engine,
            retain: retained.is_some(),
            external: Vec::new(),
        }
    }
    fn reload(&mut self) {
        let mut engine = Par2Repairer::new(&self.dir, self.engine.options().clone());
        engine.load_par2_set(&self.dir.join("set.par2")).unwrap();
        engine.finalize().unwrap();
        engine.verify(None, &mut NullObserver).unwrap();
        self.engine = engine;
    }
    fn donor(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }
    fn outside(&mut self, bytes: &[u8]) -> PathBuf {
        let p = self.dir.with_extension("donor");
        std::fs::write(&p, bytes).unwrap();
        self.external.push(p.clone());
        p
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.retain {
            std::fs::remove_dir_all(&self.dir).unwrap();
            for p in &self.external {
                std::fs::remove_file(p).unwrap();
            }
        }
    }
}
fn zero_refuses(policy: ExtraFileScanPolicy) {
    let mut f = Fixture::new();
    let mut budget = DonorReadBudget::new(0);
    let result = f.engine.add_extra_file_with_read_budget(
        &f.dir.join("D"),
        policy,
        &mut budget,
        None,
        &mut NullObserver,
    );
    eprintln!(
        "policy={policy:?} result={result:?} files={:?} disks={:?}",
        f.engine.source_files(),
        f.engine.disk_files()
    );
    assert!(matches!(result, Err(DonorReadError::Limit { .. })));
    assert!(f.engine.disk_files().is_empty());
    assert!(f.engine.source_files()[0].complete_file.is_none());
    assert_eq!(budget.charged_bytes(), 0);
}
#[test]
fn zero_full_refuses_before_admitting_real_complete_donor() {
    zero_refuses(ExtraFileScanPolicy::Full);
}
#[test]
fn zero_ordered_refuses_before_admitting_real_complete_donor() {
    zero_refuses(ExtraFileScanPolicy::OrderedPrefix);
}

fn literal_options() -> RepairOptions {
    // Complete external literal; no field was added for the new capability.
    RepairOptions {
        num_threads: 1,
        mem_limit_bytes: 16 << 20,
        backup: par_rs::BackupPolicy::RenameNumbered,
        verify_repaired: true,
        sync_repaired: false,
        rename_misnamed: false,
        scan_buffer: 64 << 10,
        ignore_extensions: Vec::new(),
        full_file_md5: true,
        kernel: par_rs::Kernel::scalar(),
    }
}
fn old_error_kind(error: &par_rs::RepairError) -> &'static str {
    use par_rs::RepairError::*;
    // Deliberately exhaustive, proving the incumbent error enum was not extended.
    match error {
        NoMainPacket => "main",
        IncompleteMetadata { .. } => "metadata",
        NotFinalized => "finalize",
        WrongSet { .. } => "set",
        NotEnoughRecovery { .. } => "recovery",
        StreamingMemoryLimit { .. } => "streaming",
        RecoveryMemoryLimit { .. } => "matrix",
        Singular => "singular",
        VerificationFailed { .. } => "verify",
        Io { .. } => "io",
        Cancelled => "cancelled",
        UnknownFile(_) => "file",
    }
}
#[derive(Debug, PartialEq, Eq)]
struct PublicState {
    files: String,
    locations: Vec<Option<par_rs::repairer::BlockLocation>>,
    disks: Vec<PathBuf>,
}
fn state(r: &Par2Repairer) -> PublicState {
    PublicState {
        files: format!("{:?}", r.source_files()),
        locations: r.block_locations().to_vec(),
        disks: r.disk_files().to_vec(),
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    files: Vec<(String, par_rs::FileStatus, u32, bool, bool)>,
    locations: Vec<Option<(bool, u64)>>,
}
fn outcome(r: &Par2Repairer, donor: &std::path::Path) -> Outcome {
    Outcome {
        files: r
            .source_files()
            .iter()
            .map(|f| {
                (
                    f.target_filename.clone(),
                    f.status.clone(),
                    f.available_blocks,
                    f.complete_file.as_deref() == Some(donor),
                    f.target_exists,
                )
            })
            .collect(),
        locations: r
            .block_locations()
            .iter()
            .map(|l| {
                l.as_ref()
                    .map(|l| (r.disk_files()[l.file] == donor, l.offset))
            })
            .collect(),
    }
}

#[test]
fn ample_budget_matches_both_native_policies_on_real_donor_shapes() {
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        for (original, donor, slice) in [
            (
                b"abcdefghijkl".as_slice(),
                b"PREFIX!abcdefghijkl".as_slice(),
                4,
            ),
            (b"abcdefghijkl", b"abcdijklefgh", 4),
            (b"abcdYZ", b"abcdYZ", 4),
            (b"q\0", b"q", 4),
        ] {
            let mut expected = None;
            for bounded in [false, true] {
                let mut f = Fixture::with(&[("a.bin", original)], slice, 0, literal_options());
                let path = f.donor("D", donor);
                let mut budget = DonorReadBudget::new(1 << 20);
                let count = if bounded {
                    f.engine
                        .add_extra_file_with_read_budget(
                            &path,
                            policy,
                            &mut budget,
                            None,
                            &mut NullObserver,
                        )
                        .unwrap()
                } else if policy == ExtraFileScanPolicy::Full {
                    f.engine.add_extra_file(&path, &mut NullObserver).unwrap()
                } else {
                    f.engine
                        .add_extra_file_with_policy(&path, policy, &mut NullObserver)
                        .unwrap()
                };
                let got = (count, outcome(&f.engine, &path));
                if bounded {
                    assert_eq!(Some(got), expected);
                    assert!(budget.charged_bytes() > 0);
                } else {
                    expected = Some(got);
                }
                assert_eq!(std::fs::read(path).unwrap(), donor);
            }
        }
    }
}
#[test]
fn exact_and_per_call_under_refusal_preserve_real_state_and_allow_retry() {
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        let mut f = Fixture::new();
        let before = state(&f.engine);
        let path = f.dir.join("D");
        let mut budget = DonorReadBudget::new(16);
        let error = f
            .engine
            .add_extra_file_with_read_budget(
                &path,
                policy,
                &mut budget,
                Some(15),
                &mut NullObserver,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            DonorReadError::Limit {
                scope: par_rs::DonorReadScope::PerCall,
                limit_bytes: 15,
                charged_bytes: 0,
                request_bytes: 16
            }
        ));
        assert_eq!(state(&f.engine), before);
        assert_eq!(budget.charged_bytes(), 0);
        assert_eq!(
            f.engine
                .add_extra_file_with_read_budget(
                    &path,
                    policy,
                    &mut budget,
                    Some(16),
                    &mut NullObserver
                )
                .unwrap(),
            1
        );
        assert_eq!(budget.limit_bytes(), 16);
        assert_eq!(budget.remaining_bytes(), 0);
        assert_eq!(std::fs::read(path).unwrap(), b"abcdefghABCDEFGH");
    }
}
#[test]
fn shared_aggregate_spans_donors_and_retries_without_refunding_or_resetting() {
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        let mut f = Fixture::with(
            &[("a.bin", b"abcdEFGH"), ("b.bin", b"ijklMNOP")],
            4,
            0,
            literal_options(),
        );
        let a = f.donor("D1", b"abcd");
        let b = f.donor("D2", b"ijkl");
        let c = f.donor("D3", b"ijklMNOP");
        let mut budget = DonorReadBudget::new(8);
        assert_eq!(
            f.engine
                .add_extra_file_with_read_budget(
                    &a,
                    policy,
                    &mut budget,
                    Some(4),
                    &mut NullObserver
                )
                .unwrap(),
            1
        );
        let prior = state(&f.engine);
        assert!(matches!(
            f.engine.add_extra_file_with_read_budget(
                &b,
                policy,
                &mut budget,
                Some(3),
                &mut NullObserver
            ),
            Err(DonorReadError::Limit {
                scope: par_rs::DonorReadScope::PerCall,
                ..
            })
        ));
        assert_eq!(state(&f.engine), prior);
        assert_eq!(budget.charged_bytes(), 4);
        assert_eq!(
            f.engine
                .add_extra_file_with_read_budget(&b, policy, &mut budget, None, &mut NullObserver)
                .unwrap(),
            1
        );
        assert_eq!(budget.charged_bytes(), 8);
        let prior = state(&f.engine);
        assert!(matches!(
            f.engine.add_extra_file_with_read_budget(
                &c,
                policy,
                &mut budget,
                None,
                &mut NullObserver
            ),
            Err(DonorReadError::Limit {
                scope: par_rs::DonorReadScope::Aggregate,
                ..
            })
        ));
        assert_eq!(state(&f.engine), prior);
        assert_eq!(
            f.engine
                .add_extra_file_with_read_budget(
                    &a,
                    policy,
                    &mut budget,
                    Some(0),
                    &mut NullObserver
                )
                .unwrap(),
            0
        );
        assert_eq!(budget.charged_bytes(), 8);
    }
}
#[test]
fn empty_donor_identity_costs_zero_and_never_fabricates_nonempty_eof() {
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        let mut f = Fixture::with(&[("empty.bin", b"")], 4, 0, literal_options());
        let path = f.donor("D", b"");
        let mut budget = DonorReadBudget::new(0);
        assert_eq!(
            f.engine
                .add_extra_file_with_read_budget(
                    &path,
                    policy,
                    &mut budget,
                    Some(0),
                    &mut NullObserver
                )
                .unwrap(),
            0
        );
        assert_eq!(budget.charged_bytes(), 0);
        assert_eq!(f.engine.source_files()[0].complete_file, Some(path));
    }
}
#[test]
fn no_ifsc_complete_identity_matches_incumbent_full_and_ordered_counts() {
    use par_rs::packet::{PacketIter, ScanOptions, TYPE_IFSC};
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        for bounded in [false, true] {
            let mut f = Fixture::with(&[("a.bin", b"abcdefgh")], 4, 0, literal_options());
            let index = f.dir.join("set.par2");
            let original = std::fs::read(&index).unwrap();
            let mut metadata = Vec::new();
            for p in PacketIter::new(original.as_slice(), ScanOptions::FULL) {
                let p = p.unwrap();
                if p.header.packet_type != TYPE_IFSC {
                    metadata.extend_from_slice(
                        &original[p.offset as usize..(p.offset + p.header.length) as usize],
                    );
                }
            }
            std::fs::write(index, metadata).unwrap();
            f.reload();
            let path = f.donor("D", b"abcdefgh");
            let mut budget = DonorReadBudget::new(8);
            let count = if bounded {
                f.engine
                    .add_extra_file_with_read_budget(
                        &path,
                        policy,
                        &mut budget,
                        None,
                        &mut NullObserver,
                    )
                    .unwrap()
            } else {
                f.engine
                    .add_extra_file_with_policy(&path, policy, &mut NullObserver)
                    .unwrap()
            };
            assert_eq!(
                count,
                if policy == ExtraFileScanPolicy::Full {
                    0
                } else {
                    2
                }
            );
            assert_eq!(f.engine.source_files()[0].available_blocks, 2);
            assert_eq!(f.engine.source_files()[0].complete_file, Some(path));
            if bounded {
                assert_eq!(budget.charged_bytes(), 8);
            }
        }
    }
}
#[test]
fn outside_base_perfect_donor_plus_rs_repairs_exact_bytes_and_retains_donor() {
    let files = [
        ("a.bin", b"abcdefghABCDEFGH".as_slice()),
        ("b.bin", b"12345678!@#$%^&*".as_slice()),
    ];
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        let mut f = Fixture::with(&files, 16, 1, literal_options());
        f.donor("b.bin", b"QQQQQQQQQQQQQQQQ");
        f.reload();
        let donor = f.outside(files[0].1);
        let mut budget = DonorReadBudget::new(16);
        assert_eq!(
            f.engine
                .add_extra_file_with_read_budget(
                    &donor,
                    policy,
                    &mut budget,
                    None,
                    &mut NullObserver
                )
                .unwrap(),
            1
        );
        assert!(matches!(
            f.engine.repair(&mut NullObserver).unwrap(),
            par_rs::RepairResult::Repaired { .. }
        ));
        for (name, bytes) in files {
            assert_eq!(std::fs::read(f.dir.join(name)).unwrap(), bytes);
        }
        assert_eq!(std::fs::read(&donor).unwrap(), files[0].1);
        assert_eq!(
            std::fs::read(f.dir.join("b.bin.1")).unwrap(),
            b"QQQQQQQQQQQQQQQQ"
        );
        assert_eq!(budget.charged_bytes(), 16);
    }
}
#[test]
fn current_cancel_token_is_used_after_repairer_replacement_and_before_apply() {
    struct Cancel(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl par_rs::RepairObserver for Cancel {
        fn progress(&mut self, p: u32, _: &str) {
            if p == 1000 {
                self.0.store(true, Ordering::Relaxed);
            }
        }
    }
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        let mut f = Fixture::new();
        let old = f.engine.cancel_token();
        f.reload();
        old.store(true, Ordering::Relaxed);
        let path = f.dir.join("D");
        let mut budget = DonorReadBudget::new(32);
        let before = state(&f.engine);
        let current = f.engine.cancel_token();
        let mut cancel = Cancel(current.clone());
        assert!(matches!(
            f.engine
                .add_extra_file_with_read_budget(&path, policy, &mut budget, None, &mut cancel),
            Err(DonorReadError::Repair(par_rs::RepairError::Cancelled))
        ));
        assert_eq!(state(&f.engine), before);
        assert_eq!(budget.charged_bytes(), 16);
        current.store(false, Ordering::Relaxed);
        assert_eq!(
            f.engine
                .add_extra_file_with_read_budget(
                    &path,
                    policy,
                    &mut budget,
                    None,
                    &mut NullObserver
                )
                .unwrap(),
            1
        );
        assert_eq!(budget.charged_bytes(), 32);
        let mut fresh = Fixture::new();
        fresh.engine.cancel();
        let mut budget = DonorReadBudget::new(16);
        let before = state(&fresh.engine);
        assert!(matches!(
            fresh.engine.add_extra_file_with_read_budget(
                &fresh.dir.join("D"),
                policy,
                &mut budget,
                None,
                &mut NullObserver
            ),
            Err(DonorReadError::Repair(par_rs::RepairError::Cancelled))
        ));
        assert_eq!(budget.charged_bytes(), 0);
        assert_eq!(state(&fresh.engine), before);
    }
}
#[test]
fn real_shrink_during_required_reads_preserves_state_and_unmarked_retry() {
    struct Shrink {
        path: PathBuf,
        fired: bool,
    }
    impl par_rs::RepairObserver for Shrink {
        fn progress(&mut self, p: u32, _: &str) {
            if p > 0 && !self.fired {
                self.fired = true;
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&self.path)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
            }
        }
    }
    let cap = 64 << 10;
    let bytes = [vec![b'x'; cap], vec![b'y'; cap], vec![b'z'; cap]].concat();
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        let mut f = Fixture::with(&[("a.bin", &bytes)], cap, 0, literal_options());
        let path = f.donor("D", &bytes);
        let before = state(&f.engine);
        let mut budget = DonorReadBudget::new(u64::MAX);
        let mut shrink = Shrink {
            path: path.clone(),
            fired: false,
        };
        let error = f
            .engine
            .add_extra_file_with_read_budget(&path, policy, &mut budget, None, &mut shrink)
            .unwrap_err();
        assert!(
            matches!(error,DonorReadError::Repair(par_rs::RepairError::Io {source,..}) if source.kind()==std::io::ErrorKind::UnexpectedEof)
        );
        assert!(shrink.fired);
        assert_eq!(state(&f.engine), before);
        assert_eq!(budget.charged_bytes(), (2 * cap) as u64);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            f.engine
                .add_extra_file_with_read_budget(
                    &path,
                    policy,
                    &mut budget,
                    None,
                    &mut NullObserver
                )
                .unwrap(),
            3
        );
        assert_eq!(budget.charged_bytes(), (5 * cap) as u64);
    }
}
#[test]
fn native_error_matching_and_skips_keep_public_contracts() {
    let f = Fixture::new();
    let mut unfinalized = Par2Repairer::new(&f.dir, literal_options());
    let mut budget = DonorReadBudget::new(0);
    let error = unfinalized
        .add_extra_file_with_read_budget(
            &f.dir.join("absent"),
            ExtraFileScanPolicy::Full,
            &mut budget,
            None,
            &mut NullObserver,
        )
        .unwrap_err();
    let DonorReadError::Repair(error) = error else {
        panic!("incumbent error expected")
    };
    assert_eq!(old_error_kind(&error), "finalize");
    assert_eq!(budget.charged_bytes(), 0);
    let mut f = Fixture::new();
    std::fs::write(f.dir.join("a.bin"), b"abcdefghABCDEFGH").unwrap();
    f.reload();
    assert_eq!(
        f.engine
            .add_extra_file_with_read_budget(
                &f.dir.join("absent"),
                ExtraFileScanPolicy::Full,
                &mut budget,
                Some(0),
                &mut NullObserver
            )
            .unwrap(),
        0
    );
    assert_eq!(budget.charged_bytes(), 0);
}
