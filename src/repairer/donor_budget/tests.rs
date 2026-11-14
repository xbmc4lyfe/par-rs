// Licensed under GPL-2.0-or-later, matching Cargo.toml.
use super::*;
use std::collections::VecDeque;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Attempt {
    offset: u64,
    requested: usize,
    result: Result<usize, io::ErrorKind>,
}
struct Script {
    bytes: Vec<u8>,
    steps: RefCell<VecDeque<io::Result<usize>>>,
    calls: RefCell<Vec<Attempt>>,
    cancel_on: Option<(Arc<AtomicBool>, usize)>,
}
impl Script {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            steps: RefCell::new(VecDeque::new()),
            calls: RefCell::new(Vec::new()),
            cancel_on: None,
        }
    }
    fn steps(self, steps: impl IntoIterator<Item = io::Result<usize>>) -> Self {
        *self.steps.borrow_mut() = steps.into_iter().collect();
        self
    }
}
impl Primitive for Script {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.steps.borrow_mut().pop_front().unwrap_or(Ok(buf.len()));
        self.calls.borrow_mut().push(Attempt {
            offset,
            requested: buf.len(),
            result: result.as_ref().copied().map_err(io::Error::kind),
        });
        if let Some((flag, call)) = &self.cancel_on
            && self.calls.borrow().len() == *call
        {
            flag.store(true, Ordering::Relaxed);
        }
        let n = result?;
        buf[..n].copy_from_slice(&self.bytes[offset as usize..offset as usize + n]);
        Ok(n)
    }
}
fn charged(source: &Metered<'_, Script>) -> u64 {
    source.state.borrow().budget.charged_bytes()
}
fn io_kind(error: DonorReadError, kind: io::ErrorKind) {
    assert!(
        matches!(error,DonorReadError::Repair(RepairError::Io {source,..}) if source.kind()==kind)
    );
}
#[test]
fn exposed_short_and_interrupted_attempts_charge_eighteen_not_eight() {
    let primitive =
        Script::new(b"abcdefgh").steps([Ok(3), Err(io::ErrorKind::Interrupted.into()), Ok(5)]);
    let mut budget = DonorReadBudget::new(18);
    let cancel = AtomicBool::new(false);
    let source = Metered::new(primitive, &mut budget, Some(18), &cancel);
    let mut bytes = [0; 8];
    source.read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"abcdefgh");
    assert_eq!(
        *source.primitive.calls.borrow(),
        [
            Attempt {
                offset: 0,
                requested: 8,
                result: Ok(3)
            },
            Attempt {
                offset: 3,
                requested: 5,
                result: Err(io::ErrorKind::Interrupted)
            },
            Attempt {
                offset: 3,
                requested: 5,
                result: Ok(5)
            }
        ]
    );
    eprintln!(
        "exposed primitive requests/returns: {:?}; charged={}",
        source.primitive.calls.borrow(),
        charged(&source)
    );
    drop(source);
    assert_eq!(budget.charged_bytes(), 18);
    assert_eq!(budget.remaining_bytes(), 0);
}
#[test]
fn exact_under_zero_and_both_scope_refusals_do_not_issue_or_partly_charge() {
    for (total, call, scope) in [
        (7, None, DonorReadScope::Aggregate),
        (0, Some(0), DonorReadScope::Aggregate),
        (8, Some(7), DonorReadScope::PerCall),
    ] {
        let mut budget = DonorReadBudget::new(total);
        let cancel = AtomicBool::new(false);
        let source = Metered::new(Script::new(b"abcdefgh"), &mut budget, call, &cancel);
        assert!(source.read_at(0, &mut [0; 8]).is_err());
        assert!(
            matches!(source.resolve(Ok(())),Err(DonorReadError::Limit {scope:s,request_bytes:8,charged_bytes:0,..}) if s==scope)
        );
        assert!(source.primitive.calls.borrow().is_empty());
        assert_eq!(charged(&source), 0);
        assert_eq!(source.state.borrow().call_charged, 0);
    }
    let mut budget = DonorReadBudget::new(8);
    let cancel = AtomicBool::new(false);
    let source = Metered::new(Script::new(b"abcdefgh"), &mut budget, Some(8), &cancel);
    source.read_at(8, &mut []).unwrap();
    assert_eq!(charged(&source), 0);
    assert!(source.primitive.calls.borrow().is_empty());
    source.read_at(0, &mut [0; 8]).unwrap();
    assert_eq!(charged(&source), 8);
    assert_eq!(source.state.borrow().call_charged, 8);
}
#[test]
fn second_request_refusal_keeps_both_previous_counters() {
    let mut budget = DonorReadBudget::new(8);
    let cancel = AtomicBool::new(false);
    let source = Metered::new(Script::new(b"abcdefgh"), &mut budget, Some(6), &cancel);
    source.read_at(0, &mut [0; 4]).unwrap();
    assert!(source.read_at(4, &mut [0; 4]).is_err());
    assert!(matches!(
        source.resolve(Ok(())),
        Err(DonorReadError::Limit {
            scope: DonorReadScope::PerCall,
            charged_bytes: 4,
            request_bytes: 4,
            ..
        })
    ));
    assert_eq!(charged(&source), 4);
    assert_eq!(source.state.borrow().call_charged, 4);
    assert_eq!(source.primitive.calls.borrow().len(), 1);
}
#[test]
fn failed_retry_spends_attempts_and_a_new_call_reuses_remaining_aggregate() {
    let mut budget = DonorReadBudget::new(17);
    let cancel = AtomicBool::new(false);
    let source = Metered::new(
        Script::new(b"abcdefgh").steps([Ok(3), Err(io::ErrorKind::Interrupted.into()), Ok(5)]),
        &mut budget,
        None,
        &cancel,
    );
    assert!(source.read_at(0, &mut [0; 8]).is_err());
    assert!(matches!(
        source.resolve(Ok(())),
        Err(DonorReadError::Limit {
            charged_bytes: 13,
            request_bytes: 5,
            ..
        })
    ));
    assert_eq!(source.primitive.calls.borrow().len(), 2);
    drop(source);
    let source = Metered::new(Script::new(b"abcd"), &mut budget, Some(4), &cancel);
    source.read_at(0, &mut [0; 4]).unwrap();
    drop(source);
    assert_eq!(budget.charged_bytes(), 17);
}
#[test]
fn terminal_io_and_eof_keep_full_charge_and_original_first_fault() {
    for kind in [
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::PermissionDenied,
    ] {
        let mut budget = DonorReadBudget::new(100);
        let cancel = AtomicBool::new(false);
        let step = if kind == io::ErrorKind::UnexpectedEof {
            Ok(0)
        } else {
            Err(io::Error::new(kind, "first primitive fault"))
        };
        let source = Metered::new(
            Script::new(b"abcdefgh").steps([step]),
            &mut budget,
            None,
            &cancel,
        );
        assert!(source.read_at(0, &mut [0; 8]).is_err());
        cancel.store(true, Ordering::Relaxed);
        assert!(source.read_at(0, &mut [0; 1]).is_err());
        assert_eq!(source.primitive.calls.borrow().len(), 1);
        assert_eq!(charged(&source), 8);
        let error = source
            .resolve::<()>(Err(RepairError::Cancelled))
            .unwrap_err();
        if kind == io::ErrorKind::PermissionDenied {
            assert!(error.to_string().contains("first primitive fault"));
        }
        io_kind(error, kind);
    }
}
#[test]
fn range_and_counter_overflow_are_typed_before_any_primitive() {
    let cancel = AtomicBool::new(false);
    for (offset, len, overflow) in [(u64::MAX - 2, 4, true), (4, 5, false), (9, 0, false)] {
        let mut budget = DonorReadBudget::new(u64::MAX);
        let source = Metered::new(Script::new(b"abcdefgh"), &mut budget, None, &cancel);
        assert!(source.read_at(offset, &mut vec![0; len]).is_err());
        let error = source.resolve(Ok(())).unwrap_err();
        if overflow {
            assert!(
                matches!(error,DonorReadError::CounterOverflow {counter:"donor read range",value,request_bytes:4} if value==offset)
            );
        } else {
            io_kind(error, io::ErrorKind::UnexpectedEof);
        }
        assert_eq!(charged(&source), 0);
        assert!(source.primitive.calls.borrow().is_empty());
    }
    // Deliberately simulated counter boundaries; not physical exabyte reads.
    for call_overflow in [false, true] {
        let mut budget = DonorReadBudget::new(u64::MAX);
        if !call_overflow {
            budget.charged = u64::MAX;
        }
        let source = Metered::new(Script::new(b"x"), &mut budget, None, &cancel);
        if call_overflow {
            source.state.borrow_mut().call_charged = u64::MAX;
        }
        assert!(source.read_at(0, &mut [0]).is_err());
        assert!(matches!(
            source.resolve(Ok(())),
            Err(DonorReadError::CounterOverflow {
                request_bytes: 1,
                ..
            })
        ));
        assert!(source.primitive.calls.borrow().is_empty());
    }
}
#[test]
fn cancellation_before_read_and_between_exposed_retries_never_refunds() {
    let cancel = Arc::new(AtomicBool::new(true));
    let mut budget = DonorReadBudget::new(100);
    let source = Metered::new(Script::new(b"abcdefgh"), &mut budget, None, &cancel);
    assert!(source.read_at(0, &mut [0; 8]).is_err());
    assert_eq!(charged(&source), 0);
    assert!(source.primitive.calls.borrow().is_empty());
    assert!(matches!(
        source.resolve(Ok(())),
        Err(DonorReadError::Repair(RepairError::Cancelled))
    ));
    drop(source);
    for step in [Ok(3), Err(io::ErrorKind::Interrupted.into())] {
        cancel.store(false, Ordering::Relaxed);
        let mut primitive = Script::new(b"abcdefgh").steps([step]);
        primitive.cancel_on = Some((cancel.clone(), 1));
        let source = Metered::new(primitive, &mut budget, None, &cancel);
        assert!(source.read_at(0, &mut [0; 8]).is_err());
        assert_eq!(source.primitive.calls.borrow().len(), 1);
        assert!(matches!(
            source.resolve(Ok(())),
            Err(DonorReadError::Repair(RepairError::Cancelled))
        ));
    }
    assert_eq!(budget.charged_bytes(), 16);
}

fn engine(bytes: &[u8], ifsc: bool, slice: usize) -> Par2Repairer {
    let set = crate::build_set(
        "set",
        &[("a.bin", bytes)],
        &crate::SetOptions {
            slice_size: slice,
            recovery_blocks: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let mut r = Par2Repairer::new(
        "targets",
        RepairOptions {
            num_threads: 1,
            scan_buffer: crate::scanner::MIN_BUFFER,
            mem_limit_bytes: 16 << 20,
            ..Default::default()
        },
    );
    r.packets =
        crate::packet::load_par2_bytes(&set.index, crate::packet::ScanOptions::FULL).unwrap();
    if !ifsc {
        r.packets.ifscs.clear();
    }
    r.finalize().unwrap();
    r
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    files: String,
    locations: Vec<Option<BlockLocation>>,
    disks: Vec<PathBuf>,
    index: HashMap<PathBuf, usize>,
    scanned: HashSet<PathBuf>,
}
fn snapshot(r: &Par2Repairer) -> Snapshot {
    Snapshot {
        files: format!("{:?}", r.files),
        locations: r.locations.clone(),
        disks: r.disk_files.clone(),
        index: r.disk_index.clone(),
        scanned: r.scanned_extra.clone(),
    }
}
fn admit(
    r: &mut Par2Repairer,
    policy: ExtraFileScanPolicy,
    primitive: Script,
    budget: &mut DonorReadBudget,
) -> (Result<usize, DonorReadError>, Vec<Attempt>) {
    let cancel = r.cancel.clone();
    let source = Metered::new(primitive, budget, None, &cancel);
    let result = r.admit_budgeted_source(Path::new("D"), policy, &source, &mut NullObserver);
    let calls = source.primitive.calls.borrow().clone();
    (result, calls)
}
#[test]
fn required_prefix_complete_identity_and_fallback_faults_preserve_every_state_field() {
    let cap = crate::scanner::MIN_BUFFER;
    let data = [vec![b'x'; cap], vec![b'y'; cap], vec![b'z'; cap]].concat();
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        for ifsc in [false, true] {
            for fail_after in [1, 2] {
                let mut r = engine(&data, ifsc, cap);
                let before = snapshot(&r);
                let mut steps: Vec<_> = (0..fail_after).map(|_| Ok(cap)).collect();
                steps.push(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "required stage fault",
                )));
                let mut budget = DonorReadBudget::new(u64::MAX);
                let (result, calls) =
                    admit(&mut r, policy, Script::new(&data).steps(steps), &mut budget);
                io_kind(result.unwrap_err(), io::ErrorKind::PermissionDenied);
                assert_eq!(snapshot(&r), before);
                assert_eq!(
                    budget.charged_bytes(),
                    calls.iter().map(|c| c.requested as u64).sum()
                );
                let (result, _) = admit(&mut r, policy, Script::new(&data), &mut budget);
                // Native Full materializes no-IFSC locations during identity handling,
                // outside its previously missing checksum-match return counter.
                let count = if policy == ExtraFileScanPolicy::Full && !ifsc {
                    0
                } else {
                    3
                };
                assert_eq!(result.unwrap(), count);
                assert_eq!(r.files[0].available_blocks, 3);
                assert!(r.files[0].complete_file.is_some());
                assert!(r.scanned_extra.contains(Path::new("D")));
            }
        }
    }
}
#[test]
fn cap_failure_after_a_staged_prefix_or_full_find_admits_nothing() {
    let cap = crate::scanner::MIN_BUFFER;
    let data = [vec![b'x'; cap], vec![b'y'; cap], vec![b'z'; cap]].concat();
    for policy in [
        ExtraFileScanPolicy::Full,
        ExtraFileScanPolicy::OrderedPrefix,
    ] {
        let mut r = engine(&data, true, cap);
        let before = snapshot(&r);
        let mut budget = DonorReadBudget::new(cap as u64);
        let (result, calls) = admit(&mut r, policy, Script::new(&data), &mut budget);
        assert!(matches!(result, Err(DonorReadError::Limit { .. })));
        assert_eq!(calls.len(), 1);
        assert_eq!(budget.charged_bytes(), cap as u64);
        assert_eq!(snapshot(&r), before);
    }
}
#[test]
fn ordered_partial_stops_without_hash_completion_and_prefetch_refusal_is_honest() {
    let cap = crate::scanner::MIN_BUFFER;
    let data = [vec![b'x'; cap], vec![b'y'; cap], vec![b'z'; cap]].concat();
    let donor = [vec![b'x'; cap], vec![b'q'; cap], vec![b'z'; cap]].concat();
    let mut r = engine(&data, true, cap);
    let before = snapshot(&r);
    let mut tiny = DonorReadBudget::new(16);
    let (result, calls) = admit(
        &mut r,
        ExtraFileScanPolicy::OrderedPrefix,
        Script::new(&donor),
        &mut tiny,
    );
    assert!(
        matches!(result,Err(DonorReadError::Limit {request_bytes,..}) if request_bytes==cap as u64)
    );
    assert!(calls.is_empty());
    assert_eq!(snapshot(&r), before);
    let mut budget = DonorReadBudget::new((2 * cap) as u64);
    let (result, calls) = admit(
        &mut r,
        ExtraFileScanPolicy::OrderedPrefix,
        Script::new(&donor),
        &mut budget,
    );
    assert_eq!(result.unwrap(), 1);
    assert_eq!(calls.len(), 2);
    assert_eq!(budget.charged_bytes(), (2 * cap) as u64);
    assert!(r.files[0].complete_file.is_none());
}
#[test]
fn full_shifted_candidate_and_outgoing_rereads_share_the_same_ledger() {
    let cap = crate::scanner::MIN_BUFFER;
    let data = [vec![b'x'; cap], vec![b'y'; cap]].concat();
    let donor = [b"prefix!".as_slice(), data.as_slice()].concat();
    let mut r = engine(&data, true, cap);
    let mut budget = DonorReadBudget::new(u64::MAX);
    let (result, calls) = admit(
        &mut r,
        ExtraFileScanPolicy::Full,
        Script::new(&donor),
        &mut budget,
    );
    assert_eq!(result.unwrap(), 2);
    assert_eq!(r.locations[0].as_ref().unwrap().offset, 7);
    assert_eq!(
        budget.charged_bytes(),
        calls.iter().map(|c| c.requested as u64).sum()
    );
    assert!(budget.charged_bytes() > donor.len() as u64);
    eprintln!(
        "Full shifted primitive requests/returns: {calls:?}; charged={}",
        budget.charged_bytes()
    );
}
#[test]
fn actual_hash_completion_swallow_still_blocks_full_admission_with_original_fault() {
    let cap = crate::scanner::MIN_BUFFER;
    let data = vec![b'x'; 2 * cap];
    let mut r = engine(&data, true, cap);
    let before = snapshot(&r);
    let mut budget = DonorReadBudget::new(u64::MAX);
    let cancel = r.cancel.clone();
    let source = Metered::new(
        Script::new(&data).steps([
            Ok(cap),
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "hash completion first fault",
            )),
        ]),
        &mut budget,
        None,
        &cancel,
    );
    let mut window = crate::scanner::Window::new(&source, cap, true);
    assert!(window.hash_until(cap as u64, None).unwrap());
    let got = window
        .checksums(0, cap as u64, |_| true, None)
        .unwrap()
        .unwrap();
    let expected = &r.checksums[0].as_ref().unwrap()[0];
    assert_eq!(got, (expected.crc32, expected.md5));
    let mut report = ScanReport::default();
    report.found.push(crate::scanner::FoundBlock {
        offset: 0,
        block: BlockRef {
            file_index: 0,
            block_index: 0,
        },
    });
    report.file_hashes = window.finish_hash(); // Actual helper discards the temporary I/O error.
    assert!(report.file_hashes.is_none());
    let result = r.finish_budgeted_admission(
        Path::new("D"),
        &source,
        Ok(Staged::Full(report)),
        &mut NullObserver,
    );
    let error = result.unwrap_err();
    assert!(error.to_string().contains("hash completion first fault"));
    io_kind(error, io::ErrorKind::PermissionDenied);
    assert_eq!(source.primitive.calls.borrow().len(), 2);
    assert_eq!(charged(&source), (2 * cap) as u64);
    assert_eq!(snapshot(&r), before);
}
#[test]
fn cancellation_before_apply_preserves_staged_full_and_ordered_reports() {
    struct Cancel(Arc<AtomicBool>);
    impl RepairObserver for Cancel {
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
        let mut r = engine(b"abcdefgh", true, 4);
        let before = snapshot(&r);
        let mut budget = DonorReadBudget::new(100);
        let cancel = r.cancel.clone();
        let source = Metered::new(Script::new(b"abcdefgh"), &mut budget, None, &cancel);
        assert!(matches!(
            r.admit_budgeted_source(Path::new("D"), policy, &source, &mut Cancel(cancel.clone())),
            Err(DonorReadError::Repair(RepairError::Cancelled))
        ));
        assert_eq!(snapshot(&r), before);
        assert_eq!(charged(&source), 8);
    }
}
#[test]
fn real_opened_file_shrink_is_eof_with_conservative_short_attempt_charges() {
    let dir = std::env::temp_dir().join(format!("par-rs-budget-shrink-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("D");
    std::fs::write(&path, b"abcdefgh").unwrap();
    let file = DonorFile::open(&path).unwrap();
    std::fs::write(&path, b"abc").unwrap();
    let mut budget = DonorReadBudget::new(100);
    let cancel = AtomicBool::new(false);
    let source = Metered::new(file, &mut budget, None, &cancel);
    assert_eq!(source.source_len(), 8);
    assert!(source.read_at(0, &mut [0; 8]).is_err());
    io_kind(
        source.resolve(Ok(())).unwrap_err(),
        io::ErrorKind::UnexpectedEof,
    );
    assert_eq!(source.state.borrow().budget.charged_bytes(), 13);
    drop(source);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn locked_seek_read_equivalent_is_checked_on_the_native_test_host() {
    struct Locked(DonorFile);
    impl Primitive for Locked {
        fn len(&self) -> u64 {
            self.0.source.source_len()
        }
        fn read_once(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read_locked(offset, buf)
        }
    }
    let dir = std::env::temp_dir().join(format!("par-rs-budget-locked-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("D");
    std::fs::write(&path, b"abcdefgh").unwrap();
    let mut budget = DonorReadBudget::new(5);
    let cancel = AtomicBool::new(false);
    let source = Metered::new(
        Locked(DonorFile::open(&path).unwrap()),
        &mut budget,
        None,
        &cancel,
    );
    let mut bytes = [0; 3];
    source.read_at(2, &mut bytes).unwrap();
    assert_eq!(&bytes, b"cde");
    let mut bytes = [0; 2];
    source.read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"ab");
    drop(source);
    assert_eq!(budget.charged_bytes(), 5);
    std::fs::remove_dir_all(dir).unwrap();
}
