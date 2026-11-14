use super::*;
use crate::create::{SetOptions, build_set};
use crate::packet::{ScanOptions, load_par2_bytes};
use std::cell::RefCell;

fn engine(sources: &[(&[u8], bool)], slice: usize) -> Par2Repairer {
    let names: Vec<_> = (0..sources.len()).map(|n| format!("file{n}")).collect();
    let inputs: Vec<_> = names
        .iter()
        .zip(sources)
        .map(|(name, (bytes, _))| (name.as_str(), *bytes))
        .collect();
    let set = build_set(
        "set",
        &inputs,
        &SetOptions {
            slice_size: slice,
            recovery_blocks: 0,
            ..SetOptions::default()
        },
    )
    .unwrap();
    let mut repairer = Par2Repairer::new(
        "targets",
        RepairOptions {
            scan_buffer: MIN_BUFFER,
            num_threads: 1,
            mem_limit_bytes: 16 << 20,
            ..RepairOptions::default()
        },
    );
    repairer.packets = load_par2_bytes(&set.index, ScanOptions::FULL).unwrap();
    // Fix the admitted Main order explicitly; these fixtures carry no RS payloads.
    let ids: Vec<_> = names
        .iter()
        .map(|name| {
            repairer
                .packets
                .file_descs
                .values()
                .find(|fd| fd.name == name.as_bytes())
                .unwrap()
                .file_id
        })
        .collect();
    repairer.packets.main.as_mut().unwrap().recoverable_file_ids = ids.clone();
    for (id, (_, ifsc)) in ids.iter().zip(sources) {
        if !ifsc {
            repairer.packets.ifscs.remove(id);
        }
    }
    repairer.finalize().unwrap();
    repairer
}

type Located = (u32, u32, u64);
type PrefixCase<'a> = (&'a [u8], &'a [u8], &'a [Located], bool);

fn accepted(report: &OrderedReport) -> Vec<Located> {
    report
        .accepted
        .iter()
        .map(|found| {
            (
                found.block.file_index,
                found.block.block_index,
                found.offset,
            )
        })
        .collect()
}
fn scan(repairer: &Par2Repairer, bytes: &[u8]) -> OrderedReport {
    repairer
        .scan_ordered_source(bytes, None, &mut |_| {})
        .unwrap()
}
fn seed(repairer: &mut Par2Repairer, file: u32, block: u32, offset: u64) {
    let disk = repairer.disk_file_index(Path::new("E"));
    assert!(repairer.set_location(
        BlockRef {
            file_index: file,
            block_index: block
        },
        BlockLocation { file: disk, offset }
    ));
}

#[test]
fn literal_prefix_and_short_payload_cases() {
    let cases: &[PrefixCase<'_>] = &[
        (b"abcdefgh", b"abcdefgh", &[(0, 0, 0), (0, 1, 4)], true),
        (b"abcdefgh", b"abcdijkl", &[(0, 0, 0)], false),
        (b"YZ", b"YZ", &[(0, 0, 0)], true),
        (b"q\0", b"q", &[], false),
        (b"abcdefghijkl", b"abcdijklefgh", &[(0, 0, 0)], false),
        (b"abcdefgh", b"1234567abcdefgh", &[], false),
        (b"abcdYZ", b"abcdYZ", &[(0, 0, 0), (0, 1, 4)], true),
        (b"abcdYZ", b"abcdYZ!!", &[(0, 0, 0), (0, 1, 4)], false),
        (b"abcdq\0", b"abcdq", &[(0, 0, 0)], false),
    ];
    for &(original, donor, want, complete) in cases {
        let repairer = engine(&[(original, true)], 4);
        let report = scan(&repairer, donor);
        assert_eq!(accepted(&report), want, "{original:?} / {donor:?}");
        assert_eq!(report.complete, complete.then_some(0));
        assert_eq!(report.file_hashes.is_some(), complete);
    }
}

#[test]
fn equal_cross_file_prefix_has_one_owner() {
    let repairer = engine(&[(b"abcdefgh", true), (b"abcdijkl", true)], 4);
    let report = scan(&repairer, b"abcdijkl");
    assert_eq!(accepted(&report), [(0, 0, 0)]);
    assert!(report.complete.is_none());
    assert!(report.file_hashes.is_none());
}

#[test]
fn complete_or_used_equal_candidates_yield_to_unused_source() {
    for complete in [false, true] {
        let mut repairer = engine(&[(b"abcdefgh", true), (b"abcdijkl", true)], 4);
        seed(&mut repairer, 0, 0, 0);
        if complete {
            seed(&mut repairer, 0, 1, 4);
            repairer.files[0].complete_file = Some(PathBuf::from("E"));
        }
        let report = scan(&repairer, b"abcdijkl");
        assert_eq!(accepted(&report), [(1, 0, 0), (1, 1, 4)]);
        assert_eq!(report.complete, Some(1));
        assert_eq!(repairer.apply_ordered(Path::new("D"), &report), 2);
        assert_eq!(
            repairer.locations[0],
            Some(BlockLocation { file: 0, offset: 0 })
        );
    }
}

#[test]
fn unique_previously_located_entries_are_replaced_without_recounting() {
    let mut repairer = engine(&[(b"abcdefghijkl", true)], 4);
    seed(&mut repairer, 0, 1, 4);
    let report = scan(&repairer, b"abcdefghijkl");
    assert_eq!(accepted(&report), [(0, 0, 0), (0, 1, 4), (0, 2, 8)]);
    assert_eq!(repairer.apply_ordered(Path::new("D"), &report), 2);
    assert_eq!(
        repairer.locations,
        [
            Some(BlockLocation { file: 1, offset: 0 }),
            Some(BlockLocation { file: 1, offset: 4 }),
            Some(BlockLocation { file: 1, offset: 8 })
        ]
    );
    assert_eq!(repairer.files[0].complete_file, Some(PathBuf::from("D")));
    assert_eq!(repairer.files[0].available_blocks, 3);
}

#[test]
fn unique_first_block_exception_replaces_prior_donor() {
    let mut repairer = engine(&[(b"abcdefgh", true)], 4);
    seed(&mut repairer, 0, 0, 0);
    let report = scan(&repairer, b"abcdefgh");
    assert_eq!(accepted(&report), [(0, 0, 0), (0, 1, 4)]);
    assert_eq!(repairer.apply_ordered(Path::new("D"), &report), 1);
    assert_eq!(
        repairer.locations[0],
        Some(BlockLocation { file: 1, offset: 0 })
    );
}

#[test]
fn repeated_nonterminal_and_terminal_suggestions_have_distinct_precedence() {
    let mut nonterminal = engine(&[(b"abcdabcdefgh", true)], 4);
    seed(&mut nonterminal, 0, 1, 4);
    let report = scan(&nonterminal, b"abcdabcdefgh");
    assert_eq!(accepted(&report), [(0, 0, 0)]);
    assert_eq!(nonterminal.apply_ordered(Path::new("D"), &report), 1);
    assert_eq!(
        nonterminal.locations[1],
        Some(BlockLocation { file: 0, offset: 4 })
    );
    assert!(nonterminal.locations[2].is_none());
    let mut terminal = engine(&[(b"abcdabcd", true)], 4);
    seed(&mut terminal, 0, 1, 4);
    let report = scan(&terminal, b"abcdabcd");
    assert_eq!(accepted(&report), [(0, 0, 0), (0, 1, 4)]);
    assert_eq!(terminal.apply_ordered(Path::new("D"), &report), 1);
    assert_eq!(
        terminal.locations[1],
        Some(BlockLocation { file: 1, offset: 4 })
    );
}

#[test]
fn absent_ifsc_fallback_requires_full_identity_and_selects_one_source() {
    let mut repairer = engine(&[(b"abcdefgh", false), (b"abcdefgh", false)], 4);
    let wrong = scan(&repairer, b"abcdijkl");
    assert!(wrong.accepted.is_empty());
    assert!(wrong.complete.is_none());
    assert!(wrong.file_hashes.is_some());
    let first = scan(&repairer, b"abcdefgh");
    assert_eq!(accepted(&first), [(0, 0, 0), (0, 1, 4)]);
    assert_eq!(first.complete, Some(0));
    assert_eq!(repairer.apply_ordered(Path::new("D"), &first), 2);
    let second = scan(&repairer, b"abcdefgh");
    assert_eq!(accepted(&second), [(1, 0, 0), (1, 1, 4)]);
    assert_eq!(second.complete, Some(1));
}

#[test]
fn mixed_ifsc_partial_and_first_mismatch_suppress_fallback() {
    for first in [b"abcdijkl".as_slice(), b"ijklijkl".as_slice()] {
        let repairer = engine(&[(first, true), (b"abcdefgh", false)], 4);
        let report = scan(&repairer, b"abcdefgh");
        let want = if first.starts_with(b"abcd") {
            vec![(0, 0, 0)]
        } else {
            vec![]
        };
        assert_eq!(accepted(&report), want);
        assert!(report.complete.is_none());
        assert!(report.file_hashes.is_none());
    }
}

#[test]
fn empty_identity_and_contradictory_hashes_are_not_inferred_from_block_count() {
    let mut empty = engine(&[(b"", false)], 4);
    let report = scan(&empty, b"");
    assert!(report.accepted.is_empty());
    assert_eq!(report.complete, Some(0));
    assert!(report.file_hashes.is_some());
    assert_eq!(empty.apply_ordered(Path::new("D"), &report), 0);
    assert_eq!(empty.files[0].status, FileStatus::Misnamed);
    for prefix_hash in [false, true] {
        let mut contradictory = engine(&[(b"abcdefgh", true)], 4);
        if prefix_hash {
            contradictory.files[0].hash_16k = [0; 16];
        } else {
            contradictory.files[0].hash_full = [0; 16];
        }
        let report = scan(&contradictory, b"abcdefgh");
        assert_eq!(accepted(&report), [(0, 0, 0), (0, 1, 4)]);
        assert!(report.complete.is_none());
        assert!(report.file_hashes.is_some());
    }
}

struct Reads {
    data: Vec<u8>,
    calls: RefCell<Vec<(u64, usize)>>,
    fail_at: Option<u64>,
    fail_repeat: Option<u64>,
}
impl Reads {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            calls: RefCell::new(Vec::new()),
            fail_at: None,
            fail_repeat: None,
        }
    }
}
impl PacketSource for Reads {
    fn source_len(&self) -> u64 {
        self.data.len() as u64
    }
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        let repeated = self.calls.borrow().iter().any(|&(old, _)| old == offset);
        self.calls.borrow_mut().push((offset, bytes.len()));
        if self
            .fail_at
            .is_some_and(|end| offset + bytes.len() as u64 > end)
            || (self.fail_repeat == Some(offset) && repeated)
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "injected donor read failure",
            ));
        }
        self.data.as_slice().read_at(offset, bytes)
    }
}

#[test]
fn partial_and_first_mismatch_do_not_touch_a_distant_fault_or_produce_hashes() {
    for prefix in [b"abcdijkl".as_slice(), b"ijklijkl".as_slice()] {
        let repairer = engine(&[(b"abcdefgh", true)], 4);
        let mut data = prefix.to_vec();
        data.resize(2 << 20, b'z');
        let mut source = Reads::new(data);
        source.fail_at = Some(1 << 20);
        let report = repairer
            .scan_ordered_source(&source, None, &mut |_| {})
            .unwrap();
        assert_eq!(
            accepted(&report),
            if prefix.starts_with(b"abcd") {
                vec![(0, 0, 0)]
            } else {
                vec![]
            }
        );
        assert!(report.file_hashes.is_none());
        assert!(report.complete.is_none());
        let calls = source.calls.borrow();
        assert!(
            calls
                .iter()
                .all(|&(off, n)| off + n as u64 <= 3 * MIN_BUFFER as u64)
        );
        assert!(calls.iter().map(|&(_, n)| n).sum::<usize>() <= 3 * MIN_BUFFER);
    }
}

#[test]
fn short_terminal_required_bytes_feed_the_complete_hash_without_a_second_read() {
    let mut original = vec![b'x'; MIN_BUFFER];
    original.extend_from_slice(b"YZ");
    let repairer = engine(&[(&original, true)], MIN_BUFFER);
    let mut source = Reads::new(original);
    source.fail_repeat = Some(MIN_BUFFER as u64);
    let report = repairer
        .scan_ordered_source(&source, None, &mut |_| {})
        .unwrap();
    assert_eq!(accepted(&report), [(0, 0, 0), (0, 1, MIN_BUFFER as u64)]);
    assert_eq!(report.complete, Some(0));
    assert!(report.file_hashes.is_some());
    assert_eq!(source.calls.borrow().len(), 2);
    assert_eq!(
        source.calls.borrow().iter().map(|&(_, n)| n).sum::<usize>(),
        MIN_BUFFER + 2
    );
}

#[test]
fn required_prefix_terminal_and_fallback_read_failures_do_not_commit_and_can_retry() {
    let mut data = vec![b'x'; MIN_BUFFER];
    data.extend(vec![b'y'; MIN_BUFFER]);
    data.extend(vec![b'z'; MIN_BUFFER]);
    for (ifsc, fail_at) in [
        (true, MIN_BUFFER as u64),
        (true, (2 * MIN_BUFFER) as u64),
        (false, MIN_BUFFER as u64),
    ] {
        let mut repairer = engine(&[(&data, ifsc)], MIN_BUFFER);
        seed(&mut repairer, 0, 0, 0);
        let previous = repairer.locations.clone();
        let disks = repairer.disk_files.clone();
        let mut source = Reads::new(data.clone());
        source.fail_at = Some(fail_at);
        let error = repairer
            .add_ordered_source(Path::new("D"), &source, &mut NullObserver)
            .unwrap_err();
        assert!(
            matches!(error,RepairError::Io{source,..} if source.kind()==io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(repairer.locations, previous);
        assert_eq!(repairer.disk_files, disks);
        assert!(!repairer.scanned_extra.contains(Path::new("D")));
        assert!(repairer.files[0].complete_file.is_none());
        source.fail_at = None;
        assert_eq!(
            repairer
                .add_ordered_source(Path::new("D"), &source, &mut NullObserver)
                .unwrap(),
            2
        );
        assert_eq!(repairer.files[0].complete_file, Some(PathBuf::from("D")));
        assert!(repairer.scanned_extra.contains(Path::new("D")));
    }
}

#[test]
fn cancellation_before_commit_discards_new_locations_and_replacements() {
    struct Cancel(Arc<AtomicBool>);
    impl RepairObserver for Cancel {
        fn progress(&mut self, permille: u32, _label: &str) {
            if permille == 1000 {
                self.0.store(true, Ordering::Relaxed);
            }
        }
    }
    let mut repairer = engine(&[(b"abcdefgh", true)], 4);
    seed(&mut repairer, 0, 0, 0);
    let previous = repairer.locations.clone();
    let token = repairer.cancel_token();
    let error = repairer
        .add_ordered_source(
            Path::new("D"),
            b"abcdefgh".as_slice(),
            &mut Cancel(token.clone()),
        )
        .unwrap_err();
    assert!(matches!(error, RepairError::Cancelled));
    assert_eq!(repairer.locations, previous);
    assert!(repairer.files[0].complete_file.is_none());
    assert!(!repairer.scanned_extra.contains(Path::new("D")));
    token.store(false, Ordering::Relaxed);
    assert_eq!(
        repairer
            .add_ordered_source(Path::new("D"), b"abcdefgh".as_slice(), &mut NullObserver)
            .unwrap(),
        1
    );
}

#[test]
fn pending_metadata_and_windows_share_the_phase_budget() {
    let pending = Pending::new(MAX_BLOCKS, 16 << 20, usize::MAX).unwrap();
    assert!(
        pending.report.metadata_bytes as u64 + 3 * pending.report.buffer_size as u64 <= 16 << 20
    );
    assert!(pending.report.buffer_size <= MAX_BUFFER);
    assert!(matches!(
        Pending::new(1, 3 * MIN_BUFFER as u64, MIN_BUFFER),
        Err(RepairError::StreamingMemoryLimit { .. })
    ));
    assert!(matches!(
        Pending::new(MAX_BLOCKS + 1, 16 << 20, MIN_BUFFER),
        Err(RepairError::Io { .. })
    ));
}

#[test]
fn ineligible_fallback_does_not_read_an_unrelated_wrong_size_donor() {
    let repairer = engine(&[(b"abcdefgh", false)], 4);
    let mut source = Reads::new(vec![b'z'; 1 << 20]);
    source.fail_at = Some(0);
    let report = repairer
        .scan_ordered_source(&source, None, &mut |_| {})
        .unwrap();
    assert!(report.accepted.is_empty());
    assert!(report.complete.is_none());
    assert!(report.file_hashes.is_none());
    assert!(source.calls.borrow().is_empty());
}

#[test]
fn oversized_declared_geometry_is_refused_before_reading_or_reserving_pending_state() {
    let mut repairer = engine(&[(b"abcdefgh", true)], 4);
    repairer.files[0].file_length = u64::MAX;
    let source = Reads::new(b"abcdefgh".to_vec());
    assert!(
        matches!(repairer.scan_ordered_source(&source,None,&mut |_|{}),Err(RepairError::Io{source,..}) if source.kind()==io::ErrorKind::InvalidData)
    );
    assert!(source.calls.borrow().is_empty());
}

#[test]
fn same_donor_nonterminal_duplicates_stop_but_terminal_suggestions_can_reselect() {
    for (bytes, want) in [
        (b"abcdefghijkl".as_slice(), vec![(0, 0, 0)]),
        (b"abcdefgh".as_slice(), vec![(0, 0, 0), (0, 1, 4)]),
    ] {
        let mut repairer = engine(&[(bytes, true)], 4);
        let disk = repairer.disk_file_index(Path::new("D"));
        assert!(repairer.set_location(
            BlockRef {
                file_index: 0,
                block_index: 1
            },
            BlockLocation {
                file: disk,
                offset: 4
            }
        ));
        let report = repairer
            .scan_ordered_source(bytes, Some(disk), &mut |_| {})
            .unwrap();
        assert_eq!(accepted(&report), want);
    }
}

#[test]
fn unique_complete_source_is_not_reassigned_to_a_new_donor() {
    let mut repairer = engine(&[(b"abcdefgh", true)], 4);
    seed(&mut repairer, 0, 0, 0);
    seed(&mut repairer, 0, 1, 4);
    repairer.files[0].complete_file = Some(PathBuf::from("E"));
    let report = scan(&repairer, b"abcdefgh");
    assert!(report.accepted.is_empty());
    assert!(report.file_hashes.is_none());
    assert!(report.complete.is_none());
}
