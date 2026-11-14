// Licensed under GPL-2.0-or-later, matching Cargo.toml.
use super::*;

fn file_digest(h: &FileSliceHasher) -> FileHashes {
    h.file.clone().finish()
}
#[test]
fn actual_length_overflow_is_rejected_before_digest_or_callback_and_poisoned() {
    let mut h = FileSliceHasher::new(4).unwrap();
    h.file.len = u64::MAX - 2;
    let before = file_digest(&h);
    let mut calls = 0;
    let e = h
        .update(b"abcd", None, &mut |_, _| {
            calls += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    assert!(e.to_string().contains("actual file length"));
    assert_eq!(file_digest(&h), before);
    assert_eq!(calls, 0);
    assert!(
        matches!(h.update_checked(b"x",&mut ||panic!("poison must precede polling"),&mut |_,_|panic!("no callback")),Err(e) if e.kind()==io::ErrorKind::Other)
    );
    assert_eq!(file_digest(&h), before);
    assert!(
        matches!(h.finish_checked(&mut ||panic!("no polling after poison"),&mut |_,_|panic!("no callback")),Err(e) if e.kind()==io::ErrorKind::Other)
    );
}
#[test]
fn simulated_slice_index_overflow_emits_nothing_and_poison_is_sticky() {
    let mut h = FileSliceHasher::new(4).unwrap();
    h.next_index = u64::MAX;
    let e = h
        .update(b"abcd", None, &mut |_, _| {
            panic!("overflow must precede callback")
        })
        .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    assert!(e.to_string().contains("slice index overflow"));
    let before = file_digest(&h);
    assert!(
        h.update(b"efgh", None, &mut |_, _| panic!("no resume"))
            .is_err()
    );
    assert_eq!(file_digest(&h), before);
    assert!(h.finish(None, &mut |_, _| panic!("no resume")).is_err());
}
#[test]
fn invalid_simulated_slice_position_uses_checked_arithmetic() {
    let mut h = FileSliceHasher::new(4).unwrap();
    h.in_slice = 5;
    let before = file_digest(&h);
    assert!(
        matches!(h.update(b"x",None,&mut |_,_|panic!("invalid position")),Err(e) if e.kind()==io::ErrorKind::InvalidData)
    );
    assert_eq!(file_digest(&h), before);
    assert!(h.finish(None, &mut |_, _| panic!("poisoned")).is_err());
    let mut h = FileSliceHasher::new(u64::MAX - 3).unwrap();
    h.in_slice = u64::MAX;
    assert!(
        matches!(h.finish(None,&mut |_,_|panic!("invalid final position")),Err(e) if e.kind()==io::ErrorKind::InvalidData)
    );
}
#[test]
fn large_borrowed_update_polls_before_more_than_sixty_four_kib_of_work() {
    let input = vec![47; 3 * WORK_WINDOW + 1];
    let mut h = FileSliceHasher::new(1 << 40).unwrap();
    let mut polls = 0;
    let mut calls = 0;
    let flag = AtomicBool::new(false);
    let mut check = || {
        polls += 1;
        if polls == 3 {
            flag.store(true, Ordering::Relaxed);
        }
        flag.load(Ordering::Relaxed)
    };
    assert!(
        matches!(h.update_checked(&input,&mut check,&mut |_,_|{calls+=1;Ok(())}),Err(e) if e.kind()==io::ErrorKind::Interrupted)
    );
    assert_eq!(h.file.len(), WORK_WINDOW as u64);
    let mut expected = FileHasher::new();
    expected.update(&input[..WORK_WINDOW]);
    assert_eq!(file_digest(&h), expected.finish());
    assert_eq!(polls, 3);
    assert_eq!(calls, 0);
    eprintln!(
        "bounded update: supplied={} consumed={} checkpoint_polls={polls} callbacks={calls}; fixed_state_bytes={} padding_scratch_bytes={} max_work_bytes={WORK_WINDOW}",
        input.len(),
        h.file.len(),
        std::mem::size_of::<FileSliceHasher>(),
        ZEROS.len()
    );
    let before = file_digest(&h);
    assert!(
        h.update(b"more", None, &mut |_, _| panic!("no resume"))
            .is_err()
    );
    assert_eq!(file_digest(&h), before);
}
#[test]
fn huge_tail_padding_cancels_between_fixed_zero_windows_without_emission() {
    let mut h = FileSliceHasher::new(1 << 40).unwrap();
    h.update(b"abc", None, &mut |_, _| panic!("not complete"))
        .unwrap();
    let mut polls = 0;
    let mut calls = 0;
    let flag = AtomicBool::new(false);
    let mut check = || {
        polls += 1;
        if polls == 3 {
            flag.store(true, Ordering::Relaxed);
        }
        flag.load(Ordering::Relaxed)
    };
    assert!(
        matches!(h.finish_checked(&mut check,&mut |_,_|{calls+=1;Ok(())}),Err(e) if e.kind()==io::ErrorKind::Interrupted)
    );
    assert_eq!(polls, 3);
    assert_eq!(calls, 0);
    eprintln!(
        "large logical padding cancellation: geometry={} actual_input=3 checkpoint_polls={polls} callbacks={calls}; not a physical terabyte read",
        1u64 << 40
    );
}
#[test]
fn final_checkpoint_can_cancel_empty_finish_instead_of_returning_hashes() {
    let h = FileSliceHasher::new(4).unwrap();
    let mut polls = 0;
    assert!(
        matches!(h.finish_checked(&mut ||{polls+=1;polls==2},&mut |_,_|panic!("empty has no slice")),Err(e) if e.kind()==io::ErrorKind::Interrupted)
    );
    assert_eq!(polls, 2);
}
#[test]
fn callback_error_returns_original_then_stops_before_more_polling_or_digest_work() {
    let mut h = FileSliceHasher::new(4).unwrap();
    let flag = AtomicBool::new(false);
    let mut calls = 0;
    let e = h
        .update(b"abcdefgh", Some(&flag), &mut |_, _| {
            calls += 1;
            flag.store(true, Ordering::Relaxed);
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "first callback source",
            ))
        })
        .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(e.to_string(), "first callback source");
    assert_eq!(calls, 1);
    assert_eq!(h.file.len(), 4);
    let before = file_digest(&h);
    assert!(
        h.update_checked(b"more", &mut || panic!("poison first"), &mut |_, _| panic!(
            "no callback"
        ))
        .is_err()
    );
    assert_eq!(file_digest(&h), before);
    assert!(
        h.finish_checked(&mut || panic!("poison first"), &mut |_, _| panic!(
            "no callback"
        ))
        .is_err()
    );
}
