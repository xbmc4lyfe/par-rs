//! Repair while downloading: out-of-order yEnc articles folded into syndromes with zero
//! re-reads, early cutoff before the tail of the set is downloaded, surgical solves.

use par_rs::create::{SetOptions, VolumeScheme, build_set};
use par_rs::gf16::simd::Kernel;
use par_rs::inspect::inspect_par2;
use par_rs::packet::SliceChecksum;
use par_rs::stream::{FileLayout, SliceState, StreamEvent, StreamStatus, StreamingSliceAssembler};

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed.wrapping_mul(53)) >> 13) as u8).collect()
}

/// Articles of `art` bytes in a scrambled order: (offset, bytes).
fn articles(file: &[u8], art: usize, seed: usize) -> Vec<(u64, &[u8])> {
    let mut v: Vec<(u64, &[u8])> = file.chunks(art).enumerate().map(|(i, c)| ((i * art) as u64, c)).collect();
    // deterministic shuffle
    let n = v.len();
    for i in 0..n {
        let j = (i * 7 + seed * 13) % n;
        v.swap(i, j);
    }
    v
}

#[test]
fn out_of_order_yenc_streaming_with_early_cutoff() {
    let k = Kernel::detect();
    let ss = 8192usize; // 8 KiB slices
    let art = 7000usize; // yEnc-like article size that never aligns with slices
    let a = data(100_000, 1); // 13 slices
    let b = data(60_000, 2); // 8 slices
    let c = data(20_001, 3); // 3 slices
    let set = build_set("rel", &[("a.bin", &a), ("b.bin", &b), ("c.bin", &c)], &SetOptions { slice_size: ss, recovery_blocks: 12, volumes: VolumeScheme::Uniform(4), kernel: k, ..SetOptions::default() }).unwrap();
    let insp = inspect_par2(&set.index, true);
    let main = &insp.main[0];
    let layouts: Vec<FileLayout> = main
        .recovery_set
        .iter()
        .map(|id| {
            let fd = insp.files.iter().find(|f| f.file_id == *id).unwrap();
            let ifsc = insp.ifsc.iter().find(|i| i.file_id == *id).unwrap();
            FileLayout { file_id: *id, size: fd.length, slices: ifsc.slices.iter().map(|&(md5, crc32)| SliceChecksum { md5, crc32 }).collect() }
        })
        .collect();
    let id_of = |name: &str| insp.files.iter().find(|f| f.name == name).unwrap().file_id;
    let (ia, ib, ic) = (id_of("a.bin"), id_of("b.bin"), id_of("c.bin"));
    let mut asm = StreamingSliceAssembler::new(ss, layouts, &(0..12).collect::<Vec<u32>>(), k, 0).unwrap();
    assert_eq!(asm.total_slices(), 24);

    // Recovery volumes arrive first (two of three volumes = 8 recovery slices).
    let mut received = 0;
    for (_, vol) in &set.volumes[..2] {
        for r in inspect_par2(vol, true).recovery {
            let ev = asm.push_recovery(r.exponent, &vol[r.data_offset..r.data_offset + r.data_len as usize]).unwrap();
            assert!(ev.contains(&StreamEvent::RecoveryReceived { exponent: r.exponent }));
            received += 1;
        }
    }
    assert_eq!(received, 8);
    assert_eq!(asm.bank().ready_syndromes().len(), 8);

    // File a: all articles, scrambled, except two that are lost (damaging the slices they touch).
    let mut verified_a = 0;
    let lost: Vec<u64> = vec![3 * 7000, 9 * 7000];
    for (off, bytes) in articles(&a, art, 1) {
        if lost.contains(&off) {
            let ev = asm.mark_range_damaged(&ia, off, bytes.len() as u64);
            assert!(ev.iter().all(|e| matches!(e, StreamEvent::SliceDamaged { .. })));
            continue;
        }
        for ev in asm.push_chunk(&ia, off, bytes).unwrap() {
            match ev {
                StreamEvent::SliceVerified { .. } => verified_a += 1,
                StreamEvent::SliceMismatch { .. } => panic!("intact article flagged as mismatch"),
                _ => {}
            }
        }
    }
    let damaged_a = asm.damaged_slices().len();
    assert!((2..=4).contains(&damaged_a), "two lost 7000-byte articles touch 2..4 slices, got {damaged_a}");
    assert_eq!(verified_a + damaged_a, 13);
    assert_eq!(asm.staging_bytes(), 0, "no partial slice left once every article of a is accounted for");

    // File b: everything arrives, scrambled.
    for (off, bytes) in articles(&b, art, 2) {
        asm.push_chunk(&ib, off, bytes).unwrap();
    }
    assert_eq!(asm.pending_slices().len(), 3, "only c is still pending");
    // Early cutoff: damaged (<=4) + pending (3) <= 8 ready syndromes -> solvable without c.
    assert!(asm.can_solve_now());
    assert!(matches!(asm.status(), StreamStatus::ReadyToSolve { .. }));
    let solved = asm.solve_now().unwrap();
    assert_eq!(solved.len(), damaged_a + 3);
    let file_ids: Vec<[u8; 16]> = asm.files().iter().map(|f| f.file_id).collect();
    let first_slices: Vec<usize> = (0..file_ids.len()).map(|fi| asm.global_slice(fi, 0).unwrap()).collect();
    let expect_slice = |g: usize| -> Vec<u8> {
        let fi = first_slices.iter().rposition(|&f| f <= g).unwrap();
        let si = g - first_slices[fi];
        let fid = file_ids[fi];
        let src: &[u8] = if fid == ia { &a } else if fid == ib { &b } else { &c };
        let mut p = src[si * ss..((si + 1) * ss).min(src.len())].to_vec();
        p.resize(ss, 0);
        p
    };
    for (g, d) in &solved {
        let e = expect_slice(*g);
        assert!(*d == e, "slice {g}: state {:?} first bytes got {:?} want {:?} (damaged {:?}, pending {:?})", asm.slice_state(*g), &d[..8], &e[..8], asm.damaged_slices(), asm.pending_slices());
        assert_ne!(asm.slice_state(*g), Some(SliceState::Verified));
    }
    // Surgical: just c's last (padded) slice.
    let c_last = asm.global_slice(asm.files().iter().position(|f| f.file_id == ic).unwrap(), 2).unwrap();
    let one = asm.solve_selected_slices(&[c_last]).unwrap();
    assert_eq!(one, vec![(c_last, expect_slice(c_last))]);

    // Late data for c still verifies and folds; everything stays consistent.
    for (off, bytes) in articles(&c, art, 3) {
        asm.push_chunk(&ic, off, bytes).unwrap();
    }
    assert!(asm.pending_slices().is_empty());
    assert_eq!(asm.bank().folded_count(), 24 - damaged_a);
    let again = asm.solve_now().unwrap();
    assert_eq!(again.len(), damaged_a);
    for (g, d) in &again {
        assert_eq!(*d, expect_slice(*g));
    }
}
