//! Obfuscated-file resolution and slice-level verification on a real set.

use par_rs::bridge::{Candidate, Par2Bridge, RAR5_SIGNATURE, ResolveMethod};
use par_rs::create::{SetOptions, VolumeScheme, build_set};
use par_rs::gf2::{crc32, fold_yenc_parts};
use par_rs::inspect::inspect_par2;
use par_rs::par2::inventory;
use par_rs::verify::{SetVerifier, SliceStatus};
use par_rs::{Isa, Kernel};

fn data(n: usize, seed: u32) -> Vec<u8> {
    // Seeds are mixed in before the multiply so two files are never shifted copies of each other.
    (0..n as u32)
        .map(|i| ((i ^ seed.wrapping_mul(0x9E37_79B9)).wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

fn rar5(volume: Option<u64>, body: &[u8]) -> Vec<u8> {
    let mut h = RAR5_SIGNATURE.to_vec();
    h.extend_from_slice(&[0, 0, 0, 0]);
    let mut hdr = vec![1u8, 0];
    match volume {
        Some(v) => {
            hdr.push(0x03);
            hdr.push(v as u8);
        }
        None => hdr.push(0x01),
    }
    h.push(hdr.len() as u8);
    h.extend_from_slice(&hdr);
    h.extend_from_slice(body);
    h
}

fn opts(ss: usize) -> SetOptions {
    SetOptions {
        slice_size: ss,
        recovery_blocks: 6,
        volumes: VolumeScheme::Single,
        kernel: Kernel::with_isa(Isa::Scalar).unwrap_or_else(Kernel::detect),
        ..SetOptions::default()
    }
}

#[test]
fn bridge_resolves_obfuscated_rar_set() {
    // Four same-size RAR volumes with RAR5 headers, a smaller last volume and an nfo.
    let v1 = rar5(None, &data(50_000 - 20, 1));
    let v2 = rar5(Some(1), &data(50_000 - 21, 2));
    let v3 = rar5(Some(2), &data(50_000 - 21, 3));
    let v4 = rar5(Some(3), &data(50_000 - 21, 4));
    let v5 = rar5(Some(4), &data(10_000, 5));
    let nfo = data(777, 6);
    let files: Vec<(&str, &[u8])> = vec![
        ("rel.part1.rar", &v1),
        ("rel.part2.rar", &v2),
        ("rel.part3.rar", &v3),
        ("rel.part4.rar", &v4),
        ("rel.part5.rar", &v5),
        ("rel.nfo", &nfo),
    ];
    let set = build_set("rel", &files, &opts(4096)).unwrap();
    let inv = inventory(&set.index);
    assert_eq!(inv.files.len(), 6);
    let bridge = Par2Bridge::new(&inv);

    // Obfuscated downloads with partial knowledge: article-1 MD5 for one, yEnc CRC for another,
    // only the RAR header bytes for the rest.
    let md5_16k = |d: &[u8]| -> [u8; 16] { par_rs::hasher::md5_16k(d) };
    let yenc_crc = |d: &[u8]| {
        fold_yenc_parts(
            &d.chunks(7000)
                .map(|c| (crc32(c), c.len()))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    };
    let cands = vec![
        Candidate {
            name: "a1b2.bin".into(),
            size: v5.len() as u64,
            ..Default::default()
        }, // unique size
        Candidate {
            name: "c3d4.bin".into(),
            size: v2.len() as u64,
            md5_16k: Some(md5_16k(&v2)),
            ..Default::default()
        }, // md5
        Candidate {
            name: "e5f6.bin".into(),
            size: v3.len() as u64,
            crc32: Some(yenc_crc(&v3)),
            ..Default::default()
        }, // crc
        Candidate {
            name: "g7h8.bin".into(),
            size: v4.len() as u64,
            head: Some(v4[..64].to_vec()),
            ..Default::default()
        }, // rar5 vol 3 -> part4
        Candidate {
            name: "i9j0.bin".into(),
            size: v1.len() as u64,
            head: Some(v1[..64].to_vec()),
            ..Default::default()
        }, // rar5 vol 0 -> part1
        Candidate {
            name: "k1l2.bin".into(),
            size: nfo.len() as u64,
            ..Default::default()
        }, // unique size
        Candidate {
            name: "stray.bin".into(),
            size: 123,
            ..Default::default()
        },
    ];
    let r = bridge.resolve(&cands);
    let name_of = |c: usize| {
        r.resolved
            .iter()
            .find(|x| x.candidate == c)
            .map(|x| (bridge.files()[x.file].name.clone(), x.method))
    };
    assert_eq!(
        name_of(0),
        Some(("rel.part5.rar".into(), ResolveMethod::SizeChain))
    );
    assert_eq!(
        name_of(1),
        Some(("rel.part2.rar".into(), ResolveMethod::Md5_16k))
    );
    assert_eq!(
        name_of(2),
        Some(("rel.part3.rar".into(), ResolveMethod::Crc32))
    );
    assert_eq!(
        name_of(3),
        Some(("rel.part4.rar".into(), ResolveMethod::Rar5Volume))
    );
    assert_eq!(
        name_of(4),
        Some(("rel.part1.rar".into(), ResolveMethod::Rar5Volume))
    );
    assert_eq!(
        name_of(5),
        Some(("rel.nfo".into(), ResolveMethod::SizeChain))
    );
    assert_eq!(r.unresolved_candidates, vec![6]);
    assert!(r.unmatched_files.is_empty());
}

#[test]
fn set_verifier_from_inspection() {
    let a = data(20_000, 11);
    let b = data(9_000, 12);
    let ss = 2048usize;
    let set = build_set("rel", &[("a.bin", &a), ("b.bin", &b)], &opts(ss)).unwrap();
    let insp = inspect_par2(&set.index, true);
    let v = SetVerifier::from_inspection(&insp).unwrap();
    assert_eq!(v.block_size(), ss as u64);
    assert_eq!(v.total_slices(), 10 + 5);
    let fa = v
        .file_index(
            &insp
                .files
                .iter()
                .find(|f| f.name == "a.bin")
                .unwrap()
                .file_id,
        )
        .unwrap();
    let fb = v
        .file_index(
            &insp
                .files
                .iter()
                .find(|f| f.name == "b.bin")
                .unwrap()
                .file_id,
        )
        .unwrap();

    assert!(v.verify_file(fa, &a).is_intact());
    assert!(v.verify_file(fb, &b).is_intact());

    // Corrupt two slices of a, delete 100 bytes at the start of b's slice 2 (shifting the rest).
    let mut da = a.clone();
    da[100] ^= 1;
    da[5000] ^= 1;
    let mut db = b.clone();
    db.drain(4096..4196);
    let report = v.verify_files(&[(fa, &da), (fb, &db)]);
    let ra = &report.files[0];
    assert_eq!(
        ra.slices
            .iter()
            .filter(|s| **s == SliceStatus::Damaged)
            .count(),
        2
    );
    let rb = &report.files[1];
    assert!(!rb.size_ok);
    assert_eq!(rb.slices[0], SliceStatus::Verified);
    assert_eq!(rb.slices[1], SliceStatus::Verified);
    assert_eq!(rb.slices[2], SliceStatus::Damaged); // 100 bytes gone: this slice is unrecoverable from b
    assert_eq!(rb.slices[3], SliceStatus::Misplaced { offset: 6144 - 100 });
    assert_eq!(rb.slices[4], SliceStatus::Misplaced { offset: 8192 - 100 });
    assert_eq!(report.missing.len(), 3);
    let asmt = v.assess(&report, insp.main[0].recovery_set.len() + 4);
    assert!(asmt.repairable);
    assert_eq!(v.assess(&report, 2).shortfall, 1);

    // A buffer that is b offered as a: all of b's slices are found and credited.
    let swapped = v.verify_files(&[(fa, &b)]);
    assert!(swapped.located.iter().filter(|l| l.is_some()).count() >= 5);
}
