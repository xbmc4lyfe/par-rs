//! Packet scanner resilience: truncation sweeps, garbage, bit flips, resynchronisation, and the
//! indexer summary built on top of it.

use par_rs::create::{SetOptions, VolumeScheme, build_set};
use par_rs::inspect::{
    CreatorTool, PacketKind, ParFormat, VerifyMode, inspect_par2, inspect_par2_with,
    parse_par2_filename,
};
use par_rs::par2::{display_name, file_descriptions, inventory, is_base_par2};
use par_rs::{Isa, Kernel};

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| {
            (i.wrapping_mul(2654435761)
                .wrapping_add(seed.wrapping_mul(1013))
                >> 13) as u8
        })
        .collect()
}

fn opts(ss: usize, rec: u32) -> SetOptions {
    SetOptions {
        slice_size: ss,
        recovery_blocks: rec,
        volumes: VolumeScheme::Uniform(3),
        creator: "par-rs test 0.2.0 (aarch64)".into(),
        kernel: Kernel::with_isa(Isa::Scalar).unwrap_or_else(Kernel::detect),
        ..SetOptions::default()
    }
}

#[test]
fn full_set_inspection_and_inventory() {
    let a = data(10_000, 1);
    let b = data(4_000, 2);
    let c = data(0, 3);
    let set = build_set(
        "rel",
        &[("alpha.rar", &a), ("bëta.rar", &b), ("empty.txt", &c)],
        &opts(1024, 7),
    )
    .unwrap();
    let r = inspect_par2(&set.index, true);
    assert_eq!(r.format, Some(ParFormat::Par2));
    assert_eq!(r.main.len(), 1);
    assert_eq!(r.main[0].slice_size, 1024);
    assert_eq!(r.main[0].recovery_set.len(), 3);
    assert_eq!(r.files.len(), 3);
    assert_eq!(r.ifsc.len(), 2, "the empty file has no IFSC packet");
    assert_eq!(r.unicode_names.len(), 1);
    assert_eq!(r.unicode_names[0].name, "bëta.rar");
    assert_eq!(r.creators.len(), 1);
    assert_eq!(r.creators[0].tool, CreatorTool::ParRs);
    assert_eq!(r.creators[0].version.as_deref(), Some("0.2.0"));
    assert_eq!(r.creators[0].arch.as_deref(), Some("aarch64"));
    assert_eq!(r.bad_md5, 0);
    assert!(r.packets.iter().all(|p| p.md5_ok == Some(true)));
    assert!(!r.truncated);
    assert_eq!(r.resyncs, 0);
    assert!(r.recovery.is_empty());

    let inv = inventory(&set.index);
    assert_eq!(inv.block_size, Some(1024));
    assert!(inv.complete);
    assert!(!inv.truncated);
    assert_eq!(inv.files.len(), 3);
    assert!(
        inv.files
            .windows(2)
            .all(|w| u128::from_le_bytes(w[0].file_id) < u128::from_le_bytes(w[1].file_id)),
        "libpar2 order"
    );
    let beta = inv.files.iter().find(|f| f.name == "bëta.rar").unwrap();
    assert_eq!(beta.size, 4000);
    assert_eq!(beta.crc32, Some(par_rs::crc32(&b)));
    assert!(beta.bound);
    let alpha = inv.files.iter().find(|f| f.name == "alpha.rar").unwrap();
    assert_eq!(alpha.crc32, Some(par_rs::crc32(&a)));
    let empty = inv.files.iter().find(|f| f.name == "empty.txt").unwrap();
    assert_eq!(empty.crc32, None);
    assert_eq!(inv.sealed.len(), 2);
    assert_eq!(display_name(&set.index).as_deref(), Some("alpha.rar"));
    let descs = file_descriptions(&set.index);
    assert_eq!(descs.len(), 3);
    assert!(descs.contains(&("alpha.rar".to_owned(), 10_000)));

    // Volumes: recovery slices with exponent-0 fingerprint, plus critical copies.
    assert_eq!(set.volumes.len(), 3);
    let v0 = inspect_par2(&set.volumes[0].1, true);
    assert_eq!(v0.recovery.len(), 3);
    assert_eq!(v0.recovery[0].exponent, 0);
    assert!(v0.recovery[0].exp0_prefix_md5.is_some());
    assert!(v0.recovery[1].exp0_prefix_md5.is_none());
    assert_eq!(v0.recovery[0].data_len, 1024);
    assert_eq!(v0.recovery[0].available, 1024);
    assert_eq!(v0.bad_md5, 0);
    assert!(!v0.main.is_empty());
    let name = parse_par2_filename(&set.volumes[1].0).unwrap();
    assert_eq!(
        (name.first_block, name.block_count, name.is_index),
        (Some(3), Some(3), false)
    );
    assert!(!is_base_par2(&set.volumes[1].0));
    assert!(is_base_par2("rel.par2"));
}

#[test]
fn prefix_sweep_is_panic_free_and_monotonic() {
    let a = data(30_000, 7);
    let b = data(1_000, 8);
    let set = build_set("rel", &[("one.bin", &a), ("two.bin", &b)], &opts(4096, 4)).unwrap();
    let full = inventory(&set.index);
    let mut prev_files = 0usize;
    let mut prev_sealed = 0usize;
    for cut in 0..=set.index.len() {
        let inv = inventory(&set.index[..cut]);
        assert!(inv.files.len() >= prev_files, "files monotonic at {cut}");
        assert!(inv.sealed.len() >= prev_sealed, "sealed monotonic at {cut}");
        for f in &inv.files {
            // Identity never changes; fields filled in by later packets (IFSC CRC) may still be absent.
            let real = full
                .files
                .iter()
                .find(|x| x.file_id == f.file_id)
                .expect("prefix reports only real files");
            assert_eq!(
                (&f.name, f.size, f.md5, f.md5_16k, f.set_id),
                (&real.name, real.size, real.md5, real.md5_16k, real.set_id)
            );
            assert!(f.crc32.is_none() || f.crc32 == real.crc32);
            assert!(!f.bound || real.bound);
        }
        // `complete` (Main + every FileDesc of the recovery set, nothing torn) implies every file is listed.
        if inv.complete {
            assert_eq!(inv.files.len(), full.files.len(), "complete at cut {cut}");
            assert!(!inv.truncated);
        }
        prev_files = inv.files.len();
        prev_sealed = inv.sealed.len();
        let _ = inspect_par2(&set.index[..cut], true);
        let _ = display_name(&set.index[..cut]);
    }
    assert_eq!(inventory(&set.index), full);
    // Volumes too, every 97 bytes.
    for (_, vol) in &set.volumes {
        for cut in (0..=vol.len()).step_by(97) {
            let r = inspect_par2(&vol[..cut], true);
            assert!(r.recovery.iter().all(|s| s.available as u64 <= s.data_len));
        }
    }
}

#[test]
fn garbage_shifts_and_bit_flips() {
    let a = data(20_000, 9);
    let set = build_set("rel", &[("file.bin", &a)], &opts(2048, 2)).unwrap();
    let base = inspect_par2(&set.index, true);

    // Leading and trailing junk, junk between packets: everything still found via resync.
    let mut shifted = b"yEnc leftovers =ybegin\r\n".to_vec();
    shifted.extend_from_slice(&set.index[..base.packets[0].length as usize + 24]); // Main packet + a torn FileDesc header
    shifted.extend_from_slice(b"JUNKJUNK");
    shifted.extend_from_slice(&set.index[base.packets[1].offset..]);
    shifted.extend_from_slice(b"=yend");
    let r = inspect_par2(&shifted, true);
    assert_eq!(r.main.len(), 1);
    assert_eq!(r.files.len(), 1);
    assert!(r.resyncs >= 1);
    assert_eq!(inventory(&shifted).files.len(), 1);
    let unverified = inspect_par2_with(&shifted, VerifyMode::None);
    assert_eq!(
        unverified.files.len(),
        1,
        "torn header must not swallow the real packet"
    );

    // Every single-bit flip: never panics; a flipped body shows up as a bad MD5 or a changed
    // field, a flipped header as truncation / resync — but never as a bogus extra file.
    let mut seen_bad = 0;
    for bit in (0..set.index.len() * 8).step_by(13) {
        let mut d = set.index.clone();
        d[bit / 8] ^= 1 << (bit % 8);
        let r = inspect_par2(&d, true);
        if r.bad_md5 > 0 {
            seen_bad += 1;
        }
        let inv = inventory(&d);
        assert!(inv.files.len() <= 1);
        let _ = display_name(&d);
    }
    assert!(seen_bad > 0);

    // Random garbage of various sizes.
    for n in [0usize, 1, 7, 63, 64, 65, 1000, 70_000] {
        let g = data(n, n as u32 + 100);
        let r = inspect_par2(&g, true);
        assert!(r.files.is_empty());
        assert_eq!(inventory(&g).files.len(), 0);
    }
    // A shaped header claiming a huge length: truncated, no allocation of that size.
    let mut huge = b"PAR2\0PKT".to_vec();
    huge.extend_from_slice(&u64::MAX.to_le_bytes());
    huge.extend_from_slice(&[0u8; 48]);
    huge.extend_from_slice(b"body");
    let r = inspect_par2(&huge, true);
    assert!(!r.truncated || r.packets.len() <= 1);
    // Unshaped length (not a multiple of 4) is skipped and the scanner resynchronises.
    let mut bad_len = b"PAR2\0PKT".to_vec();
    bad_len.extend_from_slice(&66u64.to_le_bytes());
    bad_len.extend_from_slice(&[0u8; 48]);
    bad_len.extend_from_slice(&set.index);
    let r = inspect_par2(&bad_len, false);
    assert_eq!(r.packets.len(), base.packets.len());
    assert!(r.packets.iter().all(|p| p.kind != PacketKind::Unknown));
}
