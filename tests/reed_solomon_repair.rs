//! GF(2^16) kernels (SIMD vs scalar bit identity) and Reed-Solomon repair: batch, surgical,
//! exponent-0 fast path, and multi-file disk repair driven from real par2 volumes.

use par_rs::create::{SetOptions, VolumeScheme, build_set};
use par_rs::gf16::simd::{Isa, Kernel};
use par_rs::inspect::inspect_par2;
use par_rs::reed_solomon::encode_reference;
use par_rs::repair::{
    DiskFile, DiskLocation, DiskRecovery, DiskRepairPlan, RepairError, repair_on_disk,
    repair_selected_slices, repair_slices,
};

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| {
            (i.wrapping_mul(2654435761)
                .wrapping_add(seed.wrapping_mul(31))
                >> 13) as u8
        })
        .collect()
}

#[test]
fn simd_kernels_are_bit_identical_to_scalar() {
    let scalar = Kernel::scalar();
    let kernels: Vec<Kernel> = Isa::candidates()
        .iter()
        .filter_map(|&isa| Kernel::with_isa(isa))
        .collect();
    assert!(kernels.iter().any(|k| k.isa() == Kernel::detect().isa()));
    let coeffs = [
        0u16, 1, 2, 3, 0x8000, 0xFFFF, 0x1234, 0xABCD, 0x0100, 0x00FF,
    ];
    for &len in &[
        0usize, 2, 4, 30, 32, 34, 62, 64, 66, 126, 128, 130, 1000, 4096, 4098, 65_536, 65_538,
        200_002,
    ] {
        let src_full = data(len + 64, 1);
        let dst_full = data(len + 64, 2);
        for align in [0usize, 1, 3, 16, 17, 32] {
            let src = &src_full[align..align + len];
            for k in &kernels {
                for &c in &coeffs {
                    let mut expect = dst_full[align..align + len].to_vec();
                    scalar.mul_acc(&mut expect, src, c);
                    let mut got = dst_full[align..align + len].to_vec();
                    k.mul_acc(&mut got, src, c);
                    assert_eq!(
                        got,
                        expect,
                        "isa {} len {len} align {align} coeff {c:#x}",
                        k.isa()
                    );
                }
                // Multi-target with up to 8 destinations.
                let n = 1 + (len % 8);
                let mut expect: Vec<Vec<u8>> = (0..n).map(|i| data(len, 10 + i as u32)).collect();
                let mut got = expect.clone();
                let cs: Vec<u16> = (0..n)
                    .map(|i| coeffs[i % coeffs.len()] ^ (i as u16 * 77))
                    .collect();
                {
                    let mut e: Vec<&mut [u8]> =
                        expect.iter_mut().map(|v| v.as_mut_slice()).collect();
                    scalar.mul_acc_multi(&mut e, src, &cs);
                    let mut g: Vec<&mut [u8]> = got.iter_mut().map(|v| v.as_mut_slice()).collect();
                    k.mul_acc_multi(&mut g, src, &cs);
                }
                assert_eq!(got, expect, "multi isa {} len {len} align {align}", k.isa());
            }
        }
    }
}

#[test]
fn batch_and_surgical_repair_all_patterns() {
    let k = Kernel::detect();
    let ss = 4096usize;
    let n = 16usize;
    let inputs: Vec<Vec<u8>> = (0..n).map(|i| data(ss, 100 + i as u32)).collect();
    let refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let exps: Vec<u32> = (0..8).collect();
    let rec = encode_reference(ss, &refs, &exps);
    let recovery: Vec<(u32, &[u8])> = exps
        .iter()
        .copied()
        .zip(rec.iter().map(Vec::as_slice))
        .collect();
    for missing in [
        vec![0usize],
        vec![15],
        vec![3, 4],
        vec![0, 7, 15],
        vec![1, 2, 3, 4, 5, 6, 7, 8],
        vec![0, 2, 4, 6, 8, 10, 12, 14],
    ] {
        let present: Vec<(usize, &[u8])> = inputs
            .iter()
            .enumerate()
            .filter(|(i, _)| !missing.contains(i))
            .map(|(i, d)| (i, d.as_slice()))
            .collect();
        let out = repair_slices(ss, n, &present, &recovery, &k).unwrap();
        assert_eq!(out.len(), missing.len());
        for (g, d) in &out {
            assert_eq!(d, &inputs[*g], "missing {missing:?} slice {g}");
        }
        // Using exactly as many recovery slices as missing, from the top exponents.
        let tight: Vec<(u32, &[u8])> = recovery[recovery.len() - missing.len()..].to_vec();
        let out = repair_slices(ss, n, &present, &tight, &k).unwrap();
        for (g, d) in &out {
            assert_eq!(d, &inputs[*g]);
        }
        // Surgical: first missing only.
        let out = repair_selected_slices(ss, n, &present, &recovery, &missing[..1], &k).unwrap();
        assert_eq!(out, vec![(missing[0], inputs[missing[0]].clone())]);
    }
    // Nine missing with eight recovery slices.
    let present: Vec<(usize, &[u8])> = inputs
        .iter()
        .enumerate()
        .skip(9)
        .map(|(i, d)| (i, d.as_slice()))
        .collect();
    assert!(matches!(
        repair_slices(ss, n, &present, &recovery, &k),
        Err(RepairError::NotEnoughRecovery {
            needed: 9,
            available: 8
        })
    ));
    // Exponent-0 XOR fast path equals the field solution.
    let present: Vec<(usize, &[u8])> = inputs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 5)
        .map(|(i, d)| (i, d.as_slice()))
        .collect();
    let fast = repair_slices(ss, n, &present, &recovery[..1], &k).unwrap();
    let slow = repair_slices(ss, n, &present, &recovery[5..6], &k).unwrap();
    assert_eq!(fast, slow);
    assert_eq!(fast[0].1, inputs[5]);
}

#[test]
fn disk_repair_from_real_volumes() {
    let k = Kernel::detect();
    let ss = 1024usize;
    let a = data(10_300, 1); // 11 slices, last padded
    let b = data(2_048, 2); // 2 slices
    let c = data(5_000, 3); // 5 slices
    let set = build_set(
        "rel",
        &[("a.bin", &a), ("b.bin", &b), ("c.bin", &c)],
        &SetOptions {
            slice_size: ss,
            recovery_blocks: 7,
            volumes: VolumeScheme::Uniform(4),
            kernel: k,
            ..SetOptions::default()
        },
    )
    .unwrap();
    let dir = std::env::temp_dir().join(format!("par-rs-disk-repair-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let written = set.write_to(&dir, "rel").unwrap();
    assert_eq!(written.len(), 3);

    // Layout in file-id order from the index.
    let insp = inspect_par2(&set.index, true);
    let main = &insp.main[0];
    let mut files = Vec::new();
    let mut present = Vec::new();
    let mut first = 0usize;
    let originals = [("a.bin", &a), ("b.bin", &b), ("c.bin", &c)];
    for id in &main.recovery_set {
        let fd = insp.files.iter().find(|f| f.file_id == *id).unwrap();
        let count = (fd.length as usize).div_ceil(ss);
        let path = dir.join(&fd.name);
        files.push(DiskFile {
            path: path.clone(),
            size: fd.length,
            first_slice: first,
            slice_count: count,
        });
        let orig = originals.iter().find(|(n, _)| *n == fd.name).unwrap().1;
        // a: corrupt slices 2 and 10 (kept on disk, so other slices are present); b: missing; c: intact.
        match fd.name.as_str() {
            "a.bin" => {
                let mut dmg = orig.to_vec();
                dmg[2 * ss + 5] ^= 0xFF;
                dmg[10 * ss + 1] ^= 0xFF;
                std::fs::write(&path, &dmg).unwrap();
                for s in 0..count {
                    present.push(if s == 2 || s == 10 {
                        None
                    } else {
                        Some(DiskLocation {
                            path: path.clone(),
                            offset: (s * ss) as u64,
                        })
                    });
                }
            }
            "b.bin" => {
                for _ in 0..count {
                    present.push(None);
                }
            }
            _ => {
                std::fs::write(&path, orig).unwrap();
                for s in 0..count {
                    present.push(Some(DiskLocation {
                        path: path.clone(),
                        offset: (s * ss) as u64,
                    }));
                }
            }
        }
        first += count;
    }
    // Recovery slices from the volumes on disk.
    let mut recovery = Vec::new();
    for p in &written[1..] {
        let vol = std::fs::read(p).unwrap();
        for r in inspect_par2(&vol, true).recovery {
            recovery.push(DiskRecovery {
                path: p.clone(),
                offset: r.data_offset as u64,
                exponent: r.exponent,
            });
        }
    }
    assert_eq!(recovery.len(), 7);
    let plan = DiskRepairPlan {
        slice_size: ss as u64,
        files,
        present,
        recovery,
    };
    let report = repair_on_disk(&plan, &k).unwrap();
    assert_eq!(report.repaired.len(), 4);
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b);
    assert_eq!(std::fs::read(dir.join("c.bin")).unwrap(), c);
    std::fs::remove_dir_all(&dir).unwrap();
}
