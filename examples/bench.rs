//! Quick throughput check of the GF(2^16) kernels and the Reed-Solomon engine.
//!
//! Usage: `cargo run --release --example bench [slice_bytes] [inputs] [outputs] [threads]`

use par_rs::gf16::simd::{Kernel, Plane, PlaneMut};
use par_rs::reed_solomon::{EngineConfig, encode_in_memory};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let slice: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1 << 20);
    let inputs: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);
    let outputs: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);
    let threads: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
    let kernel = Kernel::detect();
    println!("kernel: {}  crc: {:?}", kernel.isa(), par_rs::crc::kernel());

    // Single-thread kernel throughput (split planes, 4 outputs per source pass).
    let n = 1 << 20;
    let src: Vec<u8> = (0..2 * n).map(|i| (i * 31 % 251) as u8).collect();
    let mut dsts: Vec<Vec<u8>> = (0..4).map(|_| vec![0u8; 2 * n]).collect();
    let coeffs = [0x1234u16, 0x5678, 0x9abc, 0xdef1];
    let reps = 50;
    let t = Instant::now();
    for _ in 0..reps {
        let mut planes: Vec<PlaneMut> = dsts.iter_mut().map(|d| PlaneMut::from_halves(d)).collect();
        kernel.mul_acc_multi_split(&mut planes, Plane::from_halves(&src), &coeffs);
    }
    let el = t.elapsed().as_secs_f64();
    let bytes = (reps * 4 * 2 * n) as f64;
    println!(
        "kernel mul_acc_multi_split x4: {:.2} GB/s of output bytes (single thread)",
        bytes / el / 1e9
    );

    // CRC32 / MD5 throughput.
    let t = Instant::now();
    let mut c = 0u32;
    for _ in 0..reps {
        c ^= par_rs::crc::crc32(&src);
    }
    let el = t.elapsed().as_secs_f64();
    println!(
        "crc32: {:.2} GB/s ({c:08x})",
        (reps * src.len()) as f64 / el / 1e9
    );
    let t = Instant::now();
    let mut h = par_rs::hasher::FileHasher::new();
    for _ in 0..reps {
        h.update(&src);
    }
    let el = t.elapsed().as_secs_f64();
    let r = h.finish();
    println!(
        "fused crc32+md5: {:.2} GB/s ({:02x}..)",
        (reps * src.len()) as f64 / el / 1e9,
        r.md5_full[0]
    );

    // Scalar MD5 vs multi-lane MD5 over independent 1 MiB messages.
    let msgs: Vec<Vec<u8>> = (0..48u32)
        .map(|i| {
            (0..(1usize << 20))
                .map(|j| ((j as u32).wrapping_mul(2654435761).wrapping_add(i) >> 11) as u8)
                .collect()
        })
        .collect();
    let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let t = Instant::now();
    let mut x = 0u8;
    for m in &refs {
        x ^= par_rs::hasher::md5(m)[0];
    }
    let el = t.elapsed().as_secs_f64();
    println!(
        "md5 scalar: {:.2} GB/s ({x:02x})",
        (refs.len() << 20) as f64 / el / 1e9
    );
    let t = Instant::now();
    let d = par_rs::md5simd::md5_many(&refs);
    let el = t.elapsed().as_secs_f64();
    println!(
        "md5 multi-lane ({} lanes): {:.2} GB/s ({:02x})",
        par_rs::md5simd::LANES,
        (refs.len() << 20) as f64 / el / 1e9,
        d.iter().fold(0u8, |a, v| a ^ v[0])
    );

    // Engine encode.
    let data: Vec<Vec<u8>> = (0..inputs)
        .map(|i| (0..slice).map(|j| ((j * 7 + i * 13) % 253) as u8).collect())
        .collect();
    let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
    let exps: Vec<u32> = (0..outputs as u32).collect();
    let mut cfg = EngineConfig {
        num_threads: threads,
        ..EngineConfig::default()
    };
    if let Some(v) = args.get(5).and_then(|s| s.parse().ok()) {
        cfg.tile_words = v;
    }
    if let Some(v) = args.get(6).and_then(|s| s.parse().ok()) {
        cfg.output_group = v;
    }
    if let Some(v) = args.get(7).and_then(|s| s.parse().ok()) {
        cfg.input_batch = v;
    }
    let t = Instant::now();
    let out = encode_in_memory(slice, &refs, &exps, cfg, kernel).unwrap();
    let el = t.elapsed().as_secs_f64();
    let work = (inputs * outputs * slice) as f64;
    println!(
        "engine encode: {inputs} inputs x {outputs} outputs x {slice} B in {el:.3}s = {:.2} GB/s of multiply and accumulate operations ({:.2} GB/s input)",
        work / el / 1e9,
        (inputs * slice) as f64 / el / 1e9
    );
    println!("checksum: {:08x}", par_rs::crc::crc32(&out[0]));
}
