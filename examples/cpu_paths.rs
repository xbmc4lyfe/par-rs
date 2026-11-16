//! Throughput of the CPU-specific hashing paths at the sizes PAR2 uses.
//!
//! Usage: `cargo run --release --example cpu_paths`
use std::time::Instant;

fn gbps(bytes: usize, secs: f64) -> f64 {
    bytes as f64 / secs / 1e9
}

fn main() {
    let data: Vec<u8> = (0..(64usize << 20))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    println!("crc kernel: {:?}", par_rs::crc::kernel());
    for size in [
        128usize,
        192,
        256,
        512,
        1 << 10,
        4 << 10,
        16 << 10,
        64 << 10,
        256 << 10,
        1 << 20,
        8 << 20,
    ] {
        let total = 512usize << 20;
        let mut c = 0u32;
        let t = Instant::now();
        for i in 0..total / size {
            let off = (i * size) % (data.len() - size + 1);
            c ^= par_rs::crc::crc32(&data[off..off + size]);
        }
        println!(
            "crc32 {:>8} B: {:6.2} GB/s ({c:08x})",
            size,
            gbps(total, t.elapsed().as_secs_f64())
        );
    }
    let lanes = par_rs::md5simd::LANES;
    for msg in [64usize << 10, 1 << 20] {
        let msgs: Vec<&[u8]> = (0..lanes).map(|i| &data[i * msg..(i + 1) * msg]).collect();
        let reps = (1usize << 30) / (msg * lanes);
        let t = Instant::now();
        let mut x = 0u8;
        for _ in 0..reps {
            x ^= par_rs::md5simd::md5_many(&msgs)[0][0];
        }
        println!(
            "md5_many {lanes} x {:>8} B: {:6.2} GB/s ({x:02x})",
            msg,
            gbps(reps * msg * lanes, t.elapsed().as_secs_f64())
        );
    }
}
