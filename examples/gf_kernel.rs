//! Print the GF(2^16) kernel in use and its single-thread throughput.
//!
//! Usage: `cargo run --release --example gf_kernel [milliseconds]`
fn main() {
    let ms: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let r = par_rs::gf_kernel_benchmark(std::time::Duration::from_millis(ms));
    let supported: Vec<String> = r.supported.iter().map(ToString::to_string).collect();
    println!(
        "kernel: {}  supported: {}  {:.0} MB/s per thread",
        r.isa,
        supported.join(", "),
        r.mb_per_sec_per_thread
    );
}
