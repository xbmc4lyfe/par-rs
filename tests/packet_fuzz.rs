//! Deterministic, dependency-free mutation fuzzer for PAR2 packet parsing.
//!
//! Seeds are real sets from `build_set`. Each case mutates one seed (bit flips, overwrites,
//! truncation, packet duplication / reordering, hostile length and body fields, optionally with
//! the packet MD5 fixed up so body parsing runs) and feeds the result through every parsing entry
//! point. A panic, a stall, or a single allocation above [`ALLOC_LIMIT`] fails the test.
//!
//! `PAR_RS_FUZZ_CASES` overrides the case count and `PAR_RS_FUZZ_SEED` the seed.
//! [`packet_resilience.rs`](packet_resilience.rs) covers the hand-picked sweeps; this file covers
//! random combinations of them.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use par_rs::create::{SetOptions, VolumeScheme, build_set};
use par_rs::hasher::md5;
use par_rs::inspect::{VerifyMode, inspect_par2, inspect_par2_with};
use par_rs::packet::{ScanOptions, load_par2_bytes, load_par2_file};
use par_rs::par2::{display_name, file_descriptions, inventory};
use par_rs::{Isa, Kernel, SessionOptions, StreamingParSession};

// ---------------------------------------------------------------------------------------------
// Guards: huge allocations and stalls abort the process with the case number.
// ---------------------------------------------------------------------------------------------

/// Largest single allocation a hostile input may cause.
const ALLOC_LIMIT: usize = 512 << 20;
/// Wall-clock budget for one case.
const CASE_LIMIT: Duration = Duration::from_secs(10);

static CURRENT_CASE: AtomicU64 = AtomicU64::new(u64::MAX);
static ARMED: AtomicBool = AtomicBool::new(false);

fn write_num(buf: &mut [u8], mut n: u64) -> usize {
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let len = tmp.len() - i;
    buf[..len].copy_from_slice(&tmp[i..]);
    len
}

/// Abort without allocating: print `msg`, the case number and `extra`.
fn die(msg: &[u8], extra: u64) -> ! {
    let mut buf = [0u8; 160];
    let mut n = msg.len().min(100);
    buf[..n].copy_from_slice(&msg[..n]);
    buf[n..n + 6].copy_from_slice(b" case=");
    n += 6;
    n += write_num(&mut buf[n..], CURRENT_CASE.load(Ordering::Relaxed));
    buf[n] = b' ';
    n += 1;
    n += write_num(&mut buf[n..], extra);
    buf[n] = b'\n';
    n += 1;
    let _ = std::io::stderr().write_all(&buf[..n]);
    std::process::abort();
}

struct Guard;

unsafe impl GlobalAlloc for Guard {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > ALLOC_LIMIT && ARMED.load(Ordering::Relaxed) {
            die(
                b"packet_fuzz: huge allocation (bytes)",
                layout.size() as u64,
            );
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.size() > ALLOC_LIMIT && ARMED.load(Ordering::Relaxed) {
            die(
                b"packet_fuzz: huge allocation (bytes)",
                layout.size() as u64,
            );
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > ALLOC_LIMIT && ARMED.load(Ordering::Relaxed) {
            die(b"packet_fuzz: huge reallocation (bytes)", new_size as u64);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Guard = Guard;

// ---------------------------------------------------------------------------------------------
// PRNG and seeds
// ---------------------------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn chance(&mut self, one_in: u64) -> bool {
        self.next().is_multiple_of(one_in)
    }
}

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| {
            (i.wrapping_mul(2_654_435_761)
                .wrapping_add(seed.wrapping_mul(1013))
                >> 13) as u8
        })
        .collect()
}

struct Seed {
    index: Vec<u8>,
    volumes: Vec<Vec<u8>>,
}

/// Files `(len, data seed)`, slice size, recovery blocks, volume layout.
type Shape = (&'static [(usize, u32)], usize, u32, VolumeScheme);

fn seeds() -> Vec<Seed> {
    let kernel = Kernel::with_isa(Isa::Scalar).unwrap_or_else(Kernel::detect);
    let shapes: [Shape; 5] = [
        (&[(5_000, 1)], 1024, 2, VolumeScheme::Single),
        (
            &[(10_000, 2), (4_000, 3), (0, 4)],
            512,
            5,
            VolumeScheme::Uniform(3),
        ),
        (&[(30_000, 5), (1, 6)], 4096, 3, VolumeScheme::Uniform(2)),
        (
            &[(700, 7), (900, 8), (1_100, 9), (64, 10)],
            64,
            9,
            VolumeScheme::Uniform(4),
        ),
        (&[(20_000, 11)], 16384, 1, VolumeScheme::Single),
    ];
    let names = ["a.bin", "bëta.rar", "c.txt", "d"];
    shapes
        .iter()
        .map(|(files, ss, rec, vol)| {
            let bodies: Vec<Vec<u8>> = files.iter().map(|&(n, s)| data(n, s)).collect();
            let inputs: Vec<(&str, &[u8])> = bodies
                .iter()
                .enumerate()
                .map(|(i, b)| (names[i], b.as_slice()))
                .collect();
            let set = build_set(
                "fz",
                &inputs,
                &SetOptions {
                    slice_size: *ss,
                    recovery_blocks: *rec,
                    volumes: *vol,
                    creator: "par-rs fuzz".into(),
                    kernel,
                    ..SetOptions::default()
                },
            )
            .unwrap();
            Seed {
                index: set.index,
                volumes: set.volumes.into_iter().map(|(_, v)| v).collect(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------------------------

/// Packet spans `(offset, length)` of a well-formed, contiguous buffer.
fn spans(buf: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 64 <= buf.len() && buf[off..off + 8] == *b"PAR2\0PKT" {
        let len = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap());
        if len < 64 || len > (buf.len() - off) as u64 {
            break;
        }
        let len = len as usize;
        out.push((off, len));
        off += len;
    }
    out
}

/// Recompute the packet MD5 of the packet at `off`, if its declared length fits.
fn fix_md5(buf: &mut [u8], off: usize) {
    if off + 64 > buf.len() {
        return;
    }
    let len = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap());
    let Some(end) = (off as u64).checked_add(len) else {
        return;
    };
    if len < 32 || end > buf.len() as u64 {
        return;
    }
    let d = md5(&buf[off + 32..end as usize]);
    buf[off + 16..off + 32].copy_from_slice(&d);
}

const HOSTILE_U64: [u64; 14] = [
    0,
    1,
    3,
    4,
    63,
    64,
    65,
    66,
    1 << 31,
    1 << 32,
    1 << 40,
    1 << 62,
    u64::MAX - 3,
    u64::MAX,
];
const HOSTILE_U32: [u32; 10] = [
    0,
    1,
    32767,
    32768,
    65534,
    65535,
    65536,
    1 << 31,
    u32::MAX - 1,
    u32::MAX,
];

fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    if at + 8 <= buf.len() {
        buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
}
fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    if at + 4 <= buf.len() {
        buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// Overwrite a semantic body field of the packet at `(off, len)` with a hostile value.
/// Returns `true` when a field was changed.
fn mutate_field(rng: &mut Rng, buf: &mut [u8], off: usize, len: usize) -> bool {
    if len < 64 || off + len > buf.len() {
        return false;
    }
    let body = off + 64;
    let ty: [u8; 16] = buf[off + 48..off + 64].try_into().unwrap();
    let u64v = if rng.chance(3) {
        rng.next()
    } else {
        HOSTILE_U64[rng.below(HOSTILE_U64.len())]
    };
    let u32v = if rng.chance(3) {
        rng.next() as u32
    } else {
        HOSTILE_U32[rng.below(HOSTILE_U32.len())]
    };
    match &ty {
        b"PAR 2.0\0Main\0\0\0\0" => match rng.below(3) {
            0 => put_u64(buf, body, u64v),
            1 => put_u32(buf, body + 8, u32v),
            _ => {
                // Duplicate a file ID in the list (or zero one).
                let n = (len - 64).saturating_sub(12) / 16;
                if n >= 2 {
                    let a = body + 12 + 16 * rng.below(n);
                    let b = body + 12 + 16 * rng.below(n);
                    let id: [u8; 16] = buf[a..a + 16].try_into().unwrap();
                    buf[b..b + 16].copy_from_slice(&id);
                } else if n == 1 {
                    buf[body + 12..body + 28].fill(0);
                }
            }
        },
        b"PAR 2.0\0FileDesc" => match rng.below(3) {
            0 | 1 => put_u64(buf, body + 48, u64v),
            _ => buf[body..body + 16.min(len - 64)].fill(rng.next() as u8),
        },
        b"PAR 2.0\0IFSC\0\0\0\0" => {
            let at = body + rng.below(len - 64);
            put_u32(buf, at, u32v);
        }
        b"PAR 2.0\0RecvSlic" => put_u32(buf, body, u32v),
        _ => {
            if len > 64 {
                let at = body + rng.below(len - 64);
                buf[at] = rng.next() as u8;
            } else {
                return false;
            }
        }
    }
    true
}

fn mutate(rng: &mut Rng, src: &[u8]) -> Vec<u8> {
    let mut buf = src.to_vec();
    let rounds = 1 + rng.below(4);
    for _ in 0..rounds {
        let sp = spans(&buf);
        let pick = |rng: &mut Rng| sp.get(rng.below(sp.len())).copied();
        match rng.below(12) {
            // Bit flips.
            0 if !buf.is_empty() => {
                for _ in 0..1 + rng.below(8) {
                    let bit = rng.below(buf.len() * 8);
                    buf[bit / 8] ^= 1 << (bit % 8);
                }
            }
            // Byte overwrites.
            1 if !buf.is_empty() => {
                for _ in 0..1 + rng.below(8) {
                    let at = rng.below(buf.len());
                    buf[at] = rng.next() as u8;
                }
            }
            // Truncate at a packet boundary (optionally +/- a few bytes).
            2 => {
                if let Some((o, l)) = pick(rng) {
                    let mut cut = if rng.chance(2) { o } else { o + l };
                    if rng.chance(2) {
                        cut = cut.saturating_add(rng.below(80)).saturating_sub(40);
                    }
                    buf.truncate(cut.min(buf.len()));
                }
            }
            // Truncate at a random point.
            3 => {
                let cut = rng.below(buf.len() + 1);
                buf.truncate(cut);
            }
            // Duplicate a packet somewhere.
            4 => {
                if let (Some((o, l)), Some((d, _))) = (pick(rng), pick(rng)) {
                    let p = buf[o..o + l].to_vec();
                    buf.splice(d..d, p);
                }
            }
            // Swap / reorder two packets.
            5 => {
                if sp.len() >= 2 {
                    let mut packets: Vec<Vec<u8>> =
                        sp.iter().map(|&(o, l)| buf[o..o + l].to_vec()).collect();
                    let tail = buf[sp.last().map_or(0, |&(o, l)| o + l)..].to_vec();
                    if rng.chance(2) {
                        packets.reverse();
                    } else {
                        let a = rng.below(packets.len());
                        let b = rng.below(packets.len());
                        packets.swap(a, b);
                    }
                    buf = packets.concat();
                    buf.extend_from_slice(&tail);
                }
            }
            // Hostile header length.
            6 => {
                if let Some((o, l)) = pick(rng) {
                    let v = match rng.below(5) {
                        0 => HOSTILE_U64[rng.below(HOSTILE_U64.len())],
                        1 => (l as u64).wrapping_add(4 * (1 + rng.below(64) as u64)),
                        2 => (l as u64).saturating_sub(4 * (1 + rng.below(64) as u64)),
                        3 => l as u64 + 1 + rng.below(3) as u64,
                        _ => rng.next(),
                    };
                    put_u64(&mut buf, o + 8, v);
                    if rng.chance(2) {
                        fix_md5(&mut buf, o);
                    }
                }
            }
            // Hostile body field, MD5 fixed (mostly) so the body parser runs.
            7..=9 => {
                if let Some((o, l)) = pick(rng)
                    && mutate_field(rng, &mut buf, o, l)
                    && !rng.chance(8)
                {
                    fix_md5(&mut buf, o);
                }
            }
            // Shrink or grow a body while keeping the packet self-consistent.
            10 => {
                if let Some((o, l)) = pick(rng) {
                    let new_len = if rng.chance(2) {
                        64 + 4 * rng.below((l - 64) / 4 + 1)
                    } else {
                        l + 4 * (1 + rng.below(16))
                    };
                    let mut p = buf[o..o + l].to_vec();
                    p.resize(new_len, rng.next() as u8);
                    p[8..16].copy_from_slice(&(new_len as u64).to_le_bytes());
                    let d = md5(&p[32..]);
                    p[16..32].copy_from_slice(&d);
                    buf.splice(o..o + l, p);
                }
            }
            // Change a packet's type to another known type, fix MD5.
            _ => {
                if let (Some((o, _)), Some((t, _))) = (pick(rng), pick(rng)) {
                    let ty: [u8; 16] = buf[t + 48..t + 64].try_into().unwrap();
                    buf[o + 48..o + 64].copy_from_slice(&ty);
                    fix_md5(&mut buf, o);
                }
            }
        }
    }
    buf
}

// ---------------------------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------------------------

struct Ctx<'a> {
    dir: &'a Path,
    /// Session over the unmutated index of the seed this case came from.
    session: &'a StreamingParSession,
}

fn run_all(ctx: &Ctx<'_>, input: &[u8], case: u64) {
    let _ = inspect_par2(input, true);
    let _ = inspect_par2(input, false);
    let _ = inspect_par2_with(input, VerifyMode::None);
    let _ = inventory(input);
    let _ = display_name(input);
    let _ = file_descriptions(input);
    let _ = par_rs::twin::par2_set(input);
    for opts in [ScanOptions::FULL, ScanOptions::METADATA] {
        // A hostile metadata set must not explode session construction.
        if let Ok(set) = load_par2_bytes(input, opts)
            && set.main.is_some()
        {
            let _ = StreamingParSession::new(&set, ctx.dir, SessionOptions::default());
        }
    }
    let path = ctx.dir.join(format!("case-{}.par2", case % 4));
    std::fs::write(&path, input).unwrap();
    let _ = load_par2_file(&path, ScanOptions::FULL);
    let _ = ctx.session.on_recovery_volume_arrived(&path, None);
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| {
        let v = v.trim();
        v.strip_prefix("0x")
            .map_or_else(|| v.parse().ok(), |h| u64::from_str_radix(h, 16).ok())
    })
}

#[test]
fn mutation_fuzz_never_panics_hangs_or_overallocates() {
    let cases = env_u64("PAR_RS_FUZZ_CASES").unwrap_or(1_500);
    let seed = env_u64("PAR_RS_FUZZ_SEED").unwrap_or(0x5eed_9a72);
    eprintln!("packet_fuzz: PAR_RS_FUZZ_SEED={seed:#x} PAR_RS_FUZZ_CASES={cases}");

    let corpus = seeds();
    let dir = std::env::temp_dir().join(format!("par-rs-fuzz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sessions: Vec<StreamingParSession> = corpus
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let set = load_par2_bytes(&s.index, ScanOptions::FULL).unwrap();
            let base = dir.join(format!("seed-{i}"));
            std::fs::create_dir_all(&base).unwrap();
            StreamingParSession::new(&set, &base, SessionOptions::default()).unwrap()
        })
        .collect();

    // Watchdog: abort with the case number if one case stalls.
    let heartbeat = std::sync::Arc::new(AtomicU64::new(0));
    let done = std::sync::Arc::new(AtomicBool::new(false));
    {
        let (hb, done) = (heartbeat.clone(), done.clone());
        std::thread::spawn(move || {
            let start = Instant::now();
            let mut last = (u64::MAX, start);
            while !done.load(Ordering::Relaxed) {
                std::thread::park_timeout(Duration::from_millis(200));
                let now = hb.load(Ordering::Relaxed);
                if now != last.0 {
                    last = (now, Instant::now());
                } else if last.1.elapsed() > CASE_LIMIT * 3 {
                    die(
                        b"packet_fuzz: case stalled (seconds)",
                        last.1.elapsed().as_secs(),
                    );
                }
            }
        });
    }

    let started = Instant::now();
    let mut rng = Rng(seed);
    ARMED.store(true, Ordering::Relaxed);
    for case in 0..cases {
        CURRENT_CASE.store(case, Ordering::Relaxed);
        heartbeat.store(case, Ordering::Relaxed);
        let si = rng.below(corpus.len());
        let s = &corpus[si];
        let src = if s.volumes.is_empty() || rng.chance(2) {
            &s.index
        } else {
            &s.volumes[rng.below(s.volumes.len())]
        };
        let input = mutate(&mut rng, src);
        let ctx = Ctx {
            dir: &dir,
            session: &sessions[si],
        };
        let t = Instant::now();
        let r = catch_unwind(AssertUnwindSafe(|| run_all(&ctx, &input, case)));
        let took = t.elapsed();
        if r.is_err() || took > CASE_LIMIT {
            ARMED.store(false, Ordering::Relaxed);
            let dump = dir.join(format!("failing-case-{case}.par2"));
            let _ = std::fs::write(&dump, &input);
            panic!(
                "packet_fuzz case {case} {} (took {took:?}); reproduce with \
                 PAR_RS_FUZZ_SEED={seed:#x} PAR_RS_FUZZ_CASES={}; input saved to {}",
                if r.is_err() {
                    "panicked"
                } else {
                    "was too slow"
                },
                case + 1,
                dump.display()
            );
        }
    }
    ARMED.store(false, Ordering::Relaxed);
    done.store(true, Ordering::Relaxed);
    eprintln!("packet_fuzz: {cases} cases in {:?}", started.elapsed());
    drop(sessions);
    let _ = std::fs::remove_dir_all(&dir);
}
