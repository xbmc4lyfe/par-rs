//! Multi-threaded live-repair stress: the scenario model of `stress_tests`, but every scenario
//! delivers its events from 4 to 8 threads at once, the way several downloader threads share
//! one session. Articles are dealt to threads at random, so pieces of one slice, duplicates,
//! and a loss and its replacement race each other (a replacement still follows its loss in
//! that thread's order). Recovery volumes arrive interleaved with articles: a reader-writer
//! lock keeps every RAM-only article's deferred write ahead of the next back-fill, which is
//! the documented flush barrier. Some scenarios cancel from another thread mid-flight, and a
//! watcher thread samples the staging total against the cap the whole time.
//!
//! `PAR_RS_CONC_SCENARIOS` sets the scenario count (default 24) and `PAR_RS_CONC_SEED` the
//! base seed. Thread interleavings are not reproducible, but each seed fixes the fixture,
//! fates, options and the event order of every thread.

use super::stress_tests::{Fate, Rng, env_u64};
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

struct Article {
    file: usize,
    offset: u64,
    len: usize,
    fate: Fate,
    flip: usize,
    flip_xor: u8,
}

#[derive(Clone, Copy)]
enum Event {
    Article(usize),
    Recovery(usize),
}

#[test]
fn live_concurrent_damage_stress() {
    let scenarios = env_u64("PAR_RS_CONC_SCENARIOS", 24);
    let base = env_u64("PAR_RS_CONC_SEED", 0x00C0_9C0F_F5EE);
    for n in 0..scenarios {
        let seed = base.wrapping_add(n.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1;
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            run_scenario(n, seed);
            let _ = tx.send(());
        });
        match rx.recv_timeout(Duration::from_secs(120)) {
            Ok(()) => worker.join().unwrap(),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if let Err(e) = worker.join() {
                    eprintln!("concurrent scenario {n} failed, seed {seed:#x}");
                    std::panic::resume_unwind(e);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("concurrent scenario {n} hung (seed {seed:#x})")
            }
        }
    }
}

struct Shared<'a> {
    s: &'a StreamingParSession,
    fx: &'a Fx,
    ids: &'a [FileId],
    articles: &'a [Article],
    ctx: &'a str,
    /// Readers: RAM-only deliveries until their bytes sit in `deferred`. Writer: a recovery
    /// volume, which drains `deferred` to disk first.
    barrier: RwLock<()>,
    deferred: Mutex<Vec<(PathBuf, u64, Vec<u8>)>>,
    delivered: AtomicU64,
}

/// Run one thread's events. Returns `false` when the session was cancelled under it.
fn run_thread(sh: &Shared, mut rng: Rng, mut events: Vec<Event>, mode: u64) -> bool {
    let ctx = sh.ctx;
    let s = sh.s;
    let mut replaced_pending = std::collections::BTreeSet::new();
    let mut i_ev = 0;
    macro_rules! ok_or_cancel {
        ($r:expr, $what:expr) => {
            match $r {
                Ok(v) => v,
                Err(RepairError::Cancelled) => return false,
                Err(e) => panic!("{ctx}: {}: {e}", $what),
            }
        };
    }
    while i_ev < events.len() {
        let ev = events[i_ev];
        i_ev += 1;
        match ev {
            Event::Recovery(v) => {
                let _w = sh.barrier.write().unwrap();
                for (path, off, bytes) in sh.deferred.lock().unwrap().drain(..) {
                    write_at(&path, off, &bytes);
                }
                ok_or_cancel!(
                    s.on_recovery_volume_arrived(&sh.fx.vols[v], None),
                    format!("recovery volume {v}")
                );
            }
            Event::Article(i) => {
                let a = &sh.articles[i];
                let path = sh.fx.dir.join(&sh.fx.files[a.file].0);
                let id = &sh.ids[a.file];
                let start = a.offset as usize;
                let mut bytes = sh.fx.files[a.file].1[start..start + a.len].to_vec();
                match a.fate {
                    Fate::Replaced if replaced_pending.insert(i) => {
                        ok_or_cancel!(
                            s.on_article_failed_permanently(id, a.offset, a.len as u64),
                            format!("loss of article {i}")
                        );
                        let at = rng.range(i_ev as u64, events.len() as u64) as usize;
                        events.insert(at, Event::Article(i));
                        continue;
                    }
                    Fate::Lost => {
                        ok_or_cancel!(
                            s.on_article_failed_permanently(id, a.offset, a.len as u64),
                            format!("loss of article {i}")
                        );
                        continue;
                    }
                    Fate::Corrupt => bytes[a.flip] ^= a.flip_xor,
                    Fate::Good | Fate::Replaced => {}
                }
                let crc = crc32(&bytes);
                let ram = match mode {
                    0 => false,
                    1 => true,
                    _ => rng.chance(50),
                };
                if ram {
                    let guard = sh.barrier.read().unwrap();
                    match s.on_article_finished_memory_only(id, a.offset, &bytes, crc) {
                        Ok(_) => {
                            sh.deferred.lock().unwrap().push((
                                path.clone(),
                                a.offset,
                                bytes.clone(),
                            ));
                            drop(guard);
                        }
                        Err(RepairError::StreamingMemoryLimit { .. }) => {
                            drop(guard);
                            write_at(&path, a.offset, &bytes);
                            ok_or_cancel!(
                                s.on_article_finished(
                                    id,
                                    a.offset,
                                    a.len as u64,
                                    crc,
                                    Some(&bytes)
                                ),
                                format!("refused article {i} on disk")
                            );
                        }
                        Err(RepairError::Cancelled) => return false,
                        Err(e) => panic!("{ctx}: memory-only article {i}: {e}"),
                    }
                } else {
                    write_at(&path, a.offset, &bytes);
                    ok_or_cancel!(
                        s.on_article_finished(id, a.offset, a.len as u64, crc, Some(&bytes)),
                        format!("article {i}")
                    );
                }
                sh.delivered
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
        }
    }
    true
}

#[allow(clippy::too_many_lines)]
fn run_scenario(n: u64, seed: u64) {
    let ctx = format!("concurrent scenario {n} (seed {seed:#x})");
    let mut rng = Rng(seed);
    let slice = [512u64, 1024, 1536, 2048][rng.range(0, 3) as usize];
    let nfiles = rng.range(1, 3) as usize;
    let sizes: Vec<usize> = (0..nfiles)
        .map(|_| rng.range(1, 6 * slice + slice - 1) as usize)
        .collect();
    let recovery = rng.range(1, 6) as u32;
    let fx = fixture(
        &format!("conc-{n}"),
        &sizes,
        slice,
        recovery,
        VolumeScheme::Uniform(1),
    );
    let ids: Vec<FileId> = fx.files.iter().map(|(name, _)| fid(&fx, name)).collect();

    // Small articles so several share a slice and race on it.
    let mut articles = Vec::new();
    for (fi, (_, data)) in fx.files.iter().enumerate() {
        let mut off = 0usize;
        while off < data.len() {
            let len = (rng.range(1, slice + slice / 2) as usize).min(data.len() - off);
            let fate = match rng.next() % 100 {
                0..=9 => Fate::Lost,
                10..=17 => Fate::Corrupt,
                18..=25 => Fate::Replaced,
                _ => Fate::Good,
            };
            articles.push(Article {
                file: fi,
                offset: off as u64,
                len,
                fate,
                flip: (rng.next() % len as u64) as usize,
                flip_xor: 1 + (rng.next() % 255) as u8,
            });
            off += len;
        }
    }

    let threads = rng.range(4, 8) as usize;
    let mut per_thread: Vec<Vec<Event>> = vec![Vec::new(); threads];
    let by_file = rng.chance(25);
    for (i, a) in articles.iter().enumerate() {
        let t = if by_file {
            (a.file + rng.range(0, 1) as usize) % threads
        } else {
            rng.range(0, threads as u64 - 1) as usize
        };
        per_thread[t].push(Event::Article(i));
        // Duplicates go to a different thread, so the two copies race.
        if a.fate == Fate::Good && rng.chance(20) {
            let u = (t + 1 + rng.range(0, threads as u64 - 2) as usize) % threads;
            per_thread[u].push(Event::Article(i));
        }
    }
    for v in 0..fx.vols.len() {
        let t = rng.range(0, threads as u64 - 1) as usize;
        per_thread[t].push(Event::Recovery(v));
    }
    for evs in &mut per_thread {
        let order = shuffled(evs.len(), rng.next());
        *evs = order.iter().map(|&i| evs[i]).collect();
    }

    let mode = rng.range(0, 2);
    let cap = if rng.chance(40) {
        rng.range(slice, 4 * slice)
    } else {
        SessionOptions::default().max_staging_bytes
    };
    let opts = SessionOptions {
        preallocated_syndrome_slots: rng.range(0, u64::from(recovery)) as usize,
        max_staging_bytes: cap,
        fold_threads: if rng.chance(50) { 0 } else { 2 },
        fold_queue_depth: rng.range(1, 8) as usize,
        ..SessionOptions::default()
    };
    let session = StreamingParSession::new(&fx.set, &fx.dir, opts).unwrap();
    let s = &session;
    let cancel_after = rng.chance(15).then(|| rng.range(0, 3000));
    let sh = Shared {
        s,
        fx: &fx,
        ids: &ids,
        articles: &articles,
        ctx: &ctx,
        barrier: RwLock::new(()),
        deferred: Mutex::new(Vec::new()),
        delivered: AtomicU64::new(0),
    };
    let stop = AtomicBool::new(false);
    let start = std::sync::Barrier::new(threads + 1);
    let (finished, over_cap) = std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let mut worst = 0u64;
            while !stop.load(Ordering::Acquire) {
                worst = worst.max(s.staging_bytes());
                std::thread::yield_now();
            }
            worst
        });
        let canceller = cancel_after.map(|us| {
            scope.spawn(move || {
                std::thread::sleep(Duration::from_micros(us));
                s.cancel();
            })
        });
        let workers: Vec<_> = per_thread
            .into_iter()
            .map(|evs| {
                let thread_rng = Rng(rng.next() | 1);
                let (sh, start) = (&sh, &start);
                scope.spawn(move || {
                    start.wait();
                    run_thread(sh, thread_rng, evs, mode)
                })
            })
            .collect();
        start.wait();
        let finished: Vec<bool> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        if let Some(c) = canceller {
            c.join().unwrap();
        }
        stop.store(true, Ordering::Release);
        (finished, watcher.join().unwrap())
    });
    assert!(
        over_cap <= cap,
        "{ctx}: staging {over_cap} exceeded cap {cap}"
    );
    if cancel_after.is_some() {
        // Every thread stopped cleanly; a cancel landing after all events is a normal finish.
        assert!(s.is_cancelled(), "{ctx}");
        drop(session);
        std::fs::remove_dir_all(&fx.dir).unwrap();
        return;
    }
    assert!(finished.iter().all(|&f| f), "{ctx}: thread saw Cancelled");
    s.flush();
    let delivered = sh.delivered.load(Ordering::Relaxed);
    assert!(
        s.staging_bytes() <= delivered,
        "{ctx}: staging beyond delivered"
    );

    let mut damaged = std::collections::BTreeSet::new();
    for a in &articles {
        match a.fate {
            Fate::Good | Fate::Replaced => {}
            Fate::Lost => {
                for si in a.offset / slice..=(a.offset + a.len as u64 - 1) / slice {
                    damaged.insert((a.file, si));
                }
            }
            Fate::Corrupt => {
                damaged.insert((a.file, (a.offset + a.flip as u64) / slice));
            }
        }
    }
    let total: usize = sizes
        .iter()
        .map(|&z| (z as u64).div_ceil(slice) as usize)
        .sum();
    let st = s.status();
    if mode != 0 {
        let bound = damaged.len() as u64 * slice;
        assert!(
            s.staging_bytes() <= bound,
            "{ctx}: staging {} beyond the {} damaged slices",
            s.staging_bytes(),
            damaged.len()
        );
    } else {
        assert_eq!(
            s.staging_bytes(),
            0,
            "{ctx}: staging left after every article"
        );
    }
    assert_eq!(st.total, total, "{ctx}");
    assert_eq!(st.unarrived, 0, "{ctx}: unarrived slices {st:?}");
    assert_eq!(st.partially_arrived, 0, "{ctx}: partial slices {st:?}");
    assert_eq!(st.damaged, damaged.len(), "{ctx}: damaged count {st:?}");
    assert_eq!(
        st.verified,
        total - damaged.len(),
        "{ctx}: verified count {st:?}"
    );

    for (path, off, bytes) in sh.deferred.lock().unwrap().drain(..) {
        write_at(&path, off, &bytes);
    }
    let fits = damaged.len() <= recovery as usize;
    assert_eq!(st.early_cutover_possible, fits, "{ctx}: cutover");
    let r = s.repair_available_targets_now(&ids);
    if fits {
        let rep = r.unwrap_or_else(|e| panic!("{ctx}: repair: {e}"));
        assert_eq!(rep.repaired_slices.len(), damaged.len(), "{ctx}");
        for (name, data) in &fx.files {
            assert!(
                std::fs::read(fx.dir.join(name)).unwrap() == *data,
                "{ctx}: {name} differs after repair"
            );
        }
    } else {
        assert!(
            matches!(r, Err(RepairError::NotEnoughRecovery { .. })),
            "{ctx}: {} damaged with {recovery} recovery should not repair",
            damaged.len()
        );
    }
    drop(session);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}

/// A RAM-only piece that completes its slice is admitted without counting against the
/// staging cap, so it must not stay charged while its slice is hashed and folded: two
/// half-slices fill the cap, and a third completes slice 0 while its fold is held up.
#[test]
fn live_completing_piece_is_not_charged_past_the_cap() {
    let slice = 1024u64;
    let fx = fixture(
        "conc-cap",
        &[2 * slice as usize],
        slice,
        1,
        VolumeScheme::Uniform(1),
    );
    let id = fid(&fx, &fx.files[0].0);
    let data = &fx.files[0].1;
    let half = (slice / 2) as usize;
    let opts = SessionOptions {
        preallocated_syndrome_slots: 1,
        max_staging_bytes: slice,
        fold_threads: 0,
        ..SessionOptions::default()
    };
    let s = StreamingParSession::new(&fx.set, &fx.dir, opts).unwrap();
    let put = |off: usize| {
        let d = &data[off..off + half];
        s.on_article_finished_memory_only(&id, off as u64, d, crc32(d))
    };
    put(0).unwrap();
    put(slice as usize).unwrap();
    assert_eq!(s.staging_bytes(), slice);
    std::thread::scope(|scope| {
        let hold = s.inner.slots.write().unwrap();
        let completer = scope.spawn(|| put(half).unwrap());
        // `status()` reads the slot list, so poll the tracker directly.
        while s.inner.tracker.lock().unwrap().states[0] != SliceState::VerifiedGood {
            std::thread::yield_now();
        }
        // The completer is now blocked folding slice 0.
        let held = s.staging_bytes();
        assert!(
            held <= slice,
            "staging {held} past the {slice}-byte cap mid-fold"
        );
        drop(hold);
        completer.join().unwrap();
    });
    assert_eq!(s.staging_bytes(), slice / 2);
    drop(s);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}
