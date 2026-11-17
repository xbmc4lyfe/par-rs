//! Randomized live-repair stress: articles of random sizes arrive out of order, some twice,
//! some lost for good and some corrupted, while recovery volumes arrive at random points. The
//! session runs with random staging caps, slot counts and fold threads, and is sometimes
//! cancelled part-way. Some scenarios also cap the RAM-only bytes kept for damaged slices. Every scenario checks the staging accounting, the final slice states,
//! and that the repaired files match the originals byte for byte.
//!
//! `PAR_RS_STRESS_SCENARIOS` sets the scenario count (default 48) and `PAR_RS_STRESS_SEED`
//! the base seed, so a failure can be replayed.

use super::*;

pub(super) struct Rng(pub(super) u64);

impl Rng {
    pub(super) fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in `lo..=hi`.
    pub(super) fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
    pub(super) fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Fate {
    Good,
    Lost,
    Corrupt,
    /// Lost first, then a good copy arrives later (a backup server).
    Replaced,
}

struct Article {
    file: usize,
    offset: u64,
    len: usize,
    fate: Fate,
    /// Offset within the article of the flipped byte (corrupt articles only).
    flip: usize,
}

enum Event {
    Article(usize),
    Replacement(usize),
    Recovery(usize),
}

pub(super) fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn live_randomized_damage_stress() {
    let scenarios = env_u64("PAR_RS_STRESS_SCENARIOS", 48);
    let base = env_u64("PAR_RS_STRESS_SEED", 0x0005_EED0_F5EE);
    for n in 0..scenarios {
        let seed = base.wrapping_add(n.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1;
        run_scenario(n, seed);
    }
}

#[allow(clippy::too_many_lines)]
fn run_scenario(n: u64, seed: u64) {
    let ctx = format!("scenario {n} (PAR_RS_STRESS_SEED base, seed {seed:#x})");
    let mut rng = Rng(seed);
    let slice = [512u64, 1024, 1536, 2048][rng.range(0, 3) as usize];
    let nfiles = rng.range(1, 3) as usize;
    let sizes: Vec<usize> = (0..nfiles)
        .map(|_| rng.range(1, 6 * slice + slice - 1) as usize)
        .collect();
    let recovery = rng.range(1, 6) as u32;
    let fx = fixture(
        &format!("stress-{n}"),
        &sizes,
        slice,
        recovery,
        VolumeScheme::Uniform(1),
    );
    let ids: Vec<FileId> = fx.files.iter().map(|(name, _)| fid(&fx, name)).collect();

    // Cut every file into articles of random size; give each a fate.
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
            let flip = (rng.next() % len as u64) as usize;
            articles.push(Article {
                file: fi,
                offset: off as u64,
                len,
                fate,
                flip,
            });
            off += len;
        }
    }

    // Every article once, about 15% of the good ones twice, and every recovery volume once,
    // all in random order.
    let mut events: Vec<Event> = (0..articles.len()).map(Event::Article).collect();
    for (i, a) in articles.iter().enumerate() {
        if a.fate == Fate::Good && rng.chance(15) {
            events.push(Event::Article(i));
        }
    }
    events.extend((0..fx.vols.len()).map(Event::Recovery));
    let order = shuffled(events.len(), rng.next());
    let mut events: std::collections::VecDeque<Event> = {
        let mut slots: Vec<Option<Event>> = events.into_iter().map(Some).collect();
        order.iter().map(|&i| slots[i].take().unwrap()).collect()
    };

    // 0: every article on disk; 1: every article RAM-only; 2: each article picks.
    let mode = rng.range(0, 2);
    // RAM-only bytes reach disk only after every event, as a slow writer would.
    let mut deferred: Vec<(std::path::PathBuf, u64, Vec<u8>)> = Vec::new();
    let cap = if rng.chance(40) {
        rng.range(slice, 4 * slice)
    } else {
        SessionOptions::default().max_staging_bytes
    };
    let preallocated_syndrome_slots = rng.range(0, u64::from(recovery)) as usize;
    let fold_threads = if rng.chance(50) { 0 } else { 2 };
    let cancel_at = rng
        .chance(15)
        .then(|| rng.range(0, events.len() as u64) as usize);
    let damaged_cap = rng.chance(30).then(|| rng.range(0, 2 * slice));
    let opts = SessionOptions {
        preallocated_syndrome_slots,
        max_staging_bytes: cap,
        fold_threads,
        max_damaged_staging_bytes: damaged_cap.unwrap_or(u64::MAX),
        ..SessionOptions::default()
    };
    let s = StreamingParSession::new(&fx.set, &fx.dir, opts).unwrap();

    let mut delivered = 0usize;
    let mut done_events = 0usize;
    while let Some(ev) = events.pop_front() {
        if cancel_at == Some(done_events) {
            s.cancel();
            let a = &articles[0];
            let data = &fx.files[a.file].1[..a.len];
            let r = s.on_article_finished_memory_only(&ids[a.file], 0, data, crc32(data));
            assert!(
                matches!(r, Err(RepairError::Cancelled)),
                "{ctx}: delivery after cancel must fail as Cancelled"
            );
            drop(s);
            std::fs::remove_dir_all(&fx.dir).unwrap();
            return;
        }
        done_events += 1;
        match ev {
            Event::Recovery(v) => {
                // A new recovery slot is back-filled from the target files, so pending
                // RAM-only writes must land first (the documented flush barrier).
                for (path, off, bytes) in deferred.drain(..) {
                    write_at(&path, off, &bytes);
                }
                s.on_recovery_volume_arrived(&fx.vols[v], None).unwrap();
            }
            Event::Article(i) | Event::Replacement(i) => {
                let replacement = matches!(ev, Event::Replacement(_));
                let a = &articles[i];
                let path = fx.dir.join(&fx.files[a.file].0);
                let id = &ids[a.file];
                let start = a.offset as usize;
                let mut bytes = fx.files[a.file].1[start..start + a.len].to_vec();
                match a.fate {
                    Fate::Replaced if !replacement => {
                        s.on_article_failed_permanently(id, a.offset, a.len as u64)
                            .unwrap();
                        let at = rng.range(0, events.len() as u64) as usize;
                        events.insert(at, Event::Replacement(i));
                        continue;
                    }
                    Fate::Lost => {
                        s.on_article_failed_permanently(id, a.offset, a.len as u64)
                            .unwrap();
                        continue;
                    }
                    Fate::Corrupt => {
                        bytes[a.flip] ^= 1 + (rng.next() % 255) as u8;
                    }
                    Fate::Good | Fate::Replaced => {}
                }
                let crc = crc32(&bytes);
                let ram = match mode {
                    0 => false,
                    1 => true,
                    _ => rng.chance(50),
                };
                if ram {
                    match s.on_article_finished_memory_only(id, a.offset, &bytes, crc) {
                        Ok(_) => {
                            delivered += bytes.len();
                            deferred.push((path.clone(), a.offset, bytes.clone()));
                        }
                        Err(RepairError::StreamingMemoryLimit { context, .. }) => {
                            if std::env::var_os("PAR_RS_STRESS_DUMP").is_some() {
                                eprintln!(
                                    "{ctx}: refused article {i} ({context}) state {:?}",
                                    s.status()
                                );
                            }
                            // Refused unchanged (the staging cap, or a duplicate into a slice
                            // that RAM alone can no longer complete): a downloader writes it
                            // to disk and reports it the ordinary way.
                            write_at(&path, a.offset, &bytes);
                            s.on_article_finished(id, a.offset, a.len as u64, crc, Some(&bytes))
                                .unwrap();
                            delivered += bytes.len();
                        }
                        Err(e) => panic!("{ctx}: memory-only article {i}: {e}"),
                    }
                } else {
                    write_at(&path, a.offset, &bytes);
                    s.on_article_finished(id, a.offset, a.len as u64, crc, Some(&bytes))
                        .unwrap_or_else(|e| panic!("{ctx}: article {i}: {e}"));
                    delivered += bytes.len();
                }
            }
        }
        if let Some(limit) = damaged_cap {
            let t = s.inner.tracker.lock().unwrap();
            let kept: u64 = t
                .staging
                .iter()
                .filter(|(g, _)| t.states[**g] == SliceState::Damaged)
                .map(|(_, st)| st.pieces.held() as u64)
                .sum();
            assert!(
                kept <= limit,
                "{ctx}: damaged staging {kept} exceeds {limit}"
            );
        }
        let held = s.staging_bytes();
        assert!(held <= cap, "{ctx}: staging {held} exceeds cap {cap}");
        assert!(
            held <= delivered as u64,
            "{ctx}: staging {held} exceeds the {delivered} bytes delivered"
        );
    }
    s.flush();

    // A slice is damaged when a lost article touches it or holds a corrupted byte.
    let mut damaged = std::collections::BTreeSet::new();
    for a in &articles {
        match a.fate {
            Fate::Good | Fate::Replaced => {}
            Fate::Lost => {
                let first = a.offset / slice;
                let last = (a.offset + a.len as u64 - 1) / slice;
                for si in first..=last {
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
    // With a damaged cap, a replaced slice whose RAM-only bytes were released before its
    // replacement arrived reads the gap from a file that lacks them, so it stays damaged.
    let mut damaged_count = damaged.len();
    if damaged_cap.is_some() {
        let mut maybe = damaged.clone();
        for a in articles.iter().filter(|a| a.fate == Fate::Replaced) {
            for si in a.offset / slice..=(a.offset + a.len as u64 - 1) / slice {
                maybe.insert((a.file, si));
            }
        }
        assert!(
            (damaged.len()..=maybe.len()).contains(&st.damaged),
            "{ctx}: damaged count {} outside {}..={}",
            st.damaged,
            damaged.len(),
            maybe.len()
        );
        damaged_count = st.damaged;
    }
    if std::env::var_os("PAR_RS_STRESS_DUMP").is_some()
        && (s.staging_bytes() != 0 || st.damaged != damaged_count)
    {
        eprintln!("{ctx}: slice {slice} sizes {sizes:?} mode {mode} cap {cap} status {st:?}");
        for a in &articles {
            eprintln!(
                "  f{} off {} len {} slices {}..={} {}",
                a.file,
                a.offset,
                a.len,
                a.offset / slice,
                (a.offset + a.len as u64 - 1) / slice,
                match a.fate {
                    Fate::Good => "good",
                    Fate::Replaced => "REPLACED",
                    Fate::Lost => "LOST",
                    Fate::Corrupt => "CORRUPT",
                }
            );
        }
    }
    if mode != 0 {
        // RAM-only bytes for a damaged slice stay staged in case a replacement arrives,
        // but nothing else may be left.
        let bound = damaged_count as u64 * slice;
        assert!(
            s.staging_bytes() <= bound,
            "{ctx}: staging {} beyond the {damaged_count} damaged slices",
            s.staging_bytes(),
        );
    } else {
        assert_eq!(
            s.staging_bytes(),
            0,
            "{ctx}: staging left after every article"
        );
    }
    assert_eq!(st.total, total, "{ctx}");
    assert_eq!(st.unarrived, 0, "{ctx}: unarrived slices");
    assert_eq!(st.partially_arrived, 0, "{ctx}: partial slices");
    assert_eq!(st.damaged, damaged_count, "{ctx}: damaged count");
    assert_eq!(st.verified, total - damaged_count, "{ctx}: verified count");

    for (path, off, bytes) in &deferred {
        write_at(path, *off, bytes);
    }
    let fits = damaged_count <= recovery as usize;
    assert_eq!(st.early_cutover_possible, fits, "{ctx}: cutover");
    let r = s.repair_available_targets_now(&ids);
    if fits {
        let rep = r.unwrap_or_else(|e| panic!("{ctx}: repair: {e}"));
        assert_eq!(rep.repaired_slices.len(), damaged_count, "{ctx}");
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
            damaged_count
        );
    }
    drop(s);
    std::fs::remove_dir_all(&fx.dir).unwrap();
}
