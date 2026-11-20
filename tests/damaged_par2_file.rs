//! A damaged recovery volume (holes, zero-filled ranges, a truncated last packet) must not
//! make the set unverifiable: its valid packets are kept, only its intact recovery slices
//! count, and verification fails only when no loaded file has the Main or a `FileDesc` packet.

use par_rs::create::{Par2Set, SetOptions, VolumeScheme, build_set};
use par_rs::inspect::{PacketInfo, PacketKind, inspect_par2};
use par_rs::packet::{ScanOptions, load_par2_bytes, load_par2_collection, load_par2_file};
use par_rs::{
    NullObserver, Par2Repairer, RepairError, RepairOptions, RepairResult, SessionOptions,
    StreamingParSession,
};
use std::path::{Path, PathBuf};

const SLICE: usize = 4096;
/// Intact recovery slices left in the damaged volume by [`damage`].
const INTACT: u64 = 5;

fn data(n: usize, seed: u32) -> Vec<u8> {
    let mut s = seed.wrapping_mul(2_654_435_761) | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s as u8
        })
        .collect()
}

struct Fixture {
    dir: PathBuf,
    source: Vec<u8>,
    set: Par2Set,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 25 source slices, 16 recovery slices in two volumes of 8.
fn fixture(tag: &str) -> Fixture {
    let dir =
        std::env::temp_dir().join(format!("par-rs-damaged-par2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let source = data(100_000, 7);
    let set = build_set(
        "set",
        &[("a.bin", &source)],
        &SetOptions {
            slice_size: SLICE,
            recovery_blocks: 16,
            volumes: VolumeScheme::Uniform(8),
            ..SetOptions::default()
        },
    )
    .unwrap();
    Fixture { dir, source, set }
}

fn packets(bytes: &[u8], kind: PacketKind) -> Vec<PacketInfo> {
    inspect_par2(bytes, true)
        .packets
        .into_iter()
        .filter(|p| p.kind == kind)
        .collect()
}

/// Damage a volume of eight recovery slices the way missing articles do: a hole over the first
/// packet header, a zero-filled range inside the third payload, and a cut inside the last
/// recovery packet (losing the metadata copies after it). Slices 1, 3, 4, 5, 6 stay intact.
fn damage(vol: &[u8]) -> Vec<u8> {
    let rec = packets(vol, PacketKind::RecvSlic);
    assert_eq!(rec.len(), 8);
    let mut d = vol.to_vec();
    d[rec[0].offset..rec[0].offset + 200].fill(0);
    d[rec[2].offset + 100..rec[2].offset + 1100].fill(0);
    d.truncate(rec[7].offset + 1000);
    d
}

/// Write `a.bin` with `bad` corrupted slices.
fn write_source(fx: &Fixture, bad: usize) {
    let mut a = fx.source.clone();
    for k in 0..bad {
        a[k * 4 * SLICE + 7] ^= 0x5A;
    }
    std::fs::write(fx.dir.join("a.bin"), a).unwrap();
}

/// Write the index and the damaged second volume; returns their paths.
fn write_damaged_set(fx: &Fixture) -> (PathBuf, PathBuf) {
    let index = fx.dir.join("set.par2");
    std::fs::write(&index, &fx.set.index).unwrap();
    let (name, vol) = &fx.set.volumes[1];
    let vol_path = fx.dir.join(name);
    std::fs::write(&vol_path, damage(vol)).unwrap();
    (index, vol_path)
}

fn repairer(dir: &Path, index: &Path) -> Par2Repairer {
    let mut r = Par2Repairer::new(dir, RepairOptions::default());
    r.load_par2_set(index).unwrap();
    r.finalize().unwrap();
    r
}

#[test]
fn loaders_keep_valid_packets_and_count_only_intact_slices() {
    let fx = fixture("loaders");
    let (index, vol) = write_damaged_set(&fx);
    for opts in [ScanOptions::METADATA, ScanOptions::FULL] {
        let set = load_par2_file(&vol, opts).unwrap();
        assert_eq!(set.recovery_count() as u64, INTACT, "{opts:?}");
        assert!(set.stats.damaged());
        let set = load_par2_bytes(&std::fs::read(&vol).unwrap(), opts).unwrap();
        assert_eq!(set.recovery_count() as u64, INTACT, "{opts:?}");
    }
    let (set, loaded) = load_par2_collection(&index, ScanOptions::METADATA).unwrap();
    assert_eq!(loaded, vec![index.clone(), vol]);
    assert!(set.is_complete());
    assert_eq!(set.recovery_count() as u64, INTACT);
    assert_eq!(set.stats.corrupt_recovery, 1, "the zero-filled payload");
    let clean = load_par2_bytes(&fx.set.index, ScanOptions::METADATA).unwrap();
    assert!(!clean.stats.damaged());
}

#[test]
fn verify_and_repair_with_the_intact_slices_of_a_damaged_volume() {
    let fx = fixture("repair");
    let (index, vol) = write_damaged_set(&fx);
    write_source(&fx, INTACT as usize);
    let mut r = repairer(&fx.dir, &index);
    assert_eq!(r.recovery_blocks(), INTACT);
    let reports = r.par_file_reports();
    assert_eq!(reports.len(), 2);
    assert!(!reports[0].damaged());
    assert_eq!(reports[0].usable_recovery_slices, 0);
    assert!(reports[1].damaged());
    assert_eq!(reports[1].path, vol);
    assert_eq!(reports[1].usable_recovery_slices, INTACT);

    let v = r.verify(None, &mut NullObserver).unwrap();
    assert_eq!(v.recovery_blocks, INTACT);
    assert_eq!(v.missing_blocks, INTACT);
    assert!(v.repair_needed && v.repair_possible);
    assert_eq!(v.damaged_par_files, vec![vol]);
    let result = r.repair(&mut NullObserver).unwrap();
    assert!(
        matches!(
            result,
            RepairResult::Repaired {
                blocks_recovered: INTACT,
                ..
            }
        ),
        "{result:?}"
    );
    assert_eq!(std::fs::read(fx.dir.join("a.bin")).unwrap(), fx.source);
}

#[test]
fn damaged_volume_alone_is_not_enough_recovery() {
    let fx = fixture("short");
    let (index, _) = write_damaged_set(&fx);
    write_source(&fx, INTACT as usize + 1);
    let mut r = repairer(&fx.dir, &index);
    let v = r.verify(None, &mut NullObserver).unwrap();
    assert_eq!(v.recovery_blocks, INTACT);
    assert!(v.repair_needed && !v.repair_possible);
    assert_eq!(v.blocks_needed(), 1);
    assert!(matches!(
        r.repair(&mut NullObserver),
        Err(RepairError::NotEnoughRecovery {
            needed: 6,
            available: INTACT,
        })
    ));
}

/// The first file loaded is the damaged volume, and a hole also zeroed the set id of its
/// second recovery header (left unhashed by a metadata scan). That header must not capture
/// the set and turn the index away as a foreign set.
#[test]
fn damaged_header_loaded_first_does_not_capture_the_set() {
    let fx = fixture("first");
    let index = fx.dir.join("set.par2");
    std::fs::write(&index, &fx.set.index).unwrap();
    let (name, vol) = &fx.set.volumes[1];
    let mut d = damage(vol);
    let rec = packets(vol, PacketKind::RecvSlic);
    d[rec[1].offset + 40..rec[1].offset + 48].fill(0);
    let vol_path = fx.dir.join(name);
    std::fs::write(&vol_path, d).unwrap();
    write_source(&fx, 4);

    let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
    assert_eq!(r.load_par2_file(&vol_path).unwrap(), 4);
    assert_eq!(r.load_par2_file(&index).unwrap(), 0);
    r.finalize().unwrap();
    assert_eq!(r.set_id(), Some(fx.set.set_id));
    let v = r.verify(None, &mut NullObserver).unwrap();
    assert_eq!((v.missing_blocks, v.recovery_blocks), (4, 4));
    assert!(matches!(
        r.repair(&mut NullObserver).unwrap(),
        RepairResult::Repaired { .. }
    ));
    assert_eq!(std::fs::read(fx.dir.join("a.bin")).unwrap(), fx.source);

    // The same through the plain loader, and with a set that starts out unverified.
    let mut set = load_par2_file(&vol_path, ScanOptions::METADATA).unwrap();
    set.merge(load_par2_file(&index, ScanOptions::METADATA).unwrap());
    assert_eq!(set.set_id, Some(fx.set.set_id));
    assert!(set.is_complete());
}

#[test]
fn missing_main_or_descriptions_everywhere_fails_clearly() {
    let fx = fixture("nometa");
    let (name, vol) = &fx.set.volumes[1];
    let vol_path = fx.dir.join(name);
    std::fs::write(&vol_path, damage(vol)).unwrap();
    write_source(&fx, 1);
    // Only the damaged volume, whose metadata copies were cut off.
    let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
    r.load_par2_set(&vol_path).unwrap();
    assert!(matches!(r.finalize(), Err(RepairError::NoMainPacket)));

    // An index whose FileDesc packet fell into a hole.
    let mut index = fx.set.index.clone();
    let fd = &packets(&index, PacketKind::FileDesc)[0];
    let (start, end) = (fd.offset, fd.offset + fd.length as usize);
    index[start..end].fill(0);
    std::fs::write(fx.dir.join("set.par2"), &index).unwrap();
    let mut r = Par2Repairer::new(&fx.dir, RepairOptions::default());
    r.load_par2_set(&fx.dir.join("set.par2")).unwrap();
    assert!(matches!(
        r.finalize(),
        Err(RepairError::IncompleteMetadata { missing_descriptions }) if missing_descriptions.len() == 1
    ));
}

#[test]
fn live_session_absorbs_only_intact_slices_of_a_damaged_volume() {
    let fx = fixture("live");
    let (_, vol) = write_damaged_set(&fx);
    let set = load_par2_bytes(&fx.set.index, ScanOptions::FULL).unwrap();
    let root = fx.dir.join("live");
    std::fs::create_dir_all(&root).unwrap();
    let session = StreamingParSession::new(&set, &root, SessionOptions::default()).unwrap();
    assert_eq!(
        session.on_recovery_volume_arrived(&vol, None).unwrap() as u64,
        INTACT
    );
}
