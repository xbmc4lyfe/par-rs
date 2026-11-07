//! The additions requested by the Atlas indexer (`docs/PARITY_REQUESTS.md` in its repo) and by
//! RustyGet (`PARITY_LIBRARY_ROUND2_RESPONSE.md`): set ids on the inventory and creator, the
//! Main-body-hashes-to-set-id check, IFSC CRCs on an article grid, the subject rule for base
//! `.par2` names, the optimistic inventory scan, `ParIgnoreExt` wildcard masks, and loading a
//! par2 collection without a repairer.

use par_rs::create::{SetOptions, VolumeScheme, build_set};
use par_rs::inspect::{CreatorInfo, PacketKind, VerifyMode, inspect_par2_with};
use par_rs::packet::{ScanOptions, load_par2_collection};
use par_rs::par2::{Inventory, inventory, inventory_from, is_base_par2};
use par_rs::repairer::{BackupPolicy, Par2Repairer, RepairObserver, RepairOptions, ignore_name_matches};
use par_rs::{Isa, Kernel};

fn data(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| ((i ^ seed.wrapping_mul(0x9E37_79B9)).wrapping_mul(2654435761) >> 13) as u8).collect()
}

fn opts(ss: usize, rec: u32) -> SetOptions {
    SetOptions { slice_size: ss, recovery_blocks: rec, volumes: VolumeScheme::Uniform(2), creator: "par-rs test 0.2.0".into(), kernel: Kernel::with_isa(Isa::Scalar).unwrap_or_else(Kernel::detect), ..SetOptions::default() }
}

/// The reference the fast path must equal byte for byte.
fn slow_inventory(buf: &[u8]) -> Inventory {
    inventory_from(&inspect_par2_with(buf, VerifyMode::Metadata))
}

#[test]
fn set_ids_and_main_body_hash() {
    let a = data(30_000, 1);
    let b = data(5_000, 2);
    let set = build_set("rel", &[("a.rar", &a), ("b.rar", &b)], &opts(2048, 3)).unwrap();
    let insp = inspect_par2_with(&set.index, VerifyMode::Metadata);
    assert_eq!(insp.main.len(), 1);
    assert!(insp.main[0].body_hashes_to_set_id, "a set made here hashes its Main body to the set id");
    assert_eq!(insp.creators.len(), 1);
    assert_eq!(insp.creators[0].set_id, Some(insp.main[0].set_id));
    assert_eq!(CreatorInfo::parse(b"QuickPar 0.9").set_id, None);
    let inv = inventory(&set.index);
    assert_eq!(inv.set_id, Some(insp.main[0].set_id));
    assert_eq!(inv.set_id.map(|s| s.to_vec()), Some(set.set_id.0.to_vec()));
    assert_eq!(inventory(b"").set_id, None);

    // A Main packet whose set id is not the hash of its body: patch the header's set id and
    // recompute the packet MD5 so the packet itself still verifies.
    let main_pkt = insp.packets.iter().find(|p| p.kind == PacketKind::Main).unwrap();
    let mut forged = set.index.clone();
    let (off, len) = (main_pkt.offset, main_pkt.length as usize);
    forged[off + 32] ^= 0x55;
    let md5 = par_rs::hasher::md5(&forged[off + 32..off + len]);
    forged[off + 16..off + 32].copy_from_slice(&md5);
    let insp2 = inspect_par2_with(&forged, VerifyMode::Metadata);
    assert_eq!(insp2.bad_md5, 0);
    assert_eq!(insp2.main.len(), 1);
    assert!(!insp2.main[0].body_hashes_to_set_id);
    // The forged Main now heads a set of its own; the files stay with the original set id.
    let inv2 = inventory(&forged);
    assert_eq!(inv2.set_id, Some(insp2.main[0].set_id));
    assert_eq!(inv2.files.len(), 2);
    assert_eq!(inv2, slow_inventory(&forged));
}

#[test]
fn base_par2_subject_rule() {
    // The table from Atlas's request, then the older cases.
    let cases = [
        (r#""a.par2" yEnc"#, true),
        ("a.par2.rar", false),
        ("a.par2-1", false),
        ("(a.par2)", true),
        ("[a.par2]", true),
        (r#""a.vol00+01.par2" and "b.par2""#, true),
        ("a.vol00+01.par2", false),
        ("Release.Name-GRP [1/50] - \"release.par2\" yEnc (1/1)", true),
        ("release.PAR2", true),
        ("Release [2/50] - \"release.vol000+01.par2\" yEnc", false),
        ("release.vol07-13.par2", false),
        ("release.part01.rar", false),
        ("odd.vol.par2", true),
        ("a.par2 and b.vol0+1.par2", true),
        ("par2 is in the text but not a file", false),
        (".par2", true),
        ("\".par2\"", true),
        (r#"(  [  obfuscated  ]   ) [01/16] - ".par2" yEnc"#, true),
        ("a.par2\tyEnc", true),
        ("a.par2;", false),
        ("<a.par2>", true),
        ("x.PaR2", true),
        ("x.par2x", false),
        ("", false),
        // A closing bracket belongs to the name: these are real base par2 subjects.
        (r#""Show (2026).par2" yEnc (1/1)"#, true),
        ("Movie.2026.1080p[rartv].par2", true),
        ("a (1).par2", true),
        ("[HorribleSubs]_AIURA_-_01_[480p].par2", true),
        ("[Chyuu] Nanatsu no Taizai - 12 [720p][D1F49539].par2", true),
        ("Marillion - Live From Cadogan Hall 2011 (DVD 1).par2", true),
        ("100 Hits - Lady Sings The Blues 2006 (5cd's).par2", true),
        ("Guido Negraszus - Lounge (2012)(320).par2", true),
        ("Assassins Creed - Bloodlines [EUR].par2", true),
        ("Show (2026).vol000+01.par2", false),
        ("Show (2026).par2.rar", false),
        ("Show (2026).par2-1", false),
        ("(2026).par2", true),
        ("().par2", true),
        ("a (1).par2 and b.vol0+1.par2", true),
    ];
    for (subject, want) in cases {
        assert_eq!(is_base_par2(subject), want, "{subject:?}");
    }
}

#[test]
fn optimistic_inventory_equals_the_resynchronising_scanner() {
    let files: Vec<Vec<u8>> = (0..12).map(|i| data(3_000 + i * 1_777, 10 + i as u32)).collect();
    let names: Vec<String> = (0..12).map(|i| if i % 4 == 0 { format!("fïlé{i}.rar") } else { format!("file{i}.rar") }).collect();
    let srcs: Vec<(&str, &[u8])> = names.iter().zip(&files).map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    let set = build_set("rel", &srcs, &opts(1024, 9)).unwrap();
    let full = inventory(&set.index);
    assert_eq!(full.files.len(), 12);
    assert!(full.complete);
    assert_eq!(full, slow_inventory(&set.index));
    // Index followed by a volume (recovery data present, never hashed), then two sets in one buffer.
    let mut joined = set.index.clone();
    joined.extend_from_slice(&set.volumes[0].1);
    assert_eq!(inventory(&joined), slow_inventory(&joined));
    let other = build_set("other", &srcs[..3], &opts(4096, 2)).unwrap();
    joined.extend_from_slice(&other.index);
    let two = inventory(&joined);
    assert_eq!(two, slow_inventory(&joined));
    assert_eq!(two.set_id, full.set_id);
    assert_eq!(two.files.len(), 15);
    // Every prefix.
    for cut in (0..set.index.len()).step_by(61).chain([set.index.len() - 1]) {
        let buf = &set.index[..cut];
        assert_eq!(inventory(buf), slow_inventory(buf), "prefix {cut}");
    }
    // Bit flips everywhere (headers, bodies, MD5s): the fast path must fall back, never diverge.
    for pos in (0..set.index.len()).step_by(37) {
        let mut buf = set.index.clone();
        buf[pos] ^= 0x10;
        assert_eq!(inventory(&buf), slow_inventory(&buf), "flip at {pos}");
    }
    // Garbage between packets and a torn header.
    let mut buf = Vec::new();
    for p in &inspect_par2_with(&set.index, VerifyMode::None).packets {
        buf.extend_from_slice(b"PAR2\0PKT\x40\0\0\0\0\0\0\0junk");
        buf.extend_from_slice(&set.index[p.offset..p.offset + p.length as usize]);
    }
    assert_eq!(inventory(&buf), slow_inventory(&buf));
    assert_eq!(inventory(&buf).files.len(), 12);
}

#[test]
fn ignore_extensions_accept_wildcard_masks() {
    for (name, entry, want) in [
        ("release.nfo", ".nfo", true),
        ("release.NFO", ".nfo", true),
        ("release.nfo", "nfo", true),
        ("release.nfo", "*.nfo", true),
        ("release.nfo", "*", true),
        ("release.nfo", "release.???", true),
        ("release.nfo", "REL*.nfo", true),
        ("release.nfo", "*.sfv", false),
        ("release.nfo", "?.nfo", false),
        ("release.nfo", "", false),
        ("sub/dir/release.nfo", "*.nfo", true),
        ("sub/dir/release.nfo", "sub*", true),
        ("sub/dir/release.nfo", "release*", false),
        ("extras/clip.mkv", "clip*", false),
        ("extras/clip.mkv", "*/clip*", true),
        ("a.part01.rar", "*.part??.rar", true),
        ("a.part1.rar", "*.part??.rar", false),
        ("x", "*x*", true),
        ("aaab", "*ab", true),
        ("aaab", "*a?b", true),
        ("aaab", "a*c", false),
        // nzbget's WildMask: `#` is one digit inside a mask; a literal file name is a suffix match.
        ("sample01.nfo", "sample##.*", true),
        ("sample1.nfo", "sample##.*", false),
        ("sampleAB.nfo", "sample##.*", false),
        ("readme.nfo", "readme.nfo", true),
        ("README.NFO", "readme.nfo", true),
        ("xreadme.nfo", "readme.nfo", true),
        ("sub/readme.nfo", "readme.nfo", true),
    ] {
        assert_eq!(ignore_name_matches(name, entry), want, "{name:?} vs {entry:?}");
    }

    // RustyGet's test: ParIgnoreExt=* with a damaged .dat and an intact .nfo: nothing to repair,
    // and only the intact file is complete.
    let dat = data(20_000, 5);
    let nfo = data(900, 6);
    let set = build_set("testfile", &[("testfile.dat", &dat), ("testfile.nfo", &nfo)], &opts(1024, 4)).unwrap();
    let dir = std::env::temp_dir().join(format!("par-rs-ignore-glob-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let written = set.write_to(&dir, "testfile").unwrap();
    let mut damaged = dat.clone();
    damaged[3_000] ^= 0xFF;
    std::fs::write(dir.join("testfile.dat"), &damaged).unwrap();
    std::fs::write(dir.join("testfile.nfo"), &nfo).unwrap();
    struct Quiet;
    impl RepairObserver for Quiet {}
    let mut rep = Par2Repairer::new(&dir, RepairOptions { ignore_extensions: vec!["*".into()], backup: BackupPolicy::RenameNumbered, ..RepairOptions::default() });
    rep.load_par2_set(&written[0]).unwrap();
    rep.finalize().unwrap();
    assert!(rep.source_files().iter().all(|f| f.ignored));
    let res = rep.verify(None, &mut Quiet).unwrap();
    assert!(!res.repair_needed, "damage confined to ignored files");
    assert_eq!(res.missing_blocks, 1);
    assert_eq!(res.ignored_damaged, vec!["testfile.dat".to_string()]);
    let complete: Vec<&str> = rep.source_files().iter().filter(|f| f.status == par_rs::repairer::FileStatus::Complete).map(|f| f.target_filename.as_str()).collect();
    assert_eq!(complete, vec!["testfile.nfo"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn load_collection_without_a_repairer() {
    let a = data(9_000, 21);
    let set = build_set("rel", &[("a.bin", &a)], &opts(1024, 6)).unwrap();
    let other = build_set("rel2", &[("a.bin", &a)], &opts(512, 2)).unwrap();
    let dir = std::env::temp_dir().join(format!("par-rs-collection-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let written = set.write_to(&dir, "rel").unwrap();
    assert!(written.len() >= 2);
    // Same base name, different set: must be skipped; unrelated name: never looked at.
    std::fs::write(dir.join("REL.vol9+2.PAR2"), &other.volumes[0].1).unwrap();
    std::fs::write(dir.join("rel2.par2"), &other.index).unwrap();
    let (pkts, loaded) = load_par2_collection(&written[0], ScanOptions::METADATA).unwrap();
    assert_eq!(loaded[0], written[0]);
    assert_eq!(loaded.len(), written.len(), "{loaded:?} recovery={:?}", pkts.recovery.values().map(|r| (r.exponent, r.source_id)).collect::<Vec<_>>());
    assert!(loaded.iter().all(|p| written.contains(p)));
    assert_eq!(pkts.recovery.len(), 6);
    assert_eq!(pkts.set_id.map(|s| s.0.to_vec()), Some(set.set_id.0.to_vec()));
    assert!(pkts.recovery.values().all(|r| r.source_id < loaded.len()));
    std::fs::remove_dir_all(&dir).unwrap();
}
