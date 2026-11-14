// Licensed under GPL-2.0-or-later, matching Cargo.toml.
//! Explicit exponential filename spelling through public creator APIs.
use par_rs::{
    CreateOptions, SetOptions, SourceFile, VolumeNaming, build_set_with_volume_naming,
    create_with_volume_naming,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Root {
    path: PathBuf,
    retain: bool,
}
impl Root {
    fn new() -> Self {
        let retained = std::env::var_os("PAR2_NAMING_TEST_ARTIFACT_DIR");
        let path = retained
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "par-rs-naming-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&path).unwrap();
        Self {
            path,
            retain: retained.is_some(),
        }
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if !self.retain {
            std::fs::remove_dir_all(&self.path).unwrap();
        }
    }
}
#[test]
fn exponential_compatibility_names_at_ten_recovery_slices() {
    let root = Root::new();
    let data: Vec<_> = (0..64).collect();
    let files = [("empty.bin", b"".as_slice()), ("data.bin", data.as_slice())];
    let set = build_set_with_volume_naming(
        "set",
        &files,
        &SetOptions {
            slice_size: 16,
            recovery_blocks: 10,
            ..Default::default()
        },
        VolumeNaming::Par2cmdlineExponential,
    )
    .unwrap();
    let sources: Vec<_> = files
        .iter()
        .map(|(name, data)| {
            let path = root.path.join(name);
            std::fs::write(&path, data).unwrap();
            SourceFile::new(path)
        })
        .collect();
    let report = create_with_volume_naming(
        &sources,
        &root.path.join("disk"),
        "set",
        &CreateOptions {
            slice_size: 16,
            recovery_blocks: 10,
            ..Default::default()
        },
        VolumeNaming::Par2cmdlineExponential,
        None,
        &mut |_, _, _| {},
    )
    .unwrap();
    let memory_names: Vec<_> = set.volumes.iter().map(|(name, _)| name.as_str()).collect();
    let disk_names: Vec<_> = report
        .files
        .iter()
        .skip(1)
        .map(|p| p.file_name().unwrap().to_str().unwrap())
        .collect();
    let expected = [
        "set.vol00+1.par2",
        "set.vol01+2.par2",
        "set.vol03+4.par2",
        "set.vol07+3.par2",
    ];
    assert_eq!(
        (memory_names.as_slice(), disk_names.as_slice()),
        (expected.as_slice(), expected.as_slice())
    );
}

fn options(total: u32, first: u32, scheme: par_rs::VolumeScheme) -> (CreateOptions, SetOptions) {
    // Complete external literals deliberately pin the unchanged public structs.
    let disk = CreateOptions {
        slice_size: 16,
        recovery_blocks: total,
        first_exponent: first,
        volumes: scheme,
        creator: "par-rs-naming-test".into(),
        engine: par_rs::EngineConfig {
            num_threads: 1,
            mem_limit_bytes: 16 << 20,
            ..Default::default()
        },
        kernel: par_rs::Kernel::scalar(),
    };
    let memory = SetOptions {
        slice_size: 16,
        recovery_blocks: total,
        first_exponent: first,
        volumes: scheme,
        creator: disk.creator.clone(),
        unicode_names: false,
        kernel: disk.kernel,
    };
    (disk, memory)
}

fn disk_set(report: &par_rs::CreateReport) -> par_rs::Par2Set {
    let mut actual: Vec<_> = std::fs::read_dir(report.files[0].parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let mut reported = report.files.clone();
    actual.sort();
    reported.sort();
    assert_eq!(actual, reported);
    par_rs::Par2Set {
        set_id: report.set_id,
        input_slices: report.input_slices as usize,
        index: std::fs::read(&report.files[0]).unwrap(),
        volumes: report
            .files
            .iter()
            .skip(1)
            .map(|p| {
                (
                    p.file_name().unwrap().to_str().unwrap().to_owned(),
                    std::fs::read(p).unwrap(),
                )
            })
            .collect(),
    }
}

fn raw_packets(bytes: &[u8], id: par_rs::packet::SetId) -> Vec<par_rs::packet::RawPacket> {
    use par_rs::packet::{PacketIter, ScanOptions};
    let mut iter = PacketIter::new(
        bytes,
        ScanOptions {
            resync: false,
            ..ScanOptions::FULL
        },
    );
    let packets: Vec<_> = iter.by_ref().map(Result::unwrap).collect();
    assert_eq!(iter.stats().md5_failures, 0);
    assert_eq!(iter.stats().skipped_bytes, 0);
    let mut cursor = 0;
    for packet in &packets {
        assert!(packet.md5_verified);
        assert_eq!(packet.header.set_id, id);
        assert_eq!(packet.offset as usize, cursor);
        cursor += packet.header.length as usize;
    }
    assert_eq!(cursor, bytes.len());
    packets
}

type Volumes<'a> = std::collections::BTreeMap<Vec<u32>, &'a [u8]>;
fn packet_volumes(set: &par_rs::Par2Set) -> Volumes<'_> {
    use par_rs::packet::{TYPE_CREATOR, TYPE_FILEDESC, TYPE_IFSC, TYPE_MAIN, TYPE_RECVSLIC};
    let critical: std::collections::BTreeSet<_> = raw_packets(&set.index, set.set_id)
        .iter()
        .map(|p| {
            assert!(
                [TYPE_MAIN, TYPE_FILEDESC, TYPE_IFSC, TYPE_CREATOR].contains(&p.header.packet_type)
            );
            set.index[p.offset as usize..(p.offset + p.header.length) as usize].to_vec()
        })
        .collect();
    let mut volumes = Volumes::new();
    for (_, bytes) in &set.volumes {
        let mut exponents = Vec::new();
        let mut copies = std::collections::BTreeMap::new();
        for packet in raw_packets(bytes, set.set_id) {
            let offset = packet.offset as usize;
            let end = offset + packet.header.length as usize;
            if packet.header.packet_type == TYPE_RECVSLIC {
                assert_eq!(packet.header.length, 64 + 4 + 16);
                exponents.push(u32::from_le_bytes(
                    bytes[offset + 64..offset + 68].try_into().unwrap(),
                ));
            } else {
                assert!(critical.contains(&bytes[offset..end]));
                *copies.entry(bytes[offset..end].to_vec()).or_insert(0) += 1;
            }
        }
        assert!(!exponents.is_empty());
        assert_eq!(copies.len(), critical.len());
        for count in copies.values() {
            assert_eq!(*count, 1 + exponents.len().ilog2());
        }
        assert!(volumes.insert(exponents, bytes.as_slice()).is_none());
    }
    volumes
}
fn equal_packets(native: &par_rs::Par2Set, compat: &par_rs::Par2Set, total: u32, first: u32) {
    assert_eq!(native.set_id, compat.set_id);
    assert_eq!(native.input_slices, compat.input_slices);
    assert_eq!(native.index, compat.index);
    let a = packet_volumes(native);
    let b = packet_volumes(compat);
    assert_eq!(a, b);
    let mut exponents: Vec<_> = a.keys().flatten().copied().collect();
    exponents.sort();
    assert_eq!(exponents, (first..first + total).collect::<Vec<_>>());
}

fn qualify(total: u32, first: u32, scheme: par_rs::VolumeScheme, widths: Option<(usize, usize)>) {
    let root = Root::new();
    let data: Vec<_> = (0..64).collect();
    let files = [("empty.bin", b"".as_slice()), ("data.bin", data.as_slice())];
    let sources: Vec<_> = files
        .iter()
        .map(|(name, data)| {
            let p = root.path.join(name);
            std::fs::write(&p, data).unwrap();
            SourceFile::new(p)
        })
        .collect();
    let (disk_options, memory_options) = options(total, first, scheme);
    let old = par_rs::build_set("set", &files, &memory_options).unwrap();
    let native =
        build_set_with_volume_naming("set", &files, &memory_options, VolumeNaming::Native).unwrap();
    let compat = build_set_with_volume_naming(
        "set",
        &files,
        &memory_options,
        VolumeNaming::Par2cmdlineExponential,
    )
    .unwrap();
    assert_eq!(old, native);
    equal_packets(&native, &compat, total, first);
    if let Some((ew, cw)) = widths {
        let expected: Vec<_> = par_rs::checked_volume_layout(scheme, total)
            .unwrap()
            .iter()
            .map(|&(offset, count)| format!("set.vol{:0ew$}+{count:0cw$}.par2", first + offset))
            .collect();
        assert_eq!(
            compat
                .volumes
                .iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>()
        );
    } else {
        assert_eq!(native, compat);
    }
    let old_disk = par_rs::create(
        &sources,
        &root.path.join("old"),
        "set",
        &disk_options,
        None,
        &mut |_, _, _| {},
    )
    .unwrap();
    assert_eq!(disk_set(&old_disk), native);
    for (label, naming, expected) in [
        ("native", VolumeNaming::Native, &native),
        ("compat", VolumeNaming::Par2cmdlineExponential, &compat),
    ] {
        let mut progress = Vec::new();
        let report = create_with_volume_naming(
            &sources,
            &root.path.join(label),
            "set",
            &disk_options,
            naming,
            None,
            &mut |stage, done, total| progress.push((stage, done, total)),
        )
        .unwrap();
        assert_eq!(report.input_slices, 4);
        assert_eq!(report.recovery_slices, total);
        assert_eq!(&disk_set(&report), expected);
        assert!(
            progress
                .iter()
                .any(|&(s, d, t)| s == par_rs::CreateStage::Hashing && d == t && t == 64)
        );
        if total > 0 {
            assert!(
                progress
                    .iter()
                    .any(|&(s, _, _)| s == par_rs::CreateStage::Computing)
            );
        }
    }
}

#[test]
fn both_creators_preserve_native_bytes_and_match_exponential_decimal_boundaries() {
    for (total, first, widths) in [
        (9, 0, (1, 1)),
        (10, 0, (2, 1)),
        (99, 0, (2, 2)),
        (100, 0, (3, 2)),
        (3, 7, (2, 1)),
        (9, 90, (2, 1)),
        (9, 91, (3, 1)),
        (7, 17, (2, 1)),
        (17, 0, (2, 1)),
        (25, 0, (2, 2)),
        (227, 0, (3, 3)),
    ] {
        qualify(
            total,
            first,
            par_rs::VolumeScheme::Exponential,
            Some(widths),
        );
    }
}
#[test]
fn admitted_high_exponent_boundary_is_library_only() {
    qualify(10, 65525, par_rs::VolumeScheme::Exponential, Some((5, 1)));
}
#[test]
fn explicit_policy_keeps_all_other_schemes_native() {
    use par_rs::VolumeScheme::*;
    for scheme in [Single, Uniform(0), Uniform(3), Balanced(3), Limited(3)] {
        qualify(10, 17, scheme, None);
    }
}
#[test]
fn zero_recovery_and_empty_sources_stay_index_only() {
    qualify(0, 0, par_rs::VolumeScheme::Exponential, Some((1, 1)));
    let root = Root::new();
    let source = root.path.join("empty.bin");
    std::fs::write(&source, b"").unwrap();
    for (label, naming) in [
        ("native", VolumeNaming::Native),
        ("compat", VolumeNaming::Par2cmdlineExponential),
    ] {
        for total in [0, 10] {
            let (disk, memory) = options(total, 0, par_rs::VolumeScheme::Exponential);
            let old = par_rs::build_set("set", &[("empty.bin", b"")], &memory).unwrap();
            let set = build_set_with_volume_naming("set", &[("empty.bin", b"")], &memory, naming)
                .unwrap();
            assert_eq!(old, set);
            assert!(set.volumes.is_empty());
            let report = create_with_volume_naming(
                &[SourceFile::new(&source)],
                &root.path.join(format!("{label}-{total}")),
                "set",
                &disk,
                naming,
                None,
                &mut |_, _, _| {},
            )
            .unwrap();
            assert_eq!(report.recovery_slices, 0);
            assert_eq!(report.files.len(), 1);
            assert_eq!(disk_set(&report), set);
        }
    }
}
#[test]
fn invalid_admission_precedes_source_and_output_io_for_both_policies() {
    let root = Root::new();
    let absent = root.path.join("absent");
    let sentinel = root.path.join("set.par2");
    std::fs::write(&sentinel, b"keep").unwrap();
    for naming in [VolumeNaming::Native, VolumeNaming::Par2cmdlineExponential] {
        for case in 0..4 {
            let (mut disk, mut memory) = options(10, 0, par_rs::VolumeScheme::Exponential);
            match case {
                0 => {
                    disk.first_exponent = 65526;
                    memory.first_exponent = 65526;
                }
                1 => {
                    disk.slice_size = 3;
                    memory.slice_size = 3;
                }
                2 => {
                    disk.volumes = par_rs::VolumeScheme::Limited(0);
                    memory.volumes = disk.volumes;
                }
                _ => {
                    disk.volumes = par_rs::VolumeScheme::Balanced(11);
                    memory.volumes = disk.volumes;
                }
            }
            let error = create_with_volume_naming(
                &[SourceFile::new(root.path.join("missing"))],
                &absent,
                "set",
                &disk,
                naming,
                None,
                &mut |_, _, _| {},
            )
            .unwrap_err();
            let mem_error =
                build_set_with_volume_naming("set", &[("data.bin", b"data")], &memory, naming)
                    .unwrap_err();
            for error in [error, mem_error] {
                assert!(match case {
                    0 => matches!(error, par_rs::CreateError::TooManyRecoveryBlocks),
                    1 => matches!(error, par_rs::CreateError::BadSliceSize(3)),
                    2 => matches!(error, par_rs::CreateError::BadVolumeLimit(0)),
                    _ => matches!(error, par_rs::CreateError::BadVolumeCount { .. }),
                });
            }
        }
    }
    assert!(!absent.exists());
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
    assert_eq!(std::fs::read_dir(&root.path).unwrap().count(), 1);
}
#[test]
fn cancelled_and_failed_creation_keep_delegated_error_semantics() {
    let root = Root::new();
    let source = root.path.join("data.bin");
    std::fs::write(&source, [7; 64]).unwrap();
    let (options, _) = options(10, 0, par_rs::VolumeScheme::Exponential);
    for naming in [VolumeNaming::Native, VolumeNaming::Par2cmdlineExponential] {
        let cancelled = std::sync::atomic::AtomicBool::new(true);
        let dir = root.path.join(format!("cancel-{naming:?}"));
        let result = create_with_volume_naming(
            &[SourceFile::new(&source)],
            &dir,
            "set",
            &options,
            naming,
            Some(&cancelled),
            &mut |_, _, _| {},
        );
        assert!(matches!(result, Err(par_rs::CreateError::Cancelled)));
        // The incumbent prepares volume files before hashing observes cancellation.
        assert!(!dir.join("set.par2").exists());
        assert!(std::fs::read_dir(&dir).unwrap().next().is_some());
        let blocked = root.path.join(format!("blocked-{naming:?}"));
        std::fs::write(&blocked, b"keep destination").unwrap();
        assert!(matches!(
            create_with_volume_naming(
                &[SourceFile::new(&source)],
                &blocked,
                "set",
                &options,
                naming,
                None,
                &mut |_, _, _| {}
            ),
            Err(par_rs::CreateError::Io(_))
        ));
        assert_eq!(std::fs::read(blocked).unwrap(), b"keep destination");
        assert_eq!(std::fs::read(&source).unwrap(), [7; 64]);
    }
}
