use par_rs::create::{
    CreateError, CreateOptions, SetOptions, SourceFile, VolumeScheme, build_set,
    checked_volume_layout, create, volume_layout,
};
use par_rs::packet::{ScanOptions, load_par2_bytes, load_par2_file};
use std::path::PathBuf;

fn tempdir(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("par-rs-limited-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn limited_layouts_match_literal_reference_shapes() {
    for (total, cap, counts) in [
        (7, 3, vec![1, 2, 1, 3]),
        (8, 4, vec![1, 2, 1, 4]),
        (9, 5, vec![1, 2, 4, 2]),
        (10, 4, vec![1, 2, 3, 4]),
        (63, 1, vec![1; 63]),
        (7, 100, vec![1, 2, 4]),
        (7, u32::MAX, vec![1, 2, 4]),
        (1, u32::MAX, vec![1]),
        (0, 1, vec![]),
    ] {
        let layout = checked_volume_layout(VolumeScheme::Limited(cap), total).unwrap();
        assert_eq!(layout.iter().map(|&(_, n)| n).collect::<Vec<_>>(), counts);
        let mut next = 0;
        for (first, count) in layout {
            assert_eq!(first, next);
            next += count;
        }
        assert_eq!(next, total);
    }
}

#[test]
fn limited_geometry_is_bounded_and_contiguous() {
    for total in (1..=128).chain([65535]) {
        for cap in [1, 2, 3, 7, 64, 65535, u32::MAX] {
            let layout = checked_volume_layout(VolumeScheme::Limited(cap), total).unwrap();
            assert!(layout.len() <= total as usize);
            let mut next = 0;
            for (first, count) in layout {
                assert_eq!(first, next);
                assert!(count > 0 && count <= cap);
                next += count;
            }
            assert_eq!(next, total);
        }
    }
    let maximal = checked_volume_layout(VolumeScheme::Limited(1), 65535).unwrap();
    assert_eq!(maximal.len(), 65535);
    assert_eq!(maximal.last(), Some(&(65534, 1)));
    for total in [65536, u32::MAX] {
        assert!(matches!(
            checked_volume_layout(VolumeScheme::Limited(1), total),
            Err(CreateError::TooManyRecoveryBlocks)
        ));
        assert!(volume_layout(VolumeScheme::Limited(1), total).is_empty());
    }
}

#[test]
fn limited_static_errors_precede_source_and_output_io() {
    let dir = tempdir("invalid");
    std::fs::write(dir.join("set.par2"), b"keep index").unwrap();
    std::fs::write(dir.join("set.vol2+1.par2"), b"keep volume").unwrap();
    let absent = dir.join("absent");
    let sources = [SourceFile::new(dir.join("missing.bin"))];
    for (cap, total, first, cap_error) in [
        (0, 0, 0, true),
        (0, 8, 0, true),
        (1, 65536, 0, false),
        (4, 8, 65528, false),
    ] {
        let options = CreateOptions {
            slice_size: 4,
            recovery_blocks: total,
            first_exponent: first,
            volumes: VolumeScheme::Limited(cap),
            ..CreateOptions::default()
        };
        let alias = [SourceFile::new(dir.join("set.par2"))];
        for (source_set, destination) in [(&sources, &dir), (&sources, &absent), (&alias, &dir)] {
            let error = create(
                source_set,
                destination,
                "set",
                &options,
                None,
                &mut |_, _, _| {},
            )
            .unwrap_err();
            assert!(if cap_error {
                matches!(error, CreateError::BadVolumeLimit(0))
            } else {
                matches!(error, CreateError::TooManyRecoveryBlocks)
            });
        }
        let error = build_set(
            "set",
            &[("", b"data")],
            &SetOptions {
                slice_size: 4,
                recovery_blocks: total,
                first_exponent: first,
                volumes: VolumeScheme::Limited(cap),
                ..SetOptions::default()
            },
        )
        .unwrap_err();
        assert!(if cap_error {
            matches!(error, CreateError::BadVolumeLimit(0))
        } else {
            matches!(error, CreateError::TooManyRecoveryBlocks)
        });
        if cap_error {
            assert!(volume_layout(VolumeScheme::Limited(cap), total).is_empty());
        }
    }
    assert!(!absent.exists());
    assert_eq!(std::fs::read(dir.join("set.par2")).unwrap(), b"keep index");
    assert_eq!(
        std::fs::read(dir.join("set.vol2+1.par2")).unwrap(),
        b"keep volume"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn limited_empty_sources_reject_even_index_only_before_outputs() {
    let dir = tempdir("empty");
    std::fs::write(dir.join("empty.bin"), b"").unwrap();
    std::fs::write(dir.join("set.par2"), b"keep index").unwrap();
    let absent = dir.join("absent");
    for total in [0, 1] {
        let options = CreateOptions {
            slice_size: 4,
            recovery_blocks: total,
            volumes: VolumeScheme::Limited(1),
            ..CreateOptions::default()
        };
        for destination in [&dir, &absent] {
            assert!(matches!(
                create(
                    &[SourceFile::new(dir.join("empty.bin"))],
                    destination,
                    "set",
                    &options,
                    None,
                    &mut |_, _, _| {}
                ),
                Err(CreateError::NoSourceData)
            ));
        }
        assert!(matches!(
            build_set(
                "set",
                &[("empty.bin", b"")],
                &SetOptions {
                    slice_size: 4,
                    recovery_blocks: total,
                    volumes: VolumeScheme::Limited(1),
                    ..SetOptions::default()
                }
            ),
            Err(CreateError::NoSourceData)
        ));
        for scheme in [
            VolumeScheme::Single,
            VolumeScheme::Uniform(1),
            VolumeScheme::Exponential,
        ] {
            assert!(
                build_set(
                    "set",
                    &[("empty.bin", b"")],
                    &SetOptions {
                        slice_size: 4,
                        recovery_blocks: total,
                        volumes: scheme,
                        ..SetOptions::default()
                    }
                )
                .unwrap()
                .volumes
                .is_empty()
            );
        }
    }
    assert!(!absent.exists());
    assert_eq!(std::fs::read(dir.join("set.par2")).unwrap(), b"keep index");
    assert_eq!(std::fs::read(dir.join("empty.bin")).unwrap(), b"");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn limited_disk_and_memory_preserve_reference_names_and_native_exponents() {
    let dir = tempdir("sets");
    let data = b"abcdefghijklm";
    std::fs::write(dir.join("data.bin"), data).unwrap();
    for (first, names) in [
        (
            2,
            vec![
                "set.vol2+1.par2",
                "set.vol3+2.par2",
                "set.vol5+1.par2",
                "set.vol6+4.par2",
            ],
        ),
        (
            65527,
            vec![
                "set.vol65527+1.par2",
                "set.vol65528+2.par2",
                "set.vol65530+1.par2",
                "set.vol65531+4.par2",
            ],
        ),
    ] {
        let output = dir.join(first.to_string());
        let report = create(
            &[SourceFile::new(dir.join("data.bin"))],
            &output,
            "set",
            &CreateOptions {
                slice_size: 4,
                recovery_blocks: 8,
                first_exponent: first,
                volumes: VolumeScheme::Limited(4),
                ..CreateOptions::default()
            },
            None,
            &mut |_, _, _| {},
        )
        .unwrap();
        let memory = build_set(
            "set",
            &[("data.bin", data)],
            &SetOptions {
                slice_size: 4,
                recovery_blocks: 8,
                first_exponent: first,
                volumes: VolumeScheme::Limited(4),
                ..SetOptions::default()
            },
        )
        .unwrap();
        assert_eq!(report.files.len(), 5);
        assert_eq!(memory.volumes.len(), 4);
        for (index, (offset, count)) in [(0, 1), (1, 2), (3, 1), (4, 4)].into_iter().enumerate() {
            assert_eq!(report.files[index + 1].file_name().unwrap(), names[index]);
            assert_eq!(memory.volumes[index].0, names[index]);
            let disk = load_par2_file(&report.files[index + 1], ScanOptions::FULL).unwrap();
            let mem = load_par2_bytes(&memory.volumes[index].1, ScanOptions::FULL).unwrap();
            for set in [disk, mem] {
                assert_eq!(
                    set.recovery.keys().copied().collect::<Vec<_>>(),
                    (first + offset..first + offset + count).collect::<Vec<_>>()
                );
                assert!(set.recovery.values().all(|slice| slice.md5_verified));
            }
        }
    }
    std::fs::write(dir.join("empty.bin"), b"").unwrap();
    let mixed = build_set(
        "set",
        &[("empty.bin", b""), ("data.bin", data)],
        &SetOptions {
            slice_size: 4,
            recovery_blocks: 1,
            volumes: VolumeScheme::Limited(1),
            ..SetOptions::default()
        },
    )
    .unwrap();
    assert_eq!(mixed.volumes.len(), 1);
    let mixed_disk = create(
        &[
            SourceFile::new(dir.join("empty.bin")),
            SourceFile::new(dir.join("data.bin")),
        ],
        &dir.join("mixed"),
        "set",
        &CreateOptions {
            slice_size: 4,
            recovery_blocks: 1,
            volumes: VolumeScheme::Limited(1),
            ..CreateOptions::default()
        },
        None,
        &mut |_, _, _| {},
    )
    .unwrap();
    assert_eq!(mixed_disk.files.len(), 2);
    let output = dir.join("index-only");
    let report = create(
        &[SourceFile::new(dir.join("data.bin"))],
        &output,
        "set",
        &CreateOptions {
            recovery_blocks: 0,
            volumes: VolumeScheme::Limited(1),
            ..CreateOptions::default()
        },
        None,
        &mut |_, _, _| {},
    )
    .unwrap();
    assert_eq!(report.files, [output.join("set.par2")]);
    assert!(
        build_set(
            "set",
            &[("data.bin", data)],
            &SetOptions {
                recovery_blocks: 0,
                volumes: VolumeScheme::Limited(1),
                ..SetOptions::default()
            }
        )
        .unwrap()
        .volumes
        .is_empty()
    );
    std::fs::remove_dir_all(dir).unwrap();
}
