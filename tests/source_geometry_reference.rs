use par_rs::create::{CreateOptions, SourceFile, VolumeScheme, checked_volume_layout, create};
use par_rs::packet::{ScanOptions, load_par2_file};
use par_rs::{GeometryLimits, SliceSizeRequest, SourceSize, checked_source_geometry};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn tempdir(tag: usize) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "par-rs-source-geometry-{tag}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn physical_source_geometry_matches_reference_metadata() {
    let explicit = std::env::var_os("PAR2_LAYOUT_REFERENCE");
    let reference = explicit.unwrap_or_else(|| "par2".into());
    match Command::new(&reference).arg("--version").output() {
        Ok(out) if out.status.success() => {}
        _ if std::env::var_os("PAR2_LAYOUT_REFERENCE").is_none() => {
            eprintln!("par2 not available; skipping geometry reference comparison");
            return;
        }
        _ => panic!("required reference unavailable: {reference:?}"),
    }
    for (case, (lengths, request, max_slices, expected_slice, expected_count)) in [
        (
            vec![3usize, 1, 7, 8, 9],
            SliceSizeRequest::Exact(4),
            32768,
            4,
            9,
        ),
        (
            vec![13, 21, 32],
            SliceSizeRequest::SmallestAligned { quantum_bytes: 3 },
            5,
            24,
            4,
        ),
        (
            vec![16, 17, 31],
            SliceSizeRequest::SmallestAligned { quantum_bytes: 4 },
            6,
            16,
            5,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = tempdir(case);
        let own_dir = dir.join("own");
        let external_dir = dir.join("reference");
        std::fs::create_dir_all(&external_dir).unwrap();
        let mut input = Vec::new();
        let mut sources = Vec::new();
        let mut originals = Vec::new();
        for (index, length) in lengths.into_iter().enumerate() {
            let name = format!("data{index}.bin");
            let data: Vec<_> = (0..length)
                .map(|i| (i as u8).wrapping_mul(17).wrapping_add(index as u8))
                .collect();
            let path = dir.join(&name);
            std::fs::write(&path, &data).unwrap();
            std::fs::write(external_dir.join(&name), &data).unwrap();
            input.push(SourceSize {
                key: 100 - index as u64,
                length: length as u64,
            });
            sources.push(SourceFile::new(path));
            originals.push((name, data));
        }
        let plan = checked_source_geometry(
            &input,
            request,
            GeometryLimits {
                max_files: 100,
                max_source_slices: max_slices,
                max_slice_bytes: 1024,
                max_ranges: 100,
                max_metadata_bytes: 4096,
            },
        )
        .unwrap();
        assert_eq!(plan.slice_bytes(), expected_slice);
        assert_eq!(plan.total_source_slices(), expected_count);
        let report = create(
            &sources,
            &own_dir,
            "set",
            &CreateOptions {
                slice_size: plan.slice_bytes(),
                recovery_blocks: 7,
                volumes: VolumeScheme::Balanced(3),
                ..CreateOptions::default()
            },
            None,
            &mut |_, _, _| {},
        )
        .unwrap();
        let mut command = Command::new(&reference);
        command
            .current_dir(&external_dir)
            .args(["c", "-q", "-t1", "-c7", "-n3"])
            .arg(format!("-s{}", plan.slice_bytes()))
            .arg("set.par2");
        for (name, _) in &originals {
            command.arg(name);
        }
        let out = command.output().unwrap();
        assert!(
            out.status.success(),
            "reference failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let own = load_par2_file(&own_dir.join("set.par2"), ScanOptions::FULL).unwrap();
        let external = load_par2_file(&external_dir.join("set.par2"), ScanOptions::FULL).unwrap();
        assert_eq!(own.set_id, external.set_id);
        for set in [&own, &external] {
            assert_eq!(set.main.as_ref().unwrap().slice_size, plan.slice_bytes());
            assert_eq!(set.total_input_slices(), Some(u64::from(expected_count)));
            assert_eq!(set.file_descs.len(), originals.len());
            for (index, (name, bytes)) in originals.iter().enumerate() {
                let geometry = plan
                    .files()
                    .iter()
                    .find(|g| g.key() == 100 - index as u64)
                    .unwrap();
                let file = set
                    .file_descs
                    .values()
                    .find(|f| f.name == name.as_bytes())
                    .unwrap();
                assert_eq!(file.file_length, geometry.length());
                let ifsc = &set.ifscs[&file.file_id];
                assert_eq!(ifsc.slices.len(), geometry.source_slices() as usize);
                assert_eq!(
                    u64::from(geometry.source_slices()) * plan.slice_bytes() - geometry.length(),
                    geometry.padding_bytes()
                );
                for (chunk, checksum) in bytes.chunks(plan.slice_bytes() as usize).zip(&ifsc.slices)
                {
                    let mut padded = chunk.to_vec();
                    padded.resize(plan.slice_bytes() as usize, 0);
                    let (crc, md5) = par_rs::hasher::slice_checksums(&padded);
                    assert_eq!(checksum.crc32, crc);
                    assert_eq!(checksum.md5, md5);
                }
                assert_eq!(std::fs::read(dir.join(name)).unwrap(), *bytes);
                assert_eq!(std::fs::read(external_dir.join(name)).unwrap(), *bytes);
            }
        }
        let expected_layout = checked_volume_layout(VolumeScheme::Balanced(3), 7).unwrap();
        let layout = |directory: &Path| {
            let mut map = BTreeMap::new();
            for entry in std::fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if !path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("set.vol")
                {
                    continue;
                }
                let set = load_par2_file(&path, ScanOptions::FULL).unwrap();
                assert!(set.recovery.values().all(|r| r.md5_verified));
                let first = *set.recovery.keys().next().unwrap();
                map.insert(first, set.recovery.len() as u32);
            }
            map.into_iter().collect::<Vec<_>>()
        };
        assert_eq!(layout(&own_dir), expected_layout);
        assert_eq!(layout(&external_dir), expected_layout);
        assert_eq!(report.input_slices, u64::from(expected_count));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
