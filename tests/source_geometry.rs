use par_rs::{
    GeometryError, GeometryLimits, SliceSizeRequest, SourceSize, checked_source_geometry,
};

fn limits() -> GeometryLimits {
    GeometryLimits {
        max_files: 100_000,
        max_source_slices: 32768,
        max_slice_bytes: 268_435_456,
        max_ranges: 1000,
        max_metadata_bytes: 16 << 20,
    }
}

#[test]
fn exact_geometry_rounds_each_physical_file_and_sorts_opaque_keys() {
    let plan = checked_source_geometry(
        &[
            SourceSize { key: 9, length: 3 },
            SourceSize { key: 1, length: 1 },
        ],
        SliceSizeRequest::Exact(4),
        limits(),
    )
    .unwrap();
    assert_eq!(plan.slice_bytes(), 4);
    assert_eq!(plan.total_source_slices(), 2);
    assert_eq!(plan.total_source_bytes(), 4);
    assert_eq!(plan.total_padding_bytes(), 4);
    assert_eq!(
        plan.files()
            .iter()
            .map(|f| (f.key(), f.length(), f.source_slices(), f.padding_bytes()))
            .collect::<Vec<_>>(),
        [(1, 1, 1, 3), (9, 3, 1, 1)]
    );
    assert_eq!(
        plan.requested_metadata_bytes(),
        2 * std::mem::size_of_val(&plan.files()[0])
    );
    assert!(plan.vec_capacity_bytes() >= plan.requested_metadata_bytes());
}

#[test]
fn tails_and_zero_files_have_independent_geometry() {
    let plan = checked_source_geometry(
        &[
            SourceSize { key: 0, length: 0 },
            SourceSize { key: 1, length: 7 },
            SourceSize { key: 2, length: 8 },
            SourceSize { key: 3, length: 9 },
        ],
        SliceSizeRequest::Exact(8),
        limits(),
    )
    .unwrap();
    assert_eq!(
        plan.files()
            .iter()
            .map(|f| (f.source_slices(), f.padding_bytes()))
            .collect::<Vec<_>>(),
        [(0, 0), (1, 1), (1, 0), (2, 7)]
    );
    let zeros: Vec<_> = (0..32769)
        .map(|key| SourceSize { key, length: 0 })
        .collect();
    let plan = checked_source_geometry(
        &zeros,
        SliceSizeRequest::SmallestAligned { quantum_bytes: 3 },
        limits(),
    )
    .unwrap();
    assert_eq!(plan.slice_bytes(), 12);
    assert_eq!(plan.files().len(), 32769);
    assert_eq!(plan.total_source_slices(), 0);
    assert_eq!(plan.total_padding_bytes(), 0);
}

#[test]
fn aligned_goldens_choose_the_smallest_qualified_multiplier() {
    for (sources, expected_n, expected_padding) in [
        (
            vec![SourceSize {
                key: 0,
                length: 100_000_000_000,
            }],
            27902,
            768000,
        ),
        (
            vec![SourceSize {
                key: 0,
                length: 107_374_182_400,
            }],
            29960,
            2457600,
        ),
        (
            (0..200)
                .map(|key| SourceSize {
                    key,
                    length: 524_288_000,
                })
                .collect(),
            29400,
            512000000,
        ),
    ] {
        let plan = checked_source_geometry(
            &sources,
            SliceSizeRequest::SmallestAligned {
                quantum_bytes: 716800,
            },
            limits(),
        )
        .unwrap();
        assert_eq!(plan.slice_bytes(), 3_584_000);
        assert_eq!(plan.total_source_slices(), expected_n);
        assert_eq!(plan.total_padding_bytes(), expected_padding);
        assert!(matches!(
            checked_source_geometry(&sources, SliceSizeRequest::Exact(2_867_200), limits()),
            Err(GeometryError::TooManySourceSlices { .. })
        ));
    }
}

#[test]
fn native_slice_limits_and_exact_overrides_stay_explicit() {
    let one = [SourceSize { key: 1, length: 1 }];
    for size in [0, 1, 3, 5, 268_435_460, u64::MAX] {
        assert!(matches!(
            checked_source_geometry(&one, SliceSizeRequest::Exact(size), limits()),
            Err(GeometryError::BadSliceSize { .. })
        ));
    }
    for size in [4, 8, 268_435_456] {
        assert_eq!(
            checked_source_geometry(&one, SliceSizeRequest::Exact(size), limits())
                .unwrap()
                .slice_bytes(),
            size
        );
    }
    let ceiling = GeometryLimits {
        max_slice_bytes: 5,
        ..limits()
    };
    assert_eq!(
        checked_source_geometry(&one, SliceSizeRequest::Exact(4), ceiling)
            .unwrap()
            .slice_bytes(),
        4
    );
    assert!(matches!(
        checked_source_geometry(&one, SliceSizeRequest::Exact(8), ceiling),
        Err(GeometryError::BadSliceSize { .. })
    ));
    for quantum in [0, u64::MAX] {
        assert!(matches!(
            checked_source_geometry(
                &one,
                SliceSizeRequest::SmallestAligned {
                    quantum_bytes: quantum
                },
                limits()
            ),
            Err(GeometryError::BadAlignment(_))
        ));
    }
    assert!(matches!(
        checked_source_geometry(
            &one,
            SliceSizeRequest::SmallestAligned {
                quantum_bytes: 268_435_457
            },
            limits()
        ),
        Err(GeometryError::NoAlignedSliceSize)
    ));
}

#[test]
fn aggregate_slice_boundaries_and_no_aligned_solution() {
    for count in [32767, 32768, 32769] {
        let sources: Vec<_> = (0..count)
            .map(|key| SourceSize { key, length: 1 })
            .collect();
        for request in [
            SliceSizeRequest::Exact(4),
            SliceSizeRequest::SmallestAligned { quantum_bytes: 4 },
        ] {
            let plan = checked_source_geometry(&sources, request, limits());
            if count <= 32768 {
                assert_eq!(plan.unwrap().total_source_slices(), count as u32);
            } else {
                assert!(matches!(
                    plan,
                    Err(GeometryError::TooManySourceSlices { .. })
                        | Err(GeometryError::NoAlignedSliceSize)
                ));
            }
        }
    }
    let one = [SourceSize { key: 4, length: 17 }];
    let small = GeometryLimits {
        max_source_slices: 2,
        max_slice_bytes: 8,
        ..limits()
    };
    assert!(matches!(
        checked_source_geometry(
            &one,
            SliceSizeRequest::SmallestAligned { quantum_bytes: 4 },
            small
        ),
        Err(GeometryError::NoAlignedSliceSize)
    ));
    assert_eq!(
        checked_source_geometry(
            &one,
            SliceSizeRequest::SmallestAligned { quantum_bytes: 4 },
            GeometryLimits {
                max_slice_bytes: 12,
                ..small
            }
        )
        .unwrap()
        .slice_bytes(),
        12
    );
}

#[test]
fn input_and_limit_failures_are_typed() {
    let one = [SourceSize { key: 1, length: 1 }];
    assert!(matches!(
        checked_source_geometry(&[], SliceSizeRequest::Exact(4), limits()),
        Err(GeometryError::NoSources)
    ));
    let duplicate = [
        SourceSize { key: 7, length: 0 },
        SourceSize { key: 7, length: 1 },
    ];
    assert!(matches!(
        checked_source_geometry(&duplicate, SliceSizeRequest::Exact(4), limits()),
        Err(GeometryError::DuplicateKey(7))
    ));
    for bad in [
        GeometryLimits {
            max_files: 0,
            ..limits()
        },
        GeometryLimits {
            max_ranges: 0,
            ..limits()
        },
        GeometryLimits {
            max_metadata_bytes: 0,
            ..limits()
        },
        GeometryLimits {
            max_source_slices: 0,
            ..limits()
        },
        GeometryLimits {
            max_source_slices: 32769,
            ..limits()
        },
        GeometryLimits {
            max_slice_bytes: 3,
            ..limits()
        },
        GeometryLimits {
            max_slice_bytes: 268_435_457,
            ..limits()
        },
    ] {
        assert!(matches!(
            checked_source_geometry(&one, SliceSizeRequest::Exact(4), bad),
            Err(GeometryError::BadLimits)
        ));
    }
    assert!(matches!(
        checked_source_geometry(
            &duplicate,
            SliceSizeRequest::Exact(4),
            GeometryLimits {
                max_files: 1,
                ..limits()
            }
        ),
        Err(GeometryError::TooManyFiles { .. })
    ));
    let huge = [
        SourceSize {
            key: 1,
            length: u64::MAX,
        },
        SourceSize { key: 2, length: 1 },
    ];
    assert!(matches!(
        checked_source_geometry(&huge, SliceSizeRequest::Exact(4), limits()),
        Err(GeometryError::Overflow)
    ));
    assert!(matches!(
        checked_source_geometry(&huge[..1], SliceSizeRequest::Exact(4), limits()),
        Err(GeometryError::TooManySourceSlices { .. })
    ));
}

#[test]
fn metadata_budgets_include_retained_geometry_and_all_query_inputs() {
    let source = [SourceSize { key: 1, length: 12 }];
    let measured = checked_source_geometry(&source, SliceSizeRequest::Exact(4), limits()).unwrap();
    let retained = measured.requested_metadata_bytes();
    assert_eq!(retained, std::mem::size_of::<par_rs::FileGeometry>());
    assert!(matches!(
        checked_source_geometry(
            &source,
            SliceSizeRequest::Exact(4),
            GeometryLimits {
                max_metadata_bytes: retained - 1,
                ..limits()
            }
        ),
        Err(GeometryError::MetadataLimit { .. })
    ));
    for extra in [0, 1, 16, 17] {
        let plan = checked_source_geometry(
            &source,
            SliceSizeRequest::Exact(4),
            GeometryLimits {
                max_metadata_bytes: retained + extra,
                max_ranges: 2,
                ..limits()
            },
        )
        .unwrap();
        assert!(plan.lost_slice_ranges(1, &[]).unwrap().is_empty());
        let result = plan.lost_slice_ranges(1, &[0..0, 0..1]);
        if extra < 16 {
            assert!(matches!(result, Err(GeometryError::MetadataLimit { .. })));
        } else {
            assert_eq!(result.unwrap(), std::slice::from_ref(&(0..1)));
        }
        assert!(matches!(
            plan.lost_slice_ranges(1, &[0..0, 0..0, 0..0]),
            Err(GeometryError::RangeLimit { .. })
        ));
    }
}

#[test]
fn loss_queries_are_local_strict_sorted_unions() {
    let plan = checked_source_geometry(
        &[
            SourceSize { key: 1, length: 13 },
            SourceSize { key: 2, length: 13 },
            SourceSize { key: 3, length: 0 },
        ],
        SliceSizeRequest::Exact(4),
        limits(),
    )
    .unwrap();
    assert_eq!(
        plan.lost_slice_ranges(1, &[12..13, 1..2, 2..3, 0..1, 12..12])
            .unwrap(),
        [0..1, 3..4]
    );
    assert_eq!(
        plan.lost_slice_ranges(2, &[0..1, 3..5, 8..9, 8..9])
            .unwrap(),
        std::slice::from_ref(&(0..3))
    );
    assert!(
        plan.lost_slice_ranges(1, std::slice::from_ref(&(13..13)))
            .unwrap()
            .is_empty()
    );
    assert!(
        plan.lost_slice_ranges(3, std::slice::from_ref(&(0..0)))
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        plan.lost_slice_ranges(9, &[]),
        Err(GeometryError::UnknownKey(9))
    ));
    for range in [
        std::ops::Range { start: 5, end: 4 },
        13..14,
        14..14,
        0..u64::MAX,
    ] {
        assert!(matches!(
            plan.lost_slice_ranges(1, &[range]),
            Err(GeometryError::InvalidRange { .. })
        ));
    }
    assert!(matches!(
        plan.lost_slice_ranges(3, std::slice::from_ref(&(0..1))),
        Err(GeometryError::InvalidRange { .. })
    ));
}

#[test]
fn article_losses_count_union_of_local_slices() {
    let source = [SourceSize {
        key: 4,
        length: 8 * 716800,
    }];
    let unaligned =
        checked_source_geometry(&source, SliceSizeRequest::Exact(1_048_576), limits()).unwrap();
    assert_eq!(
        unaligned
            .lost_slice_ranges(4, std::slice::from_ref(&(716800..1433600)))
            .unwrap(),
        std::slice::from_ref(&(0..2))
    );
    let aligned =
        checked_source_geometry(&source, SliceSizeRequest::Exact(3_584_000), limits()).unwrap();
    let parts: Vec<_> = (0..5).rev().map(|i| i * 716800..(i + 1) * 716800).collect();
    assert_eq!(
        aligned.lost_slice_ranges(4, &parts).unwrap(),
        std::slice::from_ref(&(0..1))
    );
    assert_eq!(
        aligned
            .lost_slice_ranges(4, std::slice::from_ref(&(3_584_000..3_584_001)))
            .unwrap(),
        std::slice::from_ref(&(1..2))
    );
    // Existing permissive signed helpers retain their behavior.
    assert_eq!(
        par_rs::blocks_touched(&[par_rs::ByteRange::new(0, 1)], 0),
        0
    );
    assert_eq!(
        par_rs::create::volume_layout(par_rs::VolumeScheme::Uniform(3), 7),
        [(0, 3), (3, 3), (6, 1)]
    );
}

#[test]
fn maximum_tail_padding_uses_metadata_without_slice_buffers() {
    let sources: Vec<_> = (0..32768)
        .map(|key| SourceSize { key, length: 1 })
        .collect();
    let plan =
        checked_source_geometry(&sources, SliceSizeRequest::Exact(268_435_456), limits()).unwrap();
    assert_eq!(plan.total_source_slices(), 32768);
    assert_eq!(plan.total_source_bytes(), 32768);
    assert_eq!(plan.total_padding_bytes(), 8_796_092_989_440);
    assert_eq!(
        plan.requested_metadata_bytes(),
        32768 * std::mem::size_of::<par_rs::FileGeometry>()
    );
    assert_eq!(
        plan.lost_slice_ranges(0, std::slice::from_ref(&(0..1)))
            .unwrap(),
        std::slice::from_ref(&(0..1))
    );
}
