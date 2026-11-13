use par_rs::{
    GeometryError, GeometryLimits, SliceSizeRequest, SourceSize, checked_source_geometry,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct ControlledAllocator;

thread_local! {
    static STATE: Cell<(bool, bool, usize)> = const { Cell::new((false, false, 0)) };
}

fn refuse() -> bool {
    STATE
        .try_with(|state| {
            let (tracking, fail, attempts) = state.get();
            if tracking {
                state.set((true, false, attempts + 1));
            }
            tracking && fail
        })
        .unwrap_or(false)
}

unsafe impl GlobalAlloc for ControlledAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if refuse() {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if refuse() {
            std::ptr::null_mut()
        } else {
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ControlledAllocator = ControlledAllocator;

fn measured<T>(fail: bool, work: impl FnOnce() -> T) -> (T, usize) {
    STATE.with(|state| state.set((true, fail, 0)));
    let result = work();
    let attempts = STATE.with(|state| state.replace((false, false, 0)).2);
    (result, attempts)
}

fn limits() -> GeometryLimits {
    GeometryLimits {
        max_files: 100,
        max_source_slices: 32768,
        max_slice_bytes: 268435456,
        max_ranges: 100,
        max_metadata_bytes: 4096,
    }
}

#[test]
fn controlled_failure_is_typed_for_geometry_and_loss_allocation() {
    let sources = [SourceSize { key: 9, length: 17 }];
    let (result, attempts) = measured(true, || {
        checked_source_geometry(&sources, SliceSizeRequest::Exact(4), limits())
    });
    assert!(matches!(result, Err(GeometryError::AllocationFailed)));
    assert_eq!(attempts, 1);
    let plan = checked_source_geometry(&sources, SliceSizeRequest::Exact(4), limits()).unwrap();
    let (result, attempts) = measured(true, || {
        plan.lost_slice_ranges(9, std::slice::from_ref(&(0..1)))
    });
    assert!(matches!(result, Err(GeometryError::AllocationFailed)));
    assert_eq!(attempts, 1);
    assert_eq!(
        plan.lost_slice_ranges(9, std::slice::from_ref(&(0..1)))
            .unwrap(),
        std::slice::from_ref(&(0..1))
    );
}

#[test]
fn planning_and_merging_use_one_owned_vector_each() {
    let sources = [
        SourceSize {
            key: 9,
            length: 100000000000,
        },
        SourceSize { key: 1, length: 0 },
    ];
    let (result, attempts) = measured(false, || {
        checked_source_geometry(
            &sources,
            SliceSizeRequest::SmallestAligned {
                quantum_bytes: 716800,
            },
            limits(),
        )
    });
    let plan = result.unwrap();
    assert_eq!(
        attempts, 1,
        "candidate scans and unstable key sorting must not allocate"
    );
    assert_eq!(plan.slice_bytes(), 3584000);
    let (result, attempts) = measured(false, || {
        plan.lost_slice_ranges(9, &[0..1, 3..4, 4..5, 8..9])
    });
    let ranges = result.unwrap();
    assert_eq!(
        attempts, 1,
        "sorting/merging must reuse the original loss buffer"
    );
    assert_eq!(ranges, std::slice::from_ref(&(0..1)));
    assert!(ranges.capacity() >= 4);
    let (result, attempts) = measured(false, || plan.lost_slice_ranges(9, &[]));
    assert!(result.unwrap().is_empty());
    assert_eq!(attempts, 0);
}

#[test]
fn admission_refuses_excess_requests_without_allocating() {
    let sources = [SourceSize { key: 9, length: 17 }];
    let (result, attempts) = measured(true, || {
        checked_source_geometry(
            &sources,
            SliceSizeRequest::Exact(4),
            GeometryLimits {
                max_metadata_bytes: 1,
                ..limits()
            },
        )
    });
    assert!(matches!(result, Err(GeometryError::MetadataLimit { .. })));
    assert_eq!(attempts, 0);
    let initial = checked_source_geometry(&sources, SliceSizeRequest::Exact(4), limits()).unwrap();
    let plan = checked_source_geometry(
        &sources,
        SliceSizeRequest::Exact(4),
        GeometryLimits {
            max_metadata_bytes: initial.requested_metadata_bytes(),
            max_ranges: 1,
            ..limits()
        },
    )
    .unwrap();
    let (result, attempts) = measured(true, || {
        plan.lost_slice_ranges(9, std::slice::from_ref(&(0..1)))
    });
    assert!(matches!(result, Err(GeometryError::MetadataLimit { .. })));
    assert_eq!(attempts, 0);
    let (result, attempts) = measured(true, || plan.lost_slice_ranges(9, &[0..0, 0..0]));
    assert!(matches!(result, Err(GeometryError::RangeLimit { .. })));
    assert_eq!(attempts, 0);
    let (result, attempts) = measured(true, || {
        initial.lost_slice_ranges(9, std::slice::from_ref(&(17..18)))
    });
    assert!(matches!(result, Err(GeometryError::InvalidRange { .. })));
    assert_eq!(attempts, 0);
}
