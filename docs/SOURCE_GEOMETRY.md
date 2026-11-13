# Checked source geometry

Use `checked_source_geometry` for pure numeric sizing of physical source files.
Pass unique opaque keys, byte lengths, an exact or aligned size request, and
explicit `GeometryLimits`. The function does not access files or change any
existing creation, damage, verification, or repair policy.

```rust
use par_rs::{GeometryLimits, SliceSizeRequest, SourceSize, checked_source_geometry};
let limits = GeometryLimits {
    max_files: 1000,
    max_source_slices: 32768,
    max_slice_bytes: 268_435_456,
    max_ranges: 1000,
    max_metadata_bytes: 1 << 20,
};
let plan = checked_source_geometry(
    &[SourceSize { key: 9, length: 3 }, SourceSize { key: 1, length: 1 }],
    SliceSizeRequest::Exact(4),
    limits,
)?;
assert_eq!(plan.total_source_slices(), 2);
assert_eq!(plan.total_padding_bytes(), 4);
assert_eq!(plan.lost_slice_ranges(9, &[0..1, 2..3])?, [0..1]);
# Ok::<(), par_rs::GeometryError>(())
```

Every physical file has its own final padded slice. Three bytes and one byte
at slice size four need two slices. Empty files contribute zero slices and
padding. An empty source list is invalid; a nonempty all-zero list is valid
geometry. Creation schemes apply their separate empty-source rules.

`Exact(S)` validates S unchanged. S must be positive, divisible by four, and
within the supplied ceiling. `SmallestAligned { quantum_bytes }` chooses the
smallest positive multiple of `lcm(quantum_bytes, 4)` that meets the exact
aggregate slice-count ceiling. It searches borrowed sizes without enumerating
articles or allocating candidate plans. An exact S can be valid without matching
an optional profile alignment. The workflow decides whether it meets that profile.

Native limits are 32768 aggregate source slices and 268435456 slice bytes.
Callers can supply smaller ceilings. The slice-byte ceiling itself need not
be divisible by four. All budgets must be positive; zero never means unlimited.
The non-exhaustive `GeometryError` distinguishes bad limits, invalid sizes or
alignment, missing or duplicate keys, overflow, infeasibility, exceeded budgets,
invalid physical ranges, and allocator refusal. Errors contain bounded numeric
data and no owned diagnostic strings.

## Loss ranges and ordering

`files()` returns records sorted by opaque key, with local slice counts, and
logical padding. Keys and this order are not filesystem identities, PAR2 file
IDs, or global Reed-Solomon positions. Input order and lengths cannot establish
actual Main-packet order. Source binding and immutable-byte guarantees require
a separate workflow and creation adapter.

`lost_slice_ranges(key, ranges)` accepts strict half-open physical byte ranges.
Require `start <= end <= length`. Empty valid ranges are no-ops. Unknown keys
fail even for an empty query; reversed or past-EOF ranges fail without clipping.
Callers must check addition before converting offsets and lengths to ranges.
The result contains sorted disjoint half-open local slice spans. Overlaps,
adjacency, and separate holes within a slice count once. Different files remain
separate. A partial final slice counts once; logical padding is not physical
loss. A numeric loss count does not establish repairability or usable parity.

## Requested capacity accounting

Construction requests one vector of `F * size_of::<FileGeometry>()` bytes.
A query requests retained geometry bytes plus `M * size_of::<Range<u32>>()`,
where M counts all supplied ranges, including empty ones. Both requests use
checked arithmetic, admission before allocation, and fallible exact reservation.
The query sorts and merges its single vector in place. Owned plans do not
implement `Clone`.

`requested_metadata_bytes()` reports retained requested capacity.
`vec_capacity_bytes()` reports actual advertised file-vector capacity in bytes.
The returned loss vector exposes its actual capacity through `Vec::capacity()`;
merging does not reduce that capacity. Allocator rounding, bookkeeping, fixed
stack objects, borrowed inputs, prior returned vectors retained by the caller,
and concurrent calls are outside the per-call requested-capacity promise.
This is not a process RSS limit or a memory/runtime optimum.

Construction uses O(F) dynamic storage and O(F log F) sorting. Aligned selection
adds O(F log(max_slice_bytes / alignment)) work. A query uses O(M) dynamic storage,
O(log F) lookup, O(M) validation, and O(M log M) sorting. Neither path allocates
by physical file bytes, article count, or a matrix dimension squared.

## Composition and qualification

Compose expected recovery geometry with `checked_volume_layout` and the
creator's first-exponent validation. Source geometry establishes no stable
bytes, actual recovery-packet availability, creation, durability, or publication.
Provider settings, poster policy, wire budgets, and workflow finality belong
to the caller.

Public integration tests cover numeric limits, per-file tails, strict loss
unions, and arithmetic goldens for exact 100 GB, 100 GiB, and 200 x 500 MiB
inputs. These are arithmetic tests, not physical workload benchmarks. A separate
test binary uses a thread-local controlled allocator to check allocation refusal,
reservation counts, and admission without allocation. Real small physical-file
tests compare Main, FileDesc, IFSC, and expected recovery geometry with a reference.
Set `PAR2_LAYOUT_REFERENCE` to require a specific reference binary.
