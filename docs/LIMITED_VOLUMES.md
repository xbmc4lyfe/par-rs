# Limited recovery volumes

Use `VolumeScheme::Limited(max_slices)` to cap the number of recovery slices
in each volume. The cap counts payload slices, not total file bytes. Packet
headers and repeated metadata add to the size on disk. This API takes an
explicit cap; it does not inspect source-file sizes to choose one.

A compatible `-l` caller derives the cap by dividing the largest selected
source's byte length by the slice size, rounding up. Use the same source set
and slice size for planning and creation.

The layout starts with an exponential prefix, then appends full-cap volumes.
The prefix can end with a smaller remainder, so counts need not increase:

| Recovery slices | Cap | Counts in volume order |
| --- | --- | --- |
| 7 | 3 | 1, 2, 1, 3 |
| 8 | 4 | 1, 2, 1, 4 |
| 9 | 5 | 1, 2, 4, 2 |
| 10 | 4 | 1, 2, 3, 4 |
| 63 | 1 | 63 volumes with one slice each |

A positive cap greater than the recovery count is valid, including `u32::MAX`.
It produces the default exponential counts with limited-volume filenames.
Offset and count fields have independent digit widths. The offset width
includes the end of the exponential prefix and each recovery volume's start.
For eight slices, cap four, and first exponent two, the filenames are
`set.vol2+1.par2`, `set.vol3+2.par2`, `set.vol5+1.par2`, and `set.vol6+4.par2`.

## Validation and compatibility

Use `checked_volume_layout(scheme, total)` for fallible planning. A zero cap
returns `CreateError::BadVolumeLimit(0)`, including with zero recovery slices.
A positive cap with zero recovery slices returns an empty layout. Creation
then writes an index-only set if the sources contain data. Both creators
return `NoSourceData` for an all-empty source set, including index-only
Limited requests, before acquiring output files. Static layout errors are
checked before source reads; empty-source detection requires source metadata.

The planner accepts recovery totals through 65535. Creation retains its
existing `first_exponent + recovery_blocks <= 65535` bound. The reference
CLIs' count and first-exponent restrictions do not constrain this native API.
Limited layouts can contain more than 31 volumes.

Existing option fields, defaults, variants, and filenames retain their
behavior. Consumers with exhaustive enum matches must handle `Limited` and
`BadVolumeLimit`. The legacy infallible `volume_layout` returns an empty
layout for invalid new-variant parameters or allocation failure. That result
is ambiguous with valid zero recovery; both creators use the checked helper.

## Qualification

`tests/limited_creation.rs` checks geometry, source-data validation, errors
before output creation, disk and memory packets, and native exponent bounds.
`limited_volumes_match_reference_and_cross_repair` compares names, packet
checksums, and exponents with a reference, then checks missing and corrupt
source repairs in both directions, including retained damaged backups.
Set `PAR2_LAYOUT_REFERENCE` to require a specific reference binary.

Qualification uses par2cmdline at `3f247813023c9721fae3543309e977b1272c840e`
and par2cmdline-turbo at `3e60f6fcfed52bf257e79c46deae616cb6135d59`.
Both reference CLIs map explicit `-nN` to balanced volumes even without `-u`;
that syntax uses the existing `Balanced(N)` API.
