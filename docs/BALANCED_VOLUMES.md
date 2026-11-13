# Balanced recovery volumes

Use `VolumeScheme::Balanced(count)` for an exact number of recovery volumes.
The first `recovery_blocks % count` volumes receive one extra slice. For
seven slices and three volumes, the counts are 3, 2, 2. Balanced filenames use separate digit widths for offsets and counts,
matching both references. Existing schemes retain their filenames.
Existing
`Uniform(blocks_per_volume)` retains its fixed-size behavior: `Uniform(3)`
with seven slices produces 3, 3, 1.

`checked_volume_layout(scheme, total)` returns ordered `(offset, count)`
pairs. It rejects totals greater than 65535 and returns `BadVolumeCount` for zero
or excess balanced counts, including any balanced count with zero recovery
slices. Balanced planning reserves its bounded output before filling it.
The disk creator and in-memory builder use this checked path before source
metadata, hashing, encoding, or output creation. Existing exponent bounds
remain in place. Omit an explicit balanced layout for an index-only set.

## Compatibility

Existing `CreateOptions` and `SetOptions` fields and defaults are unchanged.
The public `VolumeScheme` and `CreateError` enums have new variants.
Consumers with exhaustive matches must handle `Balanced` and
`BadVolumeCount`. This requires source changes for those consumers; it is
not a claim of compatibility for every downstream source file. This Git
revision does not publish a new crate version.

The legacy `volume_layout` helper keeps its signature and previous behavior
for Single, Uniform, and Exponential, including zero totals and Uniform(0).
For the new Balanced variant, invalid counts, totals greater than 65535, or an
allocation failure return an empty layout. An empty result is ambiguous
with valid zero recovery. Use the checked helper for new callers. Neither
creation API treats this legacy fallback as successful balanced planning.

## Qualification

Unit tests cover balanced and legacy layouts, invalid counts before I/O,
existing output preservation, disk and memory builders, filenames, packet
checksums, and the first-exponent boundary. The differential test
`balanced_volumes_match_reference_and_repair` compares uneven and divisible
layouts, packet exponents, and repair bytes with the selected reference.
It uses `par2` by default; set `PAR2_LAYOUT_REFERENCE` to an explicit
executable to require that reference instead of skipping when unavailable.
The repository CI installs its checksum-pinned PAR2 reference.

Local qualification also runs that test with both Git-pinned references
used by Prybar: par2cmdline at `3f247813023c9721fae3543309e977b1272c840e`
and par2cmdline-turbo at `3e60f6fcfed52bf257e79c46deae616cb6135d59`.
The reference CLIs cap the first exponent at 32768, so differential
creation uses that boundary. The engine boundary near 65535 is checked
separately by disk and memory builder tests. The reference tools limit volume counts
to 31; the checked library planner supports larger counts
within its 65535-slice bound.
Explicit nonuniform volume counts and limited-volume layouts remain
separate work.
