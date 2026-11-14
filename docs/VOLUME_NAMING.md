# Explicit exponential volume names

`create` and `build_set` keep their native filenames and signatures. Existing
complete `CreateOptions` and `SetOptions` literals continue to compile.

Use `create_with_volume_naming` or `build_set_with_volume_naming` with
`VolumeNaming::Par2cmdlineExponential` to select reference exponential filename
spelling. Both functions are exported from the crate root. The disk function
places the policy after `opts` and before `cancel`; the memory function places
it after `opts`. Selecting `VolumeNaming::Native` matches the old entrypoints.

For ten recovery slices starting at exponent0, native exponential names use
`set.vol00+01.par2`, `set.vol01+02.par2`, `set.vol03+04.par2`, and
`set.vol07+03.par2`. The explicit policy uses `set.vol00+1.par2`,
`set.vol01+2.par2`, `set.vol03+4.par2`, and `set.vol07+3.par2`.

The exponent width includes the exclusive set end, as the zero-count index
allocation does in the references. The count width comes from the largest actual
volume count. Both have a minimum of one digit. Widths are calculated once from
the checked layout. Single, Uniform, Balanced, and Limited retain their native
names under either policy. This selects exponential spelling only; source
selection, command-line admission rules, and other compatibility behavior are unchanged.

The index name and bytes remain unchanged, as do corresponding volume bytes,
allocation, and exponents. Recovery data is unchanged. `CreateReport.files` contains the
actual output paths. Validation, cancellation, progress, and write behavior follow
the existing creator. The disk creator can truncate existing output paths and
leave partial volumes on failure. Callers remain responsible for private staging,
collision checks, and publication; the policy adds no rollback or durability claim.
