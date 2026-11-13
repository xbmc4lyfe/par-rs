# Limited volumes implementation plan

> Execute inline with the executing-plans and test-driven-development skills.

**Goal:** add an explicit recovery-slice cap with reference-compatible limited layouts.

**Architecture:** extend `VolumeScheme` and its checked planner. Keep option
structs and legacy behavior unchanged. Both creators use the checked layout
and derive the new variant's filename widths from its geometry.

**Tech stack:** the Rust toolchain, Cargo, Python, Vale, and both pinned PAR2 references.

**Spec:** the controller's approved `phase3-par2-limited-implementation-brief.md`
and preceding reference report in the shared compatibility evidence directory.

## Constraints and review focus

- Preserve existing variants, filenames, defaults, and exponent bounds.
- Reject cap zero even with zero recovery; accept positive caps greater than the total.
- Reject all-empty Limited sources even with zero recovery, before outputs.
- Keep native totals through 65535 and output counts greater than 31 valid.
- Reserve bounded layout storage fallibly and avoid arithmetic overflow.
- Preserve evidence, source files, and existing outputs on invalid requests.

## Task 1: implement and qualify limited creation

**Files:** `src/create.rs`, `tests/par2cmdline.rs`, `docs/LIMITED_VOLUMES.md`.

**Interface:** `VolumeScheme::Limited(u32)`,
`CreateError::BadVolumeLimit(u32)`, existing `checked_volume_layout` signature.

- [x] Add tests for exact counts R7/L3, R8/L4, R9/L5, R10/L4,
  `cap1`, caps greater than the total, `u32::MAX`, and totals 0, 1, 65535, 65536, and contiguous bounded output.
- [x] Observe missing-API compilation failure. Add only the API with provisional
  behavior; observe semantic layout, filename and source-validation failures.
- [x] Implement checked geometry with exact fallible reservation. Add limited
  filename widths; preserve old names. Extend source-data validation in both
  creators. Run focused tests until green.
- [x] Test disk/memory names and packet checksums at first2 and native high
  exponent65527, and invalid geometry before source/output I/O. Test index-only
  nonempty data, all-empty rejection and existing-output preservation.
- [x] Add differential tests for literal reference shapes, rounded source cap,
  first32768, zero recovery, and 63 output volumes. Compare packets and names;
  cross-repair missing and corrupt bytes in both creator/repairer directions.
- [x] Document explicit slice-cap semantics and exhaustive-match migration.
- [x] Run final `just ci` with Vale3.26 and both pinned reference tests, inspect
  the complete diff, commit locally and report exact HEAD/tree and evidence.

Independent review and PR publishing are owned by the controller.
