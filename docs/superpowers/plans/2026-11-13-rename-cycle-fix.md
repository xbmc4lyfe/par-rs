# Complete-copy rename-cycle fix plan

Execute inline with executing-plans and test-driven-development. Root already
approved the bounded source lease and owns the fresh independent review and
publication. No helper agents or publishing before that review.

Goal: keep verified complete-copy paths coherent through known backup rotations
and moves, consuming only backups actually moved into their repaired targets.

Spec: `phase3-par2-rename-cycle-fix-brief.md` and the supplied nine-command
caller swap receipt, SHA-256
`64b8e28fcd71724a9ca2d41a91fa0d4eb3d4a935b7b04bba56fd91f886fba01b`.
Baseline: ea787, tree9adfe, identical to the qualified donor-policy tree.
Use its retained 243 Rust/9 Python local checks and root's verified Linux/main CI;
run the new public baseline RED without a redundant broad baseline campaign.

## Exact file lease and design

- `src/repairer.rs`: backup/move complete-copy bookkeeping in `repair`, a private
  module declaration, and existing shared-source guard integration only.
- `src/repairer/rename.rs`: bounded reverse complete-copy references by stable
  disk ID, cached block owners and sorted target indexes, and known-own backup
  slots/consumption flags. Reserve vectors and complete-copy path capacity
  fallibly under the existing phase budget before filesystem mutations.
- `tests/rename_cycles.rs`: public swap/cycle, copy/default, mixed/damaged,
  preexisting backup, shared/equal copy, empty identity, hard-link survivor,
  cancellation and actual I/O-failure coverage.
- `tests/par2cmdline.rs`: one narrow pinned-reference cycle comparison.
- Private helper tests, this plan, and concise repair-cycle documentation.

No creator/naming, donor/scanner policy, RS/math, geometry, shutdown, dependency,
source-binding/preparation or caller changes. No new public option or larger
resource limit. This corrects existing rename_misnamed behavior.

Build reverse references once. A known disk ID retains its block locations while
its current path rotates. Update that ID's affected complete-copy references,
using pre-reserved buffers. Do not scan all logical files after every move.
Cached block ownership retains shared-donor protection; target lookup protects
already complete targets, including zero-block aliases. Auxiliary state drops
before copy/RS work. Mark a backup slot consumed only after successful rename of
that exact known backup; compact reported leftovers once without deleting files.

## Tasks

- [ ] Verify fresh ea787/tree9adfe and retained baseline evidence; add the public
  two-file swap test. Observe exact correct bytes but unwanted backup RED.
- [ ] Implement bounded remapping and known-backup consumption. Observe public
  GREEN with no new cycle backup or stale reported leftover.
- [ ] Cover two/three cycles and orders, genuine damage, preexisting .1/.2,
  rename=false, all existing backup policies, shared/equal and empty identities,
  ordinary external complete donor plus parity, and hard-linked source survivors.
- [ ] Exercise deterministic cancellation and mid-cycle rename failure with
  actual partial filesystem effects; resource preflight failure before effects.
  Keep required backups, original survivor bytes, and truthful errors.
- [ ] Compare both retained pinned references on tiny cycles and exact final
  byte/path/donor effects. Reuse existing supplied swap evidence without reruns
  outside the necessary new regression qualification.
- [ ] Run focused tests and final normal CI with pinned Vale3.26. Preserve
  existing default/ordered/repair/layout/geometry/resource/shutdown coverage.
- [ ] Commit locally; return exact HEAD/tree, commands, coverage, and evidence
  for root's fresh review, then per-repo PR, guarded merge, and successful main CI.

Review focus: shared identities, zero-block target survival, real versus consumed
backup provenance, allocation/cancellation order, partial failure, and metadata
complexity. No byte-equality deletion, caller unlink workaround, or rollback claim.
