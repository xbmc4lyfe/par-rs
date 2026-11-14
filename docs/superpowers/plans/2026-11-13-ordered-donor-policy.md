# Ordered donor policy implementation plan

Execute inline using executing-plans and test-driven-development. Root owns
one independent review and publication; no helper agents or publishing here.

Goal: add a typed integrated ordered-prefix donor scan without changing full
scanning, existing options, layouts, creation, RS, or shutdown.

Spec: controller-approved `phase3-par2-donor-policy-engine-brief.md` and frozen
R2 I2 analysis, SHA-256
`8e9be1b3093d25761b09700d433c961624ec1e4b5272f87754d4b8c07d34de96`.
Base: `97fe5b66eac32d98d7b62c3125b02e457485b602`.
Worktree: ae18, branch `codex/ordered-donor-policy`.

## Files and interfaces

- `src/repairer.rs`: additive `ExtraFileScanPolicy::{Full,OrderedPrefix}` and
  private donor module declaration. Existing methods and structs stay intact.
- `src/repairer/donor.rs`: new public
  `add_extra_file_with_policy(&mut self, &Path, ExtraFileScanPolicy,
  &mut dyn RepairObserver) -> Result<usize, RepairError>`; private bounded
  source scanner, modern candidate selection, staged result, and update path.
  Generic `PacketSource` is a production boundary for positional reads, with
  private instrumented tests for required reads and cancellation.
- `src/scanner.rs`: internal visibility for the existing bounded window and
  required checksum/hash operations; add a no-read complete-hash extractor.
  Existing full scanner behavior and public structs stay unchanged.
- `src/lib.rs`: root export of the new policy.
- `tests/ordered_donor.rs`, `tests/par2cmdline.rs`, and private donor unit tests:
  public acceptance, pinned references, and instrumented source failures.
- Documentation: this plan and a concise policy contract/limitations document.

## Constraints and review focus

Use modern Main/block tie order, terminal/nonterminal and prior-location
branches, selected replacement, and old full-scan first-location behavior.
Partial prefixes return no complete hashes and stop after bounded read-ahead.
Only complete identity or eligible absent-IFSC fallback requires full hashes.
Keep the actual-payload guard, single identity, mixed-metadata fallback gating,
finalization, idempotence, and early completion behavior, and successful-only bookkeeping.

Pending entries are capped at 32768 source blocks, with checked capacity bytes
reserved against the existing phase budget before choosing clamped read windows.
Use no per-donor unbounded source copy, global resource increase, or background
hash work. Required read/hash errors and cancellation discard staged updates.
Buffers do not promise process RSS or an arbitrary-I/O cancellation deadline.
No donor scan moves, removes, or overwrites filesystem paths.

## Task 1: public policy and ordered state machine

- [x] Establish clean fetched baseline and run existing all-feature tests.
- [x] Add a failing public prefix-before-mismatch test using existing Full as
  the controlled incumbent; record its over-crediting RED. Add the wished-for
  public policy test and record the missing additive API before implementation.
- [x] Add the typed policy/method, bounded private scanner, and staged update
  path. Full delegates to the incumbent unchanged. Run public test GREEN.
- [x] Add literal table cases for every R2 I2 row: cross-file/shared ties,
  previous donors, terminal/nonterminal duplicates, short/trailing/missing
  payload, no/mixed IFSC, empty/single identity, and exact prior/new locations.
  Keep old Full all-match/first-location controls. Run focused tests.

## Task 2: required reads, resources, and cancellation

- [x] Add instrumented production-source tests and retain read/resource REDs:
  partial/first mismatch avoids a distant fault; required prefix and identity/
  fallback hash reads fail without commit; cancellation before commit preserves
  prior locations and admission can retry after failure.
- [x] Verify optional hashes, accepted sequence, replacements, pending capacity,
  clamped windows, read bounds, and no background/tail work. Run focused tests.

## Task 3: qualification and frozen handoff

- [x] Cross-repair tiny donor sets using both retained pinned reference tools;
  compare exact bytes, status, source/donor/backup and movement effects. Keep
  qualified payload/hash differences explicit, without an unqualified parity claim.
- [x] Run pinned Vale3.26 `just ci` on final source and affected existing layout/
  geometry fixtures with both references; retain shutdown/resource coverage.
- [ ] Commit locally, verify clean original/historical worktrees, record exact
  HEAD/tree, commands, tool versions, input/output hashes, RED/GREEN and limits.
  Return frozen evidence for root's one independent review. No PR or push.
