# Explicit donor read budget implementation plan

> **For agentic workers:** use superpowers:executing-plans inline; no helpers.

**Goal:** add a parameterized extra-donor DATA-read budget while preserving native
methods, policies, options, errors, and unrelated I/O paths.

**Architecture:** one private opened-file primitive source plus a call-local meter
backs the new method. Its exact-fill loop charges the entire request before each
engine-issued read, including exposed short/Interrupted retries. Reports stage
until the sticky first terminal error and current cancellation token are checked.

**Tech Stack:** existing Rust File/PacketSource/scanner and repairer apply seams.

**Spec:** root donor-read-cap source brief, preflight rulings/review, and proposal
SHA `e1011f8e9ef6866eb7d21c0ca8684459f864f5d36a36c385c1ce64e3f7ffd9ab`.
Base: `cf4b072b1ec9de911c5617b3996c66764957a881`.

## Global constraints

No helper/publishing/caller/Cargo/dependency/unsafe FFI or unrelated product edits.
No default numeric budget, observed-length-as-I/O claim, resource-limit increase,
quota-aware refill, source-length truncation, hidden EOF probe, scanner selection
change, partial admission after failure, source binding, RSS, or time guarantee.
Keep native Full direct delegation, exhaustive RepairError, and option literals.

## Files and interfaces

- New `src/repairer/donor_budget.rs`: public DonorReadBudget with private counters,
  new/limit_bytes/charged_bytes/remaining_bytes and no Default; separate typed
  DonorReadError/limit scope; private single-attempt file backend and metered
  exact-fill source; staged additive add_extra_file_with_read_budget method.
- `src/repairer.rs`: private module declaration and public additive type exports.
- `src/repairer/donor.rs`: minimum parent visibility for OrderedReport,
  scan_ordered_source and apply_ordered, leaving native code bodies unchanged.
- `src/lib.rs`: root exports. Existing packet file/length accessors suffice;
  no packet/scanner source edits planned.
- `tests/donor_read_budget.rs`, narrow private fault/count tests, concise feature
  docs, and this plan. Test/source provenance follows GPL-2.0-or-later.

New method arguments: path, ExtraFileScanPolicy, mutable shared DonorReadBudget,
optional per-call byte ceiling, observer. Returns Result<usize,DonorReadError>.
Error wraps RepairError or identifies limit scope/limit/charge/next request or
counter overflow with the original request length. Numeric caller defaults/status
remain later decisions and do not block this parameterized engine task.

## Review focus

Primitive request versus returned bytes and hidden retries; whole-request two-cap
atomicity/overflow; first swallowed source fault before cancellation masking;
complete state/scanned-marker preservation on errors; old native and large-budget
policy parity. Cover each through deterministic request/result logs and real files.

## Task

- [ ] Run focused incumbent private/public donor baselines on exact base.
- [ ] Add minimal new API/test scaffolding. Observe public zero-cap admission/state
  runtime RED and primitive8→3/5→Interrupted/5→5 charge18 runtime RED before meter
  implementation. Retain source/logs; no missing-symbol-only evidence.
- [ ] Implement whole-request aggregate-first/per-call admission, checked counters,
  one-attempt backend, exact-fill retry loop, sticky terminal fault, current-token
  cancellation, zero/range/EOF handling. Observe focused GREEN.
- [ ] Stage both Full/Ordered reports using the same source, guard before apply,
  and retain old API/delegation bodies unchanged. Qualify all state fields and
  registry/scanned markers on required-read/hash/fallback/cap/cancel faults.
- [ ] Test exact/under/zero/empty, both limits and shared retries/donors, all exposed
  primitive results, overflow/range, no later calls after sticky fault, Full shifted
  and repeated windows, Ordered prefix/terminal/identity/fallback/prefetch refusal,
  ample native parity, real donor bytes and RS repair, exhaustive errors/literals.
- [ ] Run normal just ci with pinned Vale3.26, source diff checks, and local commit.
  Return immutable clean HEAD/tree/parent, command/tool/source/coverage/evidence
  receipts for root fresh review. No reference campaign for this resource policy.
