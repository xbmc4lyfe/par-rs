# Streaming PAR2 integration implementation plan

<!-- vale Google.Colons = NO -->
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
<!-- vale Google.Colons = YES -->

**Goal:** make RustyGet accumulate verified PAR2 contributions while downloading, with observable I/O, bounded memory, safe cancellation, and verified unpack handoff.

**Architecture:** extend the existing `StreamingParSession` with additive I/O statistics and cancellation; retain old entry points. Keep RustyGet's existing live-session registry and article callbacks, adding a focused lifecycle/budget module and explicit catch-up and write barriers. Source changes stay isolated from the active remote checkout and its open PR #378.

**Tech Stack:** `Rust` 1.100.0, existing PAR2 GF kernels, RustyGet native queue/cache hooks, offline NNTP functional fixtures, existing repository CI.

**Spec:** `docs/superpowers/specs/2026-11-14-rustyget-streaming-par2-design.md`

## Global constraints

- Initial target: four syndrome slots, reduced by job and aggregate budgets; preserve library defaults and public struct literals.
- Metadata must be complete and geometry checked before allocation. Every folded slice must pass IFSC CRC32 and MD5.
- Count damaged and pending slices globally; validate an invertible recovery plan before writes.
- Keep original archive sources available until parity decisions and any required backfill are complete.
- Preserve target whole-file MD5 verification, manual-check/repair-off policy, donor fallback, and existing unpack holds.
- Cancellation never publishes completion; interrupted in-place output remains unverified rather than claiming rollback.
- Source counters distinguish feed reads, backfill, recovery reads, and target verification; no zero-ms or microbenchmark-derived throughput claims.
- Compare current and candidate on Rust 1.100.0. Healthy-path proposed limits: at most 5% throughput loss and 10% callback-p99 growth, under a frozen statistical execution plan.
- Preserve dirty work, historical evidence, signing identity, scheduling locks, job caps, source review, and deployment holds.

## Review focus

- A metadata-bearing first recovery volume must supply its parity, even when it starts the session: task 2 regression.
- A file completed before metadata must not remain an unknown forever: task 2 late-index real-file regression.
- A cache flush or delayed article must not overwrite a certified target: task 3 writer-race regression.
- Retried/overlapping ranges must not duplicate a GF contribution or grow metadata without admission: tasks 1 and 2 regressions.
- Cancellation and generation replacement must not release an unpack hold or retain an uncharged live session: tasks 1 and 3 regressions.

## Source layout and execution

Library work uses `/Users/allen/.codex/worktrees/07e0/par-rs`, baseline `4e91c872882a2e39bb95a96b7dcfc14a6c8959fc`, branch `codex/rustyget-streaming-design`.

Caller work uses the isolated clone `/Users/allen/.codex/worktrees/07e0/RustyGet-streaming`, captured PR #378 head `36d7eb05b90ba977e1f216d93c15e4eac0738c72`. Its canonical HTTPS origin is `Appz4Fun/RustyGet`; the SSH source remote is retained only as capture provenance. Create an owned feature branch before edits. Do not update the active `live-repair-wiring` branch or include another owner's unmerged work in an unrelated default-branch PR. Reconcile the base after #378 lands, or retain a separately reviewed stacked delivery.

Native inline execution is used under the user's instruction to proceed; no repeated execution-method approval is needed. One independent source reviewer checks each completed repository branch before integration. Read and obey the caller's current AGENTS and linked execution procedures. A qualification or deployment hold is an explicit remaining delivery state, not PASS.

### Task 1: observable and cancellable library session

**Files:** modify `src/streaming.rs`, `src/reed_solomon.rs` and root reexports; create `src/streaming/control.rs` and focused tests beside `live_tests`; update streaming API documentation in `README.md`.

**Interfaces:** preserve `StreamingParSession::new`, `on_article_finished`, `on_recovery_volume_arrived`, `flush`, and `repair_available_targets_now`. Add `pub fn cancel(&self)`, `pub fn is_cancelled(&self) -> bool`, and `pub fn io_stats(&self) -> LiveIoStats`. The new `LiveIoStats` owns `u64` counters `ram_bytes_verified`, `source_bytes_read`, `backfill_bytes_read`, `recovery_bytes_read`, `target_verification_bytes_read`. Statistics are cumulative logical successful read bytes, including successful chunks before an error, not physical device I/O.

- [ ] Write real-file regressions `live_cancel_refuses_work_without_writes`, `live_io_separates_ram_backfill_and_target_verification`, `live_part40_global_repair_needs_rank_and_no_other_sources`, and `live_rejects_invalid_geometry_before_allocating`. Independently expect 100 one-slice files, 61 unknowns after the first 39 good files with part40 missing, no cutover with one parity slice, then exact bytes after the remaining 60 arrive. Remove non-target fixture source files after folding to make any final source reread fail. Assert target verification reads only the repaired target and duplicate callbacks do not increase verified-byte counts.
- [ ] Run each new test and retain its RED result; compilation failures first identify the missing additive APIs, then behavior assertions establish the actual missing behavior.
- [ ] Implement session-owned permanent cancellation, wake blocked admission/fold waits, poll bounded folding/read/solve work, and pass the flag to the existing engine. Keep partially written output unverified on cancellation. Instrument actual reads with bounded counted readers and verify RAM input counts after IFSC success. Preserve old methods' behavior while no cancellation is requested.
- [ ] Validate source count, aligned slice size, checked aggregate geometry, duplicate IDs, article length/offset and bounded coverage metadata before mutating tracker state; refuse unsafe input without panics or allocations outside admission. Tests cover truncated RAM payload, offset overflow, and repeated partial overlaps.
- [ ] Run `cargo test --locked`, strict all-target/all-feature Clippy, and `cargo check --locked --no-default-features` with the explicit named 1.100.0 toolchain PATH. Commit the independently usable library change and record exact head/tree and RED/GREEN evidence.

### Task 2: bounded caller startup and catch-up

**Files:** create `rust/src/parlive.rs`; modify `rust/src/lib.rs`, `rust/src/parchecker.rs`, `rust/src/dupefallback.rs`, `rust/src/queuecoord.rs`; add tests in the owning Rust modules and `rust/tests/parchecker.rs`.

**Interfaces:** add caller-private `SessionGeneration(u64)`, `SessionBudgetLease` (RAII), and `LiveSessionResources { options: SessionOptions, reservation_bytes: u64 }` in `parlive`. `resources(slice_size: u64, effective_pool_bytes: u64) -> Option<LiveSessionResources>` computes checked component reservations. Registry entries own the generation, session, and budget lease. Existing public parchecker wrappers remain available. Add `streaming_session_io_stats(nzb_id: i32) -> Option<LiveIoStats>` and `streaming_session_cancel(nzb_id: i32)`.

- [ ] Write failing tests `first_recovery_file_is_absorbed_once`, `late_index_reconciles_completed_and_partial_files`, `live_budget_is_shared_and_released`, `live_small_budget_reduces_slots_or_falls_back`, and `live_retry_and_mapping_failures_are_visible`. Use actual created PAR2 metadata and source files; assert real verified counts and repaired bytes rather than mock invocation counts.
- [ ] Map budget ownership to `ParBuffer` through `articledl::memory_monitor_effective_par_buffer_mb`. Use one process-wide admission pool, with a proposed per-job ceiling of 128 MiB. Account for both syndrome/output caps, independent working/staging/queue/scratch caps, matrix/engine minima, and checked metadata bounds; refuse insufficient admission and retain normal repair. Do not call the payload reservation a total process RSS bound. Reevaluate pressure at admission; invalidate a live generation before releasing its charge.
- [ ] Start up to four bounded slots as soon as complete metadata arrives, within existing repair policy. Absorb the triggering recovery-containing PAR2 file, register queue volumes, then reconcile accepted ranges from completed and in-progress files. Prefer cache snapshots; only read committed disk data after the relevant flush barrier. Mark holes and preserve exactly once folding on replay.
- [ ] Retain and surface per-generation errors, mapping misses and fallback reasons; do not discard failed session operations with `let _`. Cancellation/replacement removes the old entry, cancels its session and releases its lease only when actual owners drop it.
- [ ] Run focused RED/GREEN tests followed by the caller's full Rust tests under Rust 1.100.0, jobs 3, and warnings denied. Commit the caller startup deliverable, retaining a distinct source manifest when local library overrides are used. Final publication must use a reviewed upstream library revision and a locked dependency, not a local path patch.

### Task 3: writer ownership and unpack handoff

**Files:** modify `rust/src/parlive.rs`, `rust/src/parchecker.rs`, `rust/src/queuesubsys_host.rs`, `rust/src/queuecoord.rs`, `rust/src/articledl.rs`, `rust/src/postproc.rs`; use existing native writer/cache code in `rust/src/artwritercore.rs` where necessary.

**Interfaces:** add caller-private `TargetWriteLease`, bound to `(nzb_id, generation, file_id)`. Registry repair operations require that lease; the queue and cache writer paths honor it for the same target generation. Preserve the public early repair wrapper but route production invocation through the guarded caller path. `streaming_session_forget` cancels and invalidates before release.

- [ ] Write deterministic channel/barrier regressions `live_repair_drains_cache_before_patching`, `late_article_cannot_overwrite_verified_repair`, `replaced_generation_cannot_release_hold`, `cancelled_repair_keeps_hold`, and `manual_or_repair_off_never_fetches_or_patches`.
- [ ] Acquire target write ownership before patching, drain committed cache writes using the existing cache-content and flush-lock mechanisms, and reject or defer late conflicting writes. Do not hold the global queue mutex across hashing, disk I/O or GF work. Keep accepted identical retries idempotent.
- [ ] Check generation, cancellation and verified target MD5/length before releasing a held volume. Preserve partial output and the hold on any interruption or verification error. Publish measured solve/write/verify tail counters from the real caller path.
- [ ] Run focused regressions then the required full Rust, daemon, and affected functional tests. Commit the guarded handoff deliverable; record lock ordering and race-test evidence.

### Task 4: real caller qualification and delivery

**Files:** add `tests/functional/dupefallback/streaming_par_test.py` in RustyGet using its existing offline provider/generator infrastructure; use repository benchmark infrastructure for the separate frozen resource/performance packet. Update caller documentation and the design with actual limitations and results.

**Interfaces:** fixture results include exact source/binary/compiler identities, verified hashes, actual callback hit counts, the Task 1 I/O counters, repair tail, and resource records. Baseline and candidate use the same Rust 1.100.0 compiler and fixtures; no historical result is relabeled.

- [ ] Exercise the 100-file part40 scenario, late index, first-file parity, cache pressure, late slot growth, donor/obfuscated mapping, malformed parity, cancellation/generation races and repair/manual policy through the real queue/cache/unpack path. Prove no final whole-set reread on the fully RAM-fed pretracked positive case; account separately for backfill and target verification.
- [ ] Freeze the approximately 100 GB / 500 MB split-file campaign, whole-file/scattered/mixed damage, healthy controls, independent-process trials, CPU/RSS/I/O/tail metrics, ratio confidence intervals, and stopping rule before timing. Check actual space and obtain canonical worker admission/locks. A capacity or ownership failure leaves this campaign unexecuted; it does not permit smaller evidence to stand in for it.
- [ ] Preserve the current Rust baseline and qualify the actual changed caller. Apply the approved healthy throughput and callback-p99 guardrails without filtering unfavorable trials. Missing or inconclusive evidence keeps default enablement/deployment held.
- [ ] Before caller pushes, run the exact AGENTS local Rust/daemon/affected functional commands; require Linux x86_64, Linux arm64, and macOS build checks. Inspect the complete final source and resolve final-head review findings. Preserve signed history and integrate a locally signed, source-equivalent squash under the repository's canonical owner and identity checks.
- [ ] Follow every applicable main workflow, then perform authorized exact-artifact deployment with preservation and rollback evidence. Verify service health, source identity, repaired bytes, and unpack resume. Report source merged, performance-qualified and deployed states separately; do not declare the overall feature complete while a required gate remains.
