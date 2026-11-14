# Streaming PAR2 repair for `RustyGet`

Status: approved by the user with “ok go” after reviewing this design on 2026-11-14. Implement early bounded accumulation under the stated resource and verification contracts. Existing deployment and coordination holds remain in force.

RustyGet should do PAR2 verification and repair accumulation while articles arrive, so repairing a damaged archive volume does not require a new pass over the entire downloaded set. It should fetch useful recovery volumes alongside data and release a held unpack volume as soon as that volume is repaired and verified.

## Existing implementation

The inspected par-rs revision is `4e91c872882a2e39bb95a96b7dcfc14a6c8959fc`. `StreamingParSession` already provides article coverage, IFSC CRC32 and MD5 verification, per-exponent GF accumulation, bounded staging and folding, recovery packet validation, volume scheduling, and selected-target early repair. `SyndromeBank` and `StreamingSliceAssembler` provide a lower-level memory-only alternative.

The inspected RustyGet revision is `213441c1687e7b5da7404f6fc611502f3c6b3df4` on `live-repair-wiring`. Its queue coordinator already passes article-cache snapshots to the live session. Its file-completion callback starts a session after the first complete PAR2 file, and postprocessing can repair held volumes when the session reports sufficient recovery. These are source observations, not proof about the deployed binary.

The remote checkout is being edited by another owner. Captured working changes in `queuecoord.rs` enforce `ParRepair` and manual-check policy; preserve them. Resolve caller ownership before editing, and use fresh source identities rather than the older captured revision.

Read-only capture receipts and the static audit are retained in the local `rustyget-streaming-recon-qdhqz0pb` evidence directory. Its failed attempt to retrieve the unpublished revision from GitHub is retained separately from the successful SSH Git-object captures.

## Goals and limits

- Fold each accepted source slice exactly once into each active exponent, using article bytes before their cache storage is released whenever possible.
- Catch up verified source bytes that arrived before metadata or before a required exponent began tracking.
- Download recovery according to actual damage and usable recovery, without waiting for all source files to finish.
- Repair requested held volumes when the complete set's unknown slices can be resolved, then verify the target before unpack resumes.
- Keep all allocations and work admission within explicit job budgets, with observable fallback when those budgets are insufficient.
- Preserve manual checks, settings that turn off repair, provider fallback, duplicate/twin recovery, and unpack cleanup behavior.

This remains standard PAR2. Unarrived slices are unknowns alongside damaged slices. Recovery count is a readiness filter; the solver must find a usable full-rank matrix before writing. Recovery packets must pass set identity, geometry, payload checksum, and exponent admission checks. The [PAR2 specification](https://parchive.github.io/doc/Parity%20Volume%20Set%20Specification%20v2.0.html) defines contributions using input constants raised to recovery exponents.

There is no promise of zero milliseconds of final work or 20–50 GB/s end-to-end throughput. Solving, writes, synchronization, and target verification remain. No new coding format, per-volume parity format, or upload-side change is included.

## Approaches

| Approach | Benefit | Cost and limitation |
| --- | --- | --- |
| Early bounded accumulation using `StreamingParSession` | Reuses existing integration and avoids a new source pass for already tracked exponents | Does verification and GF work on healthy downloads; later exponent expansion can require backfill |
| Start on damage and backfill the known prefix | Saves GF work on healthy downloads and follows the supplied example directly | Needs retained source bytes and a prefix read after damage; later damage can require more backfill |
| Replace the caller with the memory-only assembler | Gives the caller direct control of source I/O | Duplicates existing scheduling, persistence, file verification, and concurrency integration |

The approved approach is early bounded accumulation. Keep damage-triggered backfill as a supported fallback; do not replace the live engine with a second implementation.

## Proposed default and resource policy

Begin after complete, validated Main, FileDesc and IFSC metadata is available. Fetch the small metadata-bearing index early without eagerly fetching all parity. Before admitting metadata, use checked source geometry and complete file-to-slice mapping; incomplete metadata keeps the job on the existing safe path.

The proposed initial target is four syndrome slots, reduced by the job's syndrome budget and available useful exponents. Use loaded exponents and the existing canonical sequence only as computation choices; filenames never authenticate recovery payloads. Do not change the library's public default options or add fields to public structs merely to tune this caller.

Derive caller limits from the existing job resource policy. Account separately for syndrome payloads, partial-slice staging, copied article payloads, queued folds, reconstructed slices, matrix planning, and engine buffers. Enforce an aggregate admission limit across active jobs as well as individual component caps. The implementation plan must identify the existing budget owner and concrete configuration mapping before code is changed.

If four slices cannot fit, reduce the initial count. If no useful slot or a required solve cannot fit, retain ordinary repair as the fallback and expose the reason. Never silently exceed a cap to preserve a performance claim. Queue saturation may fold inline, so article callback latency must include that work.

## Data and source ownership

A session belongs to one download generation, PAR2 set identity, checked file geometry, and file-ID mapping. Bind obfuscated and renamed files through the existing mapping helpers; a name-only miss must be visible and cannot count as a verified contribution.

Only yEnc-accepted article ranges with validated offset and length are eligible. Reassemble the PAR2 slice, verify its IFSC checksums including final-slice zero padding, then fold it. Duplicate callbacks, overlaps, retries, donor articles, and file-completion replay must not XOR a source contribution twice. A provider/article CRC alone does not establish a valid PAR2 slice.

Hold or copy the article payload until folding has consumed it. Use existing bounded staging for cross-article slices. Under cache pressure, a disk fallback must wait for the corresponding write/cache flush to be committed; reading an incomplete target is not equivalent to consuming accepted RAM bytes.

Verified source bytes must remain stable for their session generation. Replacement, destructive rename, restart, or a conflicting write invalidates the affected session before further repair. For the first version, rebuild the session from retained, reverified sources instead of attempting algebraic subtraction of old contributions. Do not serialize and resume GF buffers across process restarts in this version.

Keep original archive sources available until parity decisions and any required backfill are complete. Do not add early source deletion as part of this change. No additional full source copy is required.

## Metadata arrival and backfill

When the session starts, reconcile both completed files and successful in-progress article ranges. Mark failed ranges and replay accepted ranges through the same verification path. The reconciliation must cover files that completed before the index arrived, not only the file whose completion triggered session creation.

If the first PAR2 file contains recovery data, absorb that data as well as its metadata. `StreamingParSession::new` seeds exponents but does not itself add those recovery payloads; initialization must not lose their availability or count them twice when the completion notification is replayed.

Register paused recovery volumes and apply scheduler unpause decisions under the caller's existing repair policy. Additional valid exponents may allocate bounded slots and backfill precisely the verified sources missing from those slots. Record this I/O as backfill. If needed sources are unavailable, keep the relevant slot unusable and fall back visibly; do not fabricate a complete syndrome.

Backfill should run during the remaining download when possible. A claim of one prefix read applies only to a fixed exponent set; growing the set later may require another read. Expose that distinction.

## Repair and unpack handoff

Count every damaged, unarrived, and partially arrived slice as unknown until verified. Wait for pending folds, admit the matrix and output buffers, validate usable recovery rank, and solve only the requested targets' rows.

Before patching a target, the caller must obtain exclusive write ownership for that target generation and drain relevant article/cache writes. It must either cancel/suppress subsequent article writes for the reconstructed ranges or keep them unable to invalidate the certified bytes. An internal session mutex alone does not control downloader writes.

Keep a target held from unpack while repair or verification is incomplete. Preserve the current whole-file MD5 and length check after patching; its target-file read is explicitly outside the avoided whole-set source pass. A file becomes available to unpack only after the write barrier and verification succeed. Check generation again before publishing that result.

Cancellation stops new admissions and suppresses completion publication. If cancellation interrupts an in-place solve, preserve partial output as unverified, keep the unpack hold, and let the ordinary verification/repair path recover. Do not promise rollback of already written bytes. Cancellation must be polled between bounded work chunks rather than only after an entire large job.

## Observable behavior

Record counters for accepted RAM bytes, source verification reads, backfill bytes and reason, tracked/ready exponents, pending folds, inline folds, repaired bytes, target verification reads, fallback reason, and session generation. Counters must identify the real production caller boundary rather than only a helper test.

Define repair tail as elapsed time from the last required verified data or recovery arrival to verified target availability for unpack. Keep solve, write, synchronization, and target verification times separately. Report the avoided whole-set source pass independently from target verification and earlier backfill.

## Qualification

Use offline article providers and byte-identical fixtures through the actual RustyGet queue, cache, mapping, repair, and unpack-hold boundary. Test the current incumbent and the candidate using Rust 1.100.0, retaining existing Rust behavior as the baseline. Do not relabel older compiler results.

Correctness cases include a 100-file set with one damaged slice in part40 and one recovery slice; too many unknowns at part40; sufficient independent recovery near completion; early and late index arrival; the first PAR2 file containing recovery; out-of-order and cross-slice articles; duplicate callbacks; failed then retried articles; obfuscated names; donor repair; corrupt and duplicate recovery packets; singular exponent selections; cache pressure; slot growth; generation changes; cancellation; and settings for manual checks or turning off repair. Verify repaired bytes against held originals and an independent PAR2 reference control.

The required no-whole-set-reread positive case supplies all post-initialization slices from RAM, pretracks the required exponent, and proves that final repair does not reread the other source files. Separate cases must show and account for deliberate backfill and the repaired target's verification read. A small library-only fixture cannot qualify the downloader boundary.

Resource and performance qualification includes the common approximately 100 GB workload in 500 MB split files, whole-file loss, scattered damage, and mixed damage. Record healthy throughput, article callback p99 latency, total CPU, peak RSS, logical source read bytes, available physical I/O metrics, fold lag, and repair tail. Four initial slots and proposed healthy-path guardrails of at most 5% throughput loss and 10% p99 callback-latency growth are author choices for review. Freeze exact trials, controls, statistical decision rules, and stopping criteria in a separate execution plan before timing; no adaptive reruns to erase a failure.

Read RustyGet's applicable evidence, conversion, benchmark, and deployment instructions before execution. Coordinate the remote scheduling owner, fixed shared locks, storage, and job caps. Before every caller push, require the prescribed local Rust, daemon, and affected functional tests, plus the three-platform build checks. Preserve failed and inconclusive attempts.

## Delivery and remaining decisions

Implement in isolated work with an explicit caller owner; preserve the active remote edits and existing backend holds. Use signed canonical commits and the repository's required final-head reviews and CI. The owning agent carries any deployable caller change through authorized installation, health and changed-behavior verification; a merge alone is not deployment completion.

The builder may choose internal bookkeeping and additive API details after measuring the actual gaps. The implementation plan must settle the budget-owner mapping, cancellation interface, and downloader write-barrier hook from current source. If any cannot be provided safely, narrow the deliverable to the corresponding library/caller preparation and report the exact remaining integration limitation.

The user approved the early bounded default and this design's proposed guardrails. Internal bookkeeping and additive API details remain engineering choices under these contracts.
