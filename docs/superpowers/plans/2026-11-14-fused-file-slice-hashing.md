# Fused supplied-byte hashing implementation plan

> **For agentic workers:** use superpowers:executing-plans inline; no helpers.

**Goal:** add one incremental file-and-slice hashing helper for supplied bytes,
without changing creator or filesystem I/O and without a source-binding claim.

**Architecture:** one existing FileHasher plus one current-slice CRC/MD5 context.
Bounded processing and zero padding emit checksums through a fallible caller-owned
callback. Caller retains input and checksum collections. Terminal failure poisons reuse.

**Tech Stack:** existing Rust hasher/CRC/MD5 and packet::SliceChecksum types.

**Spec:** root fused-source-hashing source brief and accepted proposal
SHA `6a1b27bb225e9a7ea24e0e381b4cb889aa84bef3bd2fc6f9ad6075c0ca825041`.
Base: `1899fa3b41cf05969de1166a6fda31ba248c1229`.

## Scope and exact interfaces

- New `src/hasher/slices.rs`: `FileSliceHasher::new(slice_size:u64)->io::Result<Self>`;
  update(&mut self,bytes,cancel,emit)->io::Result<()>;
  finish(self,cancel,emit)->io::Result<FileHashes>. Exact proposal argument types.
  No Default/Clone/resume; fixed digest contexts/counters/poison bit only.
- `src/hasher.rs` module/export and consistent root re-export in `src/lib.rs`.
  Native FileHasher/hash_reader/parhash/create bodies stay byte-identical.
- New private tests and `tests/file_slice_hasher.rs`; concise docs and this plan.
  GPL-2.0-or-later provenance. No additional shared-file edits planned.

No filesystem/source ownership, input/slice/checksum Vec, new dependency/unsafe,
caller/source-binding/preparation/packet/parser/repair/naming/shutdown change.
Geometry is positive multiple-of-four with no added arbitrary helper input ceiling.
Use checked actual-byte/slice/index arithmetic, <=64KiB processing/polling windows,
and fixed4KiB zero scratch. Whole/prefix digests exclude virtual padding.

## Review focus

Boundary splits and16KiB prefix, only incomplete-tail padding, no extra empty slice;
exact callback index/first-error precedence and poisoned reuse; observed cancel on
empty/large updates/padding/last callback; arithmetic before FileHasher overflow;
no owned input/record allocation and honest one-traversal scope.

## Task

- [ ] Run focused incumbent hashing baseline at exact base. Add minimal declarations
  and a runtime checksum/emission regression, observe RED before helper logic;
  retain source/logs, no missing-symbol-only claim.
- [ ] Implement validated geometry, fused chunk updates, tail padding and callbacks,
  checked lengths/indexes, bounded cancellation and first-error poison. Observe GREEN.
- [ ] Qualify public outputs with existing FileHasher and independently padded
  slice_checksums for empty/tiny/exact/tail/arbitrary partitions and prefix edges;
  callback failures first/middle/last, last-callback cancellation and reuse refusal.
- [ ] Exercise private simulated overflow and deterministic checkpoint cancellation
  inside large updates/padding, <=64KiB work bounds and unchanged failed-state digests.
  Run a caller-owned held-file/counting-reader test proving bytes supplied once;
  do not turn it into an end-to-end performance, RSS, or stable-source claim.
- [ ] Run normal just ci with pinned Vale3.26, diff check, and clean local commit.
  Return exact SHA/tree/parent, command/tool/source/coverage/evidence receipts for
  root's single fresh independent review/publication. No helpers or publishing here.
