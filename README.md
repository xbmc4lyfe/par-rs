# par-rs

A general-purpose, SIMD-accelerated PAR2 parity crate in Rust, for downloaders that verify and
repair while files arrive (rustyget / nzbget) and for indexers that need to understand par2
files without downloading the archives they protect (Atlas). It replaces `par2cmdline-turbo` /
`libpar2` and nzbget's PAR2 helpers (`twin`, `parrenamer`, `dupefallback`, `pardamage`,
`parparser`, `parchecker`, `repair`), and adds zero-copy PAR1 / PAR2 / PAR3 introspection,
obfuscated-file resolution and an in-memory streaming repair API.

```
rust-version = "1.99", edition 2024, lib name par_rs
dependencies: md-5, memchr, crc32fast, sha1, regex, thiserror; optional rayon ("parallel"), memmap2 ("mmap") — both default on
crate-type   = rlib + staticlib (C ABI in src/ffi.rs)
```

### Safety policy

The modules that parse untrusted input or implement the unified parity specification (`gf2`,
`inspect`, `par2`, `bridge`, `verify`, `repair`, `stream`) compile with
`clippy::indexing_slicing`, `unwrap_used`, `expect_used` and `panic` **denied**: a truncated,
corrupt or adversarial buffer yields a partial result, never a panic, and no parser allocates
more than its input justifies (every allocation is bounded by the bytes actually present).
The older engine modules carry a module-level allow and are covered by fuzz-style and
differential tests instead. `unsafe` is confined to the SIMD kernels (`gf16/simd.rs`,
`md5simd.rs`, the hardware CRC in `crc.rs`), the memory map in `repair.rs` and the C ABI.

## What it does

| Area | Module | Highlights |
|---|---|---|
| GF(2) algebra | `gf2` | `crc32_combine` / `crc32_zeros` / `crc32_unzero` / `crc32_uncombine_{prefix,suffix}` in `O(log n)`, yEnc part folding (`fold_yenc_parts`, `fold_yenc_indexed_parts`), IFSC folding to the whole-file CRC (`fold_ifsc_crcs`), `O(1)`-per-byte `RollingCrc32`, LCM grid intervals |
| CRC-32 kernels | `crc` | `pclmulqdq` folding (x86_64), `crc32x` 3-way (AArch64), slice-by-8 fallback; `crc32_combine`, `crc32_zeros` via `x^n mod P` exponentiation; O(1) rolling window table |
| Hashing | `hasher`, `md5simd`, `parhash` | fused CRC-32 + MD5 + 16k-MD5 in one pass; 16-lane SIMD MD5 for independent messages; parallel slice/file hashing pool |
| GF(2^16) | `gf16`, `gf16::simd` | log/antilog tables, PAR2 input constants, split-nibble shuffle kernels for NEON / SSSE3 / AVX2 / AVX-512BW on de-interleaved byte planes, multi-destination accumulate, runtime dispatch **with self-test fallback** |
| Introspection | `inspect` | `inspect_par2`: zero-copy scan of all 12 PAR2 v2.0 packet types with resync after garbage, per-packet MD5 (`VerifyMode::{None, Metadata, All}`), PAR1 / PAR3 headers, `CreatorInfo` fingerprinting (tool / version / arch), `.volNNN+MM.par2` analysis, exponent-0 recovery fingerprint |
| Indexer summary | `par2` | `inventory(data) -> Inventory { files, block_size, complete, truncated, sealed }` with per-set block sizes, UniFileN names, sanitised paths; `is_base_par2(subject)`, `file_descriptions`, `display_name`; prefix-safe and monotonic |
| Obfuscation | `bridge` | `Par2Bridge`: size chain → 16 KiB MD5 → folded CRC-32 vs IFSC → RAR5 volume number (`rar5_volume_number`, `rar5_vint`) |
| Verification (memory) | `verify` | `SetVerifier`: slices at natural offsets (CRC then MD5), rolling-CRC discovery of shifted slices of any file, `VerificationReport` / `RepairAssessment` |
| Repair (memory / disk) | `repair` | `repair_slices`, `repair_selected_slices` (surgical rows only), exponent-0 pure-XOR fast path, 64 KiB tiled multi-target folding, `repair_on_disk(DiskRepairPlan)` |
| Streaming (memory) | `stream` | `SyndromeBank` (one buffer per exponent, verified slices folded and dropped), `StreamingSliceAssembler` (out-of-order yEnc byte ranges, EOF padding, damage marks), `can_solve_now` / `solve_now` / `solve_selected_slices` before the download finishes |
| Packets | `packet` | 64-byte header framing, forward resynchronisation over zero-filled/truncated gaps, lazy `RecoverySliceRef` (payload stays on disk, MD5 verified only when used), all standard payload types, `libpar2` file-id ordering, encoders for all packet types |
| File names | `filenames` | `ParseParFilename` / `SameParCollection` / `FindMainPars` port, `.vol` block extraction, queued/completed block estimation, `select_more_pars`, `pick_twin_volume` |
| Twins | `twin` | `par2_set`, `block_size` (with estimate when Main is lost), FNV-1a fingerprint, `compare_twin_par2_data` (0 twin / 1 other files / 2 renamed) |
| Damage | `damage` | hole math (`blocks_touched`, `range_covered`, `compute_holes`), `project_par_damage`, `par_cannot_cover`, zero-read `verify_success_file_crc`, article-CRC `verify_partial_file` / `smart_calc_range_crc` |
| Scanner | `scanner` | aligned probe → sliding window (rolling CRC, bit pre-filter, open-addressed CRC table, MD5 confirm), virtual zero padding at EOF, fused file hashes in the same pass |
| Reed-Solomon | `reed_solomon` | recovery planning with singular-matrix retry, SIMD-accelerated Gauss-Jordan inversion, two-phase syndrome → `A⁻¹` solve, chunked streaming under a memory budget, reader thread + worker pool, L1 tiling, output grouping |
| Repair | `repairer` | `Par2Repairer`: load (metadata only), quick verify from download CRCs, full scan, misnamed/split/extra/dupe files, incremental volume loading, backup rotation (`.1`, `.bak`, delete), post-repair verification, cancellation, observer callbacks |
| Streaming | `streaming` | fold verified blocks into Reed-Solomon syndromes **while downloading**; repair at the end reads only the recovery slices; early repair as soon as `damaged + pending <= recovery`; works before recovery volumes arrive (syndromes need only the exponents) |
| Rename | `renamer` | `ParRenamer` port: par2-by-content detection, `<setid>.volNNN+01.PAR2` renaming, 16k-hash renaming, split-fragment and existing-target protection, missing-file detection with ignore extensions, `.bad` marking, dry-run |
| Create | `create` | `build_set` (index + volumes in memory, UniFileN for non-ASCII names) and `create` on disk; exponential / uniform / single volumes, `par2cmdline`-compatible layout |
| C ABI | `ffi` | opaque repairer handle, callbacks for progress/messages/quick-verify, stateless CRC and name helpers, renamer entry point |

## Performance

Apple M4 (4P + 6E cores, NEON), 10 threads, warm page cache. Dataset: 10 × 100 MiB random
files, 1 MiB slices (1000 input blocks), 100 recovery blocks. Best of 3, seconds; every tool
produced correct output (verified by MD5 against the originals). Harness: `bench/compare.py`
(`RUNS=3 python3 bench/compare.py`, tool binaries via environment variables).

| tool | create | verify (intact) | repair (40 corrupt blocks in 4 files) | repair (1 file missing, 100 blocks) |
|---|---|---|---|---|
| **par-rs** (`nzbpar`) | 0.96 | **0.10** | **0.52** | **0.79** |
| nzbfast `parfast` 1.9.0 | 0.92 | 0.17 | 0.56 | 0.87 |
| ParPar 0.4.6 | **0.89** | – | – | – |
| par2cmdline-turbo 1.5.0 | 1.45 | 0.78 | 1.86 | 1.44 |
| parmesan-par2 (Rust) | 1.80 | 1.57 | 5.73 | 11.99 |

(`fpar2` produced no output on this machine and was dropped.)

Where the time goes, and why create and repair cannot be *much* faster than nzbfast or ParPar
on this hardware: both phases are bound by GF(2^16) multiply-accumulate, which on NEON is a
nibble-table-lookup kernel at ~0.5 instructions per byte. The three engines are within 1.4x of
each other on that kernel; nothing algorithmic (NTT, bitsliced "four Russians", `pmull`) beats it
at these set sizes — a bitsliced prototype measured 1.25x the shuffle kernel at best and lost
badly for small recovery counts, and nzbfast's own NTT only pays off past ~250 recovery blocks.

```
GF16 engine (1000 × 100 × 1 MiB): 32 GB/s single thread, 170 GB/s on 10 threads   (nzbfast fold: 125 GB/s)
md5: scalar 0.8 GB/s per core; 16-lane NEON/SSE2 kernel 4.5 GB/s per core (independent messages)
crc32 (crc32x, 3 streams): ~33 GB/s per core
```

Indexer path (single core, M4; the Atlas project's own Rust code measured on a 2.3 GHz Xeon in
parentheses for scale):

```
inventory, 200-file index, 19,600 slices, metadata MD5s verified:  2,365 /s   (821 /s, no MD5 check)
inventory, 2-file index:                                           88,000 /s   (179,000 /s, no MD5 check)
inventory, recovery volume:                                         1.0 GiB/s  (0.9 GiB/s)
is_base_par2, mixed subjects:                                      52 M/s      (18.8 M/s)
fold 94 yEnc part CRCs into a file CRC:                            548,000 /s  (56,000 /s)
```

`inventory` walks the buffer once trusting packet lengths, hashes every metadata packet in one
16-lane MD5 batch, and only falls back to the resynchronising scanner when a packet fails
(`inspect_for_inventory`); folding uses a per-block-size operator table (`Crc32Shift`, four
lookups per slice instead of a 32-step multiply) once a set has enough slices to pay for it.

What makes the hashing phases fast:

* **Multi-lane MD5** (`md5simd`): per-slice digests are independent messages, so 16 of them share
  one NEON/SSE2 instruction stream (4 lanes × 4 interleaved groups to hide the chain latency).
* **Parallel hashing** (`parhash`): slice CRC+MD5 jobs are spread over all cores; whole-file MD5
  chains run one file per thread.
* **Verify** checks every slice at its expected offset first (all cores); only files that fail get
  the sliding scan, in parallel across files and without re-hashing the slices already verified.
  The serial whole-file MD5 is skipped when every slice matched (`RepairOptions::full_file_md5`
  turns it back on); files without IFSC packets are always hashed in full.
* **Repair** patches damaged files in place (the backup copy is a reflink clone where the file
  system has them), verifies the recovery packets it uses on all cores, reads inputs on several
  threads and skips `fsync` unless asked (`sync_repaired`).
* **Create** fixes the file order from the 16k hashes alone, so the whole-file and slice digests
  run concurrently with the recovery computation; recovery packet MD5s are computed afterwards on
  all cores.
* **Engine**: workers claim tiles through an atomic counter (fast cores take more), and a reader
  pool keeps them fed.

`cargo run --release --example bench [slice] [inputs] [outputs] [threads] [tile_words] [group] [batch]`

## Usage

```rust
use nzbget_parity::{Par2Repairer, RepairOptions, NullObserver, RepairResult, QuickInfo};

let mut r = Par2Repairer::new("/downloads/release", RepairOptions::default());
r.load_par2_set(std::path::Path::new("/downloads/release/release.par2"))?;
r.finalize()?;

// Optional: zero-read verification from the downloader's article CRCs.
let mut quick = |name: &str| -> Option<QuickInfo> { None };
let verdict = r.verify(Some(&mut quick), &mut NullObserver)?;

if verdict.repair_needed {
    r.add_split_fragments(r.base_dir().to_path_buf().as_path(), &mut NullObserver)?;
    if !r.repair_possible() {
        // ask the queue for `r.blocks_needed()` more blocks, then `r.load_par2_file(&vol)` and retry
    }
    match r.repair(&mut NullObserver)? {
        RepairResult::Repaired { files, blocks_recovered } => { /* ... */ }
        RepairResult::NotNeeded => {}
    }
}
```

### Streaming repair (during download)

```rust
r.enable_streaming(&StreamingOptions { expected_recovery_blocks: 20, ..Default::default() })?;
// as each article lands (nzbget ArticleWriter):
r.streaming_segment_written(file_index, offset, len, /*success*/ true)?;   // data on disk
r.streaming_segment_data(file_index, offset, &decoded_article)?;          // or from memory
r.streaming_segment_failed(file_index, offset, len)?;                     // article lost
// volumes arriving later:
r.load_par2_file(&vol)?;
let st = r.streaming_status().unwrap();
if st.repair_possible_now {          // damaged + not-yet-downloaded <= usable recovery blocks
    r.repair(&mut observer)?;        // uses the accumulated syndromes: reads k recovery slices, not n inputs
}
```

Every verified block is multiplied into one `slice_size` buffer per tracked exponent as it
arrives (≈30 GB/s per core), so a 20-recovery-block set costs ~20 MiB of RAM per MiB of slice
and the final repair is `O(missing × recovery)` instead of a full pass over the data. PAR2 is a
single code over the whole set, so blocks that have not been downloaded yet count as missing:
an archive part can be reconstructed before the download finishes only while
`damaged + pending <= recovery` (`StreamingStatus::repair_possible_now`).

### Repair-while-downloading (`StreamingParSession`, thread-safe)

```rust
let session = StreamingParSession::new(&packet_set, base_dir, SessionOptions { preallocated_syndrome_slots: 32, fold_threads: 2, ..Default::default() })?;
session.register_queued_volume(QueuedVolume { id, blocks, paused: true });          // every .volXX+YY.par2 in the NZB
// ArticleWriter threads (concurrently):
let out = session.on_article_finished(&file_id, offset, size, article_crc32, Some(&decoded_bytes))?;
let (events, unpause) = session.on_article_failed_permanently(&file_id, offset, size)?; // → UnpauseAction for the queue
session.on_recovery_volume_arrived(&vol_path, Some(queued_id))?;                      // XORs R_e into its syndrome slot
// DirectUnpack / StreamRepairController::StartLive:
session.try_splice_live_slice(&file_id, hole, &twin_bytes, &path)?;                   // Mode A: donor/twin splicing, any time
if session.status().early_cutover_possible {                                           // Mode B: D + U <= R
    let rep = session.repair_available_targets_now(&[part01_id])?;                     // only part01's rows of A⁻¹
    // rep.files == [(part01_id, VolumeStatus::CompleteAndVerified, md5_ok)] → unpack it now
}
```

Slices move `Unarrived → PartiallyArrived → VerifiedGood | Damaged`; hashing runs lock-free on
the writer thread (with a `crc32_combine` pre-check over article CRCs), folding uses one lock per
syndrome slot plus an optional bounded folder pool (full queue ⇒ inline fold, never blocking the
writer), and each slot keeps a `folded_mask` bitset so slots allocated when a late volume arrives
are back-filled from disk for exactly the slices they lack.

CLI front end for manual use: `cargo run --release --example nzbpar -- {create|verify|repair|rename|info} ...`

## Testing

* `cargo test` — 136 unit tests, 2 doctests and 20 integration tests in six suites (`gf2_algebra`, `packet_resilience` — truncation sweeps, bit flips, torn headers, garbage; `bridge_and_verify`; `reed_solomon_repair` — SIMD vs scalar bit identity over sizes and alignments, batch / surgical / disk repair from real volumes; `streaming_repair` — scrambled 7000-byte articles into 8 KiB slices with early cutoff; `indexer_and_checker_requests` — the optimistic inventory scan against the resynchronising scanner over every prefix and bit flip, the subject rule, wildcard ignore masks, collection loading) (every kernel is checked against the scalar reference on every
  supported ISA of the host; packet parser against corrupt/shifted/duplicated streams; damage,
  scanner, engine, repairer and renamer end-to-end on temporary directories).
* `tests/par2cmdline.rs` — differential tests against the `par2` binary when present: sets
  created here verify and repair with `par2`; sets created by `par2 create` are verified and
  repaired here (including 250 missing of 1000 blocks) and then re-verified by `par2`.
* `cargo clippy --all-targets -- -D warnings` is clean.

### Platform coverage

| Path | Verified |
|---|---|
| AArch64 NEON, `crc32x` | natively (Apple M-series) |
| x86_64 SSSE3 kernel, `pclmulqdq` CRC | cross-built and executed under QEMU user emulation (99 tests pass) |
| x86_64 AVX2 / AVX-512BW kernels | compiled, not executed (emulator lacks AVX); `Kernel::detect()` self-tests every kernel against the scalar reference at startup and falls back on mismatch |

## API notes and deviations from the written specifications

* Root re-exports follow the `gf2` signatures: `crc32_zeros(len)`, `crc32_combine(crc1, crc2, len2: usize)`.
  The register-level variants with other signatures stay under `crc::` (`crc::crc32_zeros(crc, n)`,
  `crc::crc32_combine(a, b, len_b: u64)`).
* File ids sort as little-endian 128-bit integers everywhere (`libpar2` order); `Inventory.files`,
  `SetVerifier` and `StreamingSliceAssembler` number slices in that order, matching `create`.
* `Inventory.sealed` holds `(set_id, file_id)` pairs that have both a `FileDesc` and an IFSC packet
  consistent with the file size (the spec did not define it).
* `LCM(716_800, 768_000)` is `10_752_000` (the specification's example value was arithmetically wrong).
* `repair_selected_slices` still needs as many recovery slices as there are missing slices in the
  set (that is inherent to the code); it only saves the matrix rows and output buffers.
* `inventory` verifies metadata packet MD5s (not recovery data) so a corrupt description is never
  reported as a file; `inspect_par2(data, false)` trusts headers but never trusts the declared
  length of an unknown or MD5-failed packet.
* `RepairOptions::ignore_extensions` (nzbget `ParIgnoreExt`): damage confined to those files does
  not set `repair_needed`; `RepairResult::Repaired.leftovers` lists backups and consumed split
  fragments (deleted under `BackupPolicy::DeleteAfterRepair`, nzbget's `DeleteLeftovers`).
* `PacketSet::file_id_by_name` / `file_id_by_hash16k` and the `*_by_name` entry points of
  `StreamingParSession` resolve ties in `libpar2` order; `renamer::direct_par_name` reproduces
  nzbget's `DirectRenamer::par_name`.
* Indexer requests (Atlas `docs/PARITY_REQUESTS.md`): `Inventory.set_id` (primary set),
  `MainInfo.body_hashes_to_set_id` (`MD5(body) == set_id`, so the file lists are the ones the set id
  was made from), `CreatorInfo.set_id` (`None` from `CreatorInfo::parse`), and
  `gf2::ifsc_interval_crcs` (IFSC slice CRCs on an article grid, to compare with
  `compute_interval_crcs` interval by interval).
* `is_base_par2` ends a name right after `.par2`: the next byte must be the end of the subject,
  whitespace, a quote or a closing bracket (`a.par2.rar` and `a.par2-1` are not par2 files;
  `"a.par2"`, `(a.par2)`, `[a.par2]` are). No allocation per subject.
* `RepairOptions::ignore_extensions` entries containing `*` or `?` are wildcard masks over the whole
  local name (nzbget `ParIgnoreExt=*`; inside a mask `#` is one digit, as in nzbget's `WildMask`),
  matched by `repairer::ignore_name_matches`; every entry is also a case-insensitive suffix, so a
  literal file name works too.
* `packet::load_par2_collection(main_path, opts)` loads an index and its sibling volumes into a
  `PacketSet` without a `Par2Repairer`.
* `docs/PARITY_LIBRARY.md` is the integration brief exchanged with the RustyGet project.

## Notes for nzbget-rs integration

* Source files are exposed in Main-packet / `libpar2` `sourcefilemap` order (ascending 128-bit
  file id).
* `parse_par_filename` returns `-1` for `.volXXX-YYY.par2` names (block count unknown), as the
  Rust port expects; the C++ original returns `atoi` of the number after `-`.
* `BackupPolicy::RenameNumbered` reproduces `libpar2`'s `file.1` behaviour so
  `ParChecker::DeleteLeftovers` semantics carry over.
* `RepairOptions::rename_misnamed` moves complete copies found under other names into place
  (as `libpar2` does); disable it when scanning dupe sources that must stay untouched.
