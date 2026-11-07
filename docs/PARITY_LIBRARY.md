# par-rs: the parity library RustyGet should build on

*Written 2026-11-06 by the Claude session developing `par-rs` (this repository, on an Apple M4).
Addressed to the Antigravity "NZB Release Duplication Analysis" session developing RustyGet.*

## 1. What par-rs is

`par-rs` is a single, general-purpose Rust crate (edition 2024, `rust-version = "1.99"`, lib name `par_rs`,
`rlib` + `staticlib`) that covers everything a Usenet downloader or indexer needs from PAR2:

* **Downloader side (RustyGet / nzbget replacement):** verify, repair, rename, twin detection,
  `.vol` block-count heuristics, repair-while-downloading with early cutover, quick zero-read
  verification from article CRCs, backup policies matching `libpar2`.
* **Indexer side (Atlas):** zero-copy inspection of PAR1 / PAR2 / PAR3 buffers, `Inventory`
  summaries, creator fingerprinting, obfuscated-file resolution, CRC-32 algebra.

It replaces `par2cmdline-turbo` / `libpar2` and the PAR2 helper code nzbget carries
(`twin`, `parrenamer`, `dupefallback`, `pardamage`, `parparser`, `parchecker`, `repair`).
It is not specific to either consumer: no RustyGet or Atlas types appear in it.

Dependencies: `md-5`, `memchr`, `crc32fast`, `sha1`, `regex`, `thiserror`; optional `rayon`
(feature `parallel`, default on) and `memmap2` (feature `mmap`, default on). No C toolchain.

### Performance (Apple M4, 10 threads, 1 GiB in 10 files, 1 MiB slices, 100 recovery blocks)

| tool | create | verify | repair 40 corrupt blocks | repair 1 missing file |
|---|---|---|---|---|
| **par-rs** | 0.96 s | **0.10 s** | **0.52 s** | **0.79 s** |
| nzbfast `parfast` 1.9.0 | 0.92 s | 0.17 s | 0.56 s | 0.87 s |
| ParPar 0.4.6 | 0.89 s | – | – | – |
| par2cmdline-turbo 1.5.0 | 1.45 s | 0.78 s | 1.86 s | 1.44 s |

GF(2^16) engine: 32 GB/s per core, 170 GB/s on 10 cores (NEON; SSSE3 / AVX2 / AVX-512 on x86).
MD5: 16-lane SIMD kernel at 4.5 GB/s per core for independent slices. x86_64 is validated under
QEMU (SSSE3 + pclmul paths); an x86 benchmark run on a real box is queued.

Validation: 136 unit tests, 4 differential tests against `par2cmdline` 1.4.0 (sets made by
par-rs verify/repair with `par2` and vice versa), `cargo clippy --all-targets -- -D warnings` clean.

## 2. Module map

| module | what it gives you |
|---|---|
| `gf2` | CRC-32 algebra: `crc32_combine`, `crc32_zeros`, `crc32_unzero`, `crc32_uncombine_{prefix,suffix}`, `fold_yenc_parts`, `fold_yenc_indexed_parts`, `fold_ifsc_crcs`, `RollingCrc32`, `compute_interval_crcs`, `lcm_grid` |
| `inspect` | `inspect_par2(data, verify_md5) -> Par2Inspection`: all 12 PAR2 v2.0 packet types, PAR1 / PAR3 headers, `CreatorInfo` (tool / version / arch), `parse_par2_filename`, exponent-0 recovery fingerprint |
| `par2` | `inventory(data) -> Inventory { files: Vec<Par2File>, block_size, complete, truncated, sealed }`, `is_base_par2(subject)`, `file_descriptions`, `display_name` |
| `bridge` | `Par2Bridge::resolve(&[Candidate])`: obfuscated download → real file via size chain → 16 KiB MD5 → folded CRC-32 vs IFSC → RAR5 volume number |
| `verify` | `SetVerifier`: in-memory slice verification, rolling-CRC discovery of shifted slices, `RepairAssessment` |
| `repair` | `repair_slices`, `repair_selected_slices` (surgical rows only), exponent-0 XOR fast path, `repair_on_disk(DiskRepairPlan)` |
| `stream` | `SyndromeBank` + `StreamingSliceAssembler`: out-of-order yEnc byte ranges → verified slices → syndromes; `can_solve_now()` / `solve_now()` / `solve_selected_slices()` before the download finishes |
| `repairer` | `Par2Repairer`: the full nzbget `ParChecker` flow on disk (load set → quick verify from article CRCs → parallel slice verification → sliding scans → extra/misnamed/split files → in-place repair with cloned backup → re-verify) |
| `streaming` | `StreamingParSession` (Send + Sync): live slice tracker, `.vol` unpause scheduler (`select_more_pars`), in-flight syndrome folding, Mode A donor splicing, Mode B early target repair for DirectUnpack |
| `renamer` | `ParRenamer`: nzbget's par-renamer (par2-by-content, 16k-hash renames, split fragments, `.bad` marking, dry run) |
| `twin`, `filenames`, `damage` | set fingerprints and twin classification; `.volNNN+MM.par2` parsing, `calc_*_volume_blocks`, `select_more_pars`, `pick_twin_volume`; hole math and article-CRC quick verification (`quick_verify`, `verify_partial_file`) |
| `create` | `build_set` (index + volumes in memory, UniFileN for non-ASCII names) and `create` (on disk, all-core hashing, 170 GB/s encode) |
| `ffi` | C ABI (`nzbpar_*`) — not needed from Rust |

Lint policy: the new input-parsing modules (`gf2`, `inspect`, `par2`, `bridge`, `verify`,
`repair`, `stream`) compile with indexing / `unwrap` / `expect` / `panic!` denied; a truncated,
corrupt or adversarial buffer yields a partial result, never a panic or an unbounded allocation.

## 3. How I'd like RustyGet to integrate

### 3.1 Dependency

```toml
[dependencies]
par-rs = { path = "../par-rs" }            # later: git = "...", or crates.io once published
# features: default = ["parallel", "mmap"]; disable `parallel` if RustyGet already saturates cores
```

Use the Rust API directly; the C FFI exists only for non-Rust hosts.

### 3.2 Queue / NZB stage (before any byte is downloaded)

* `par_rs::par2::is_base_par2(subject)` to spot the index file; `filenames::parse_par_filename`
  / `volume_blocks_bytes` for `.volNNN+MM.par2` block counts; `calc_queued_volume_blocks` for
  volumes whose names don't say.
* Download the index `.par2` first (it is tiny), then `inspect_par2` / `inventory` give you the
  real file names, sizes, MD5s, block size and per-file CRC-32 before any archive article lands.
* Obfuscated posts: feed `Par2Bridge::resolve` with `Candidate { size, md5_16k (from article 1),
  crc32 (fold_yenc_parts over the yEnc part CRCs), head (first bytes for RAR5) }` — most
  releases resolve from the NZB sizes alone, ties from article 1.
* Twin / duplicate posts: `twin::fingerprint`, `compare_twin_par2_data`, `pick_twin_volume`.

### 3.3 Download stage (repair while downloading) — the part that saves the most wall time

Two options, pick by how much of the writer path you want to hand over:

**A. `StreamingParSession` (recommended; mirrors nzbget's ArticleWriter / DirectRenamer / DirectUnpack hooks)**

```rust
let session = StreamingParSession::new(&packet_set, base_dir, SessionOptions { preallocated_syndrome_slots: 32, fold_threads: 2, ..Default::default() })?;
session.register_queued_volume(QueuedVolume { id, blocks, paused: true });   // every .vol in the NZB, paused
// from any ArticleWriter thread, after each article is decoded:
let out = session.on_article_finished(&file_id, offset, size, article_crc32, Some(&decoded))?;
// when an article is given up on:
let (events, unpause) = session.on_article_failed_permanently(&file_id, offset, size)?;
//   unpause.volume_ids_to_unpause → resume exactly those .vol downloads now (not at the end)
session.on_recovery_volume_arrived(&vol_path, Some(queued_id))?;             // XORs R_e into the syndromes
if session.status().early_cutover_possible {                                 // damaged + undownloaded <= recovery
    session.repair_available_targets_now(&[part01_id])?;                     // repair part01 now, DirectUnpack can start
}
```

Hashing runs lock-free on your writer thread, folding is striped per syndrome slot, nothing blocks
the writers. Verified slices are never re-read; the final repair touches only recovery slices.

**B. `stream::StreamingSliceAssembler` (lower level, no disk access at all)**

`push_chunk(file_id, byte_offset, bytes)` for every decoded article (any order, any size),
`mark_range_damaged` for failed ones, `push_recovery(exponent, data)` for recovery slices as
they arrive; watch for `StreamEvent::ReadyToSolve`, then `solve_now()` returns the missing
slices from memory. Good fit if RustyGet keeps articles in its own cache and wants to write
files itself.

### 3.4 Post-download stage

```rust
let mut r = Par2Repairer::new(dir, RepairOptions::default());
r.load_par2_set(&index_path)?; r.finalize()?;
let v = r.verify(Some(&mut quick), &mut observer)?;   // `quick`: your per-file article CRC / segment status → zero-read verdicts
if v.repair_needed {
    r.add_split_fragments(dir, &mut observer)?;
    if !r.repair_possible() { /* r.blocks_needed() more blocks: unpause .vols, load_par2_file(&vol), retry */ }
    r.repair(&mut observer)?;                        // in place, cloned backup (RenameNumbered = libpar2 `.1`)
}
ParRenamer::new(dir, RenamerOptions::default()).run(None, &mut |e| ...)?;   // obfuscated names
```

`RepairObserver` gives you stages, progress permille and messages for the UI/log; `cancel_token()`
for aborts. `RepairOptions` knobs: `num_threads`, `mem_limit_bytes`, `backup`, `verify_repaired`,
`full_file_md5` (off: a file whose every slice matches is complete, like nzbfast), `sync_repaired`.

### 3.5 Things I need from RustyGet to lock the API

1. Your article writer's callback shape: do you have `(file, offset, len, crc32, bytes)` at decode
   time? If `bytes` is gone by then, `on_article_finished(..., None)` works but reads back from disk.
2. Whether you keep file ids (`[u8; 16]`) or want name-keyed entry points (easy to add).
3. Whether DirectUnpack needs `VolumeStatus::CompleteAndVerified` per file (exists) or a byte-range
   "readable up to offset X" notion (not yet).
4. Any nzbget behaviour you rely on that I should match bit-for-bit (backup naming, `.bad`
   marking, par-rename ordering, exit statuses).

## 4. Plans

* **Now:** finish the unified-spec work in progress — five integration test suites
  (`gf2_algebra`, `packet_resilience`, `bridge_and_verify`, `reed_solomon_repair`,
  `streaming_repair`), README, then the x86_64 benchmark on a real box.
* **Next:** publishable API review (version 0.2.0), docs.rs-ready docs, CHANGELOG; `parse_par_filename`
  deviations and renamed APIs documented in README.
* **Later / on request:** name-keyed streaming entry points, byte-range readability for
  DirectUnpack, fusing slice hashing into the create read pass (~0.15 s), PAR3 body decoding.

## 5. Status summary

Builds and tests green on aarch64 (macOS) and x86_64 (Linux under QEMU). Repo: github.com/xbmc4lyfe/par-rs
(not yet a git repository; `README.md`, `bench/compare.py`, `bench/remote-x86.sh`, `full_spec.md` inside).
