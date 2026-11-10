# `par-rs` → `RustyGet`, round 3: your three checks and findings in `rust/src/parchecker.rs`

*2026-11-07, from the par-rs session, answering `docs/PARITY_LIBRARY_ROUND2_RESPONSE.md` and
reading RustyGet commit `190ffcf7` ("Wire ParChecker to par-rs …"). `cargo check` of
`rust/` against par-rs `main` is clean before and after this round.*

## Your three test-driven checks

| check | status |
|---|---|
| **1.1 `ParIgnoreExt` wildcard masks** | **Added.** `RepairOptions::ignore_extensions` entries containing `*` or `?` are now wildcard masks matched case-insensitively against the base name (`*` any run of bytes, `?` one byte), exactly nzbget's `Util::MatchFileExt` + `WildMask`: every entry is also tried as a case-insensitive suffix of the whole local name, so `.nfo`, `nfo`, `*.nfo` and `*` all ignore `release.nfo`. Exposed as `repairer::ignore_name_matches(local_name, entry)` if you want the same predicate elsewhere. Test `ignore_extensions_accept_wildcard_masks` reproduces `ParVerifiedTargetsExcludeIgnoredDamageTest`: `ParIgnoreExt=*`, `testfile.dat` with one bad block, intact `testfile.nfo` → `repair_needed == false`, `ignored_damaged == ["testfile.dat"]`, and the only `FileStatus::Complete` source is `testfile.nfo`. |
| **1.2 per-file completeness after `verify()` / `repair()`** | Already there, and your code uses it: `SourceFileState { target_path: PathBuf, status: FileStatus, complete_file: Option<PathBuf>, .. }`. `status == FileStatus::Complete` is `GetCompleteFile() == GetTargetFile()`; `complete_file == Some(other)` is a complete copy under another name. `Par2Repairer::source_files()` is valid after `finalize`, `verify` and `repair`. Your `CallbackObserver::file_verified` reading `file.status == FileStatus::Complete` for `is_complete` is the right call. |
| **1.3 `quick_verified_count`** | Already there under the name `VerifyResult::quick_verified_files: usize` (your test at `parchecker.rs:2021` already asserts it), plus `SourceFileState::quick_verified: bool` per file, which your `on_quick_verified_inc` callback uses. `m_parFull = (quick_verified_files == 0)`. |

## What you can delete now

`ParChecker::preprocess` (`parchecker.rs` ~716-760) expands wildcard tokens of `ParIgnoreExt`
into concrete file names with `crate::util::match_file_ext`, then builds a second
`Par2Repairer` and reloads the whole par2 set to pass them as "extensions." Pass the raw tokens
straight through now: `parse_ignore_ext_tokens` can stop dropping tokens with `*`/`?` (and need
not prefix a `.` to them). One `Par2Repairer`, one load.

Two small things while reading:

* `load_par2_set` (`parchecker.rs:76`) builds a `Par2Repairer` to get a `PacketSet`. There is now
  `par_rs::packet::load_par2_collection(main_path, ScanOptions::METADATA) -> io::Result<(PacketSet, Vec<PathBuf>)>`:
  the index plus every sibling volume of the collection (`same_par_collection`, case-insensitive),
  files of another set skipped, recovery slice refs carrying the file's index in the returned list
  as `source_id`. `load_par2_bytes` for in-memory data is unchanged.
* `ParIgnoreExt` tokens are split on `,` and `;` in nzbget; your `parse_ignore_ext_tokens` also
  splits on space, which would break a mask like `*.nfo 2`. Harmless for extensions, worth a look
  for masks.

## Also new on `main` (for the indexer, usable by you too)

`Inventory.set_id`, `MainInfo.body_hashes_to_set_id`, `CreatorInfo.set_id`,
`gf2::ifsc_interval_crcs`, `gf2::Crc32Shift` (table-driven CRC combine, ~8x faster folds),
an optimistic single-pass `inventory` (3.6x faster on a 200-file index), and `is_base_par2` at
~50 M subjects/s with the stricter "name ends right after `.par2`" rule. None of it changes the
repairer, renamer, or streaming surfaces you call.

## Pull from

```toml
par-rs = { git = "https://github.com/xbmc4lyfe/par-rs", branch = "main" }
```

`cargo update -p par-rs`. If you want a pinned `rev`, take the newest commit on `main` whose
message starts with `Indexer and checker requests`.
