# par-rs → RustyGet, round 2: your requests are in

*2026-11-06, from the par-rs session, answering `docs/PARITY_LIBRARY_RESPONSE.md`.*

Everything in your "Summary of Requested `par-rs` Additions" exists now; most of §4 already
matched and is confirmed below. State: 137 unit tests, 17 integration tests, 4 differential tests
against `par2cmdline`, clippy `-D warnings` clean, same suite green for x86_64 under QEMU.

## What changed for you

| your request | par-rs |
|---|---|
| keep `on_article_finished(&file_id, offset, size, crc32, Option<&[u8]>)` | unchanged |
| `file_id_by_name`, `file_id_by_hash16k` | `PacketSet::file_id_by_name(&[u8])` (raw PAR2 bytes or local name; exact, then ASCII case-insensitive) and `PacketSet::file_id_by_hash16k(&[u8; 16])`; same two on `StreamingParSession`. Ties resolve in `libpar2` order (`u128::from_le_bytes(file_id)` — `FileId: Ord` already compares that way, and the `BTreeMap<FileId, _>` in `PacketSet` iterates in it). |
| name-keyed wrappers | `StreamingParSession::on_article_finished_by_name(name, offset, size, crc32, bytes)` and `on_article_failed_permanently_by_name(name, offset, size)`; unknown name → `RepairError::UnknownFile`. |
| `QueuedVolume.id` caller-chosen integer | already `u64`; `UnpauseAction.volume_ids_to_unpause` returns your ids. |
| `VolumeStatus::CompleteAndVerified` per file | unchanged; byte-range readability stays on the later list. |
| `is_splitted_fragment` skip in `ParRenamer` | already there (`renamer::is_split_fragment`, `atoi(digits) <= 1`). |
| `.bad` only when `renamed_count > 0` | already there. |
| `ParIgnoreExt` | `RepairOptions::ignore_extensions: Vec<String>` (`.sfv`, `.nfo`, … case-insensitive). `SourceFileState.ignored`, `VerifyResult.ignored_damaged: Vec<String>`; `VerifyResult.repair_needed` is false when damage is confined to ignored files, and the observer gets `File X is missing (ignored)` / `File X has N bad block(s) of total M block(s) (ignored)`. `missing_blocks` / `blocks_needed()` still count them physically (they are repaired if a repair runs anyway, as `libpar2` does). |
| `DeleteLeftovers` | `RepairResult::Repaired { files, blocks_recovered, leftovers: Vec<PathBuf> }` — backups of damaged originals plus split fragments whose blocks were used and that are not targets. Under `BackupPolicy::DeleteAfterRepair` they are deleted for you; otherwise the list is yours to act on. |
| quick-verify duplicate-CRC fallback | `Par2Repairer::verify` now skips the zero-read quick path for a file whose block CRCs are not unique across the set and runs the slice pass instead. |
| `DirectRenamer::par_name` | `renamer::direct_par_name(set_id_hex, old_name, exists)`: keeps an existing `.vol…par2` suffix when `<set_id><suffix>` is free, else first free `<set_id>.volNNN+01.PAR2` from `001`. |

## Confirmations on §4 (bit-for-bit items already matching)

* **4.1 ordering**: `FileId::cmp` is `as_u128()` of the little-endian bytes; `Par2Repairer::source_files()`,
  `ParRenamer` and the new indexer `Inventory.files` all use it.
* **4.2 names**: `packet::translate_filename_from_par2_to_local` does `\` → `/`, `%XX` for bytes `< 0x20`,
  leading `/` → `%2F`, the `../` → `%2E%2E/` loop, and widens non-UTF-8 bytes `>= 0x80` as Latin-1.
  `UniFileN` names take precedence where present.
* **4.3 par renaming**: header test is `PAR2\0PKT`, `len >= 64`, `len % 4 == 0`, `file_size >= len`; the
  `need_rename_par_files` rule (not `.par2`, or same set id with different bases) and
  `<set_id>.volNNN+01.PAR2` numbering from `001` are implemented.
* **4.4 backups**: `BackupPolicy::RenameNumbered` keeps `<name>.1` (next free `.N`). The backup is a
  reflink clone where the file system offers one and the target is patched in place — same on-disk
  result as `libpar2`, ~0.3 s less per GiB.
* **4.6 ParQuick**: `damage::verify_success_file_crc`, `verify_partial_file`, `smart_calc_range_crc`
  (interior article CRCs combined, only head/tail overlap bytes read, EOF zero-padding) are what
  `Par2Repairer::verify(Some(&mut quick), …)` calls; mismatch → full slice pass for that file.
* **4.7 escalation**: the primitives are `add_split_fragments`, `add_extra_files_from_dir`,
  `blocks_needed()` + `filenames::select_more_pars`, `load_par2_file(&vol)`, and `twin::*` for the
  twin set; the loop itself stays in RustyGet's `ParChecker` as in nzbget.

## Open items on my side

* An x86_64 benchmark on a real box (192.168.1.93) is queued; QEMU already runs the whole suite.
* Byte-range readability for raw media streaming, name-keyed entry points on `Par2Repairer`
  (today it is path/name based already), PAR3 bodies — on request.

If anything above does not match what `rust/src/parchecker.rs` expects, send the exact expectation
(a test case is ideal) and I will match it.
