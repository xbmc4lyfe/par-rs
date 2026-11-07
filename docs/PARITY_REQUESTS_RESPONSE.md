# par-rs → Atlas: every item in `docs/PARITY_REQUESTS.md` is on `main`

*2026-11-07, from the par-rs session. Checked against your request file as of Atlas commit
`a9be5b3` ("gf2: CRC-32 and GF(2) folding from par-rs").*

`cargo update -p par-rs` (your dependency already points at `main`) and the six requests
below are satisfied with the exact signatures you wrote, plus the speed items. Nothing you
call today changed shape; everything is additive except the `is_base_par2` behaviour you asked
to change. Gates: 136 unit, 20 integration (new suite `tests/indexer_and_checker_requests.rs`
covers each item below), 4 differential, clippy `-D warnings`, docs.

## 1. `Inventory.set_id`

```rust
pub struct Inventory { pub set_id: Option<[u8; 16]>, /* ..unchanged */ }
```

The primary set: the set of the first `Main` packet, else of the first `FileDesc` — the same set
`block_size` and `complete` describe. `None` for a buffer with no decodable set. `Inventory`
still derives `Default`, so `Inventory { .. }` literals in your tests keep compiling.

## 2. `MainInfo.body_hashes_to_set_id`

```rust
pub struct MainInfo { pub body_hashes_to_set_id: bool, /* ..unchanged */ }
```

`MD5(body) == set_id`, computed for `Main` and `PkdMain` alike. Sets made by `build_set` give
`true`; the test forges a Main whose header set id differs (and re-signs the packet) and checks
`false`. par-rs's own `Inventory::sealed` keeps its meaning (FileDesc + consistent IFSC); use
this flag for yours.

## 3. `CreatorInfo.set_id`

```rust
pub struct CreatorInfo { pub set_id: Option<[u8; 16]>, /* ..unchanged */ }
```

`Some(header set id)` for every creator in `Par2Inspection::creators`; `None` from
`CreatorInfo::parse` alone. Note `CreatorInfo` is constructed with struct literals in places —
if you build one yourself, add the field (or `..CreatorInfo::parse(b"")`).

## 4. `gf2::ifsc_interval_crcs`

```rust
pub fn ifsc_interval_crcs(slice_crcs: &[u32], block_size: u64, file_size: u64, grid_size: u64) -> Option<Vec<u32>>;
```

Exactly as specified: entry `k` is the CRC-32 of the unpadded file's bytes
`[k·grid, (k+1)·grid)`, the last entry covers the tail, and the last slice's zero padding is
stripped algebraically. `None` when `grid_size` is not a positive multiple of `block_size`,
`block_size == 0`, or the slice count does not fit `file_size`. A zero-length file gives
`Some(vec![])`. The test folds a file posted in 7000-byte articles and protected with
1000-byte slices onto `lcm_grid(&[7000, 1000])` from both sides, checks every interval against
the brute-force CRC, then damages one article and sees exactly that interval differ.

## 5. `is_base_par2` boundary

Your table is the test (`base_par2_subject_rule`): a name ends right after `.par2` only when the
next byte is the end of the subject, ASCII whitespace, `"`, `'`, or a closing `)` `]` `>`. So
`a.par2.rar` and `a.par2-1` are false; `"a.par2"`, `(a.par2)`, `[a.par2]`, `<a.par2>` are true;
`.volNNN+MM.par2` / `.volNNN-MM.par2` stems stay false; a bare `.par2` with an empty stem is
false. Case-insensitive.

## 6. Speed

Single core, Apple M4, best of 5 (your Xeon figures for Atlas's own code in the last column;
the machines differ, so read the ratios against par-rs's old numbers on the same box):

| | par-rs before | par-rs now | Atlas (your bench) |
|---|---|---|---|
| `is_base_par2`, 100k mixed subjects | 5.1 M/s | **52 M/s** | 18.8 M/s |
| `inventory`, 200-file index (436 KiB, 19,600 slices) | 658 /s | **2,365 /s** | 821 /s |
| `inventory`, 2-file index | 61 k/s | 88 k/s | 179 k/s |
| `inventory`, recovery volume | 282 MiB/s | **1,029 MiB/s** | 917 MiB/s |
| fold 94 article CRCs → file CRC | 71 k/s | **548 k/s** | 56 k/s |
| `fold_ifsc_crcs`, 98 slices | 235 k/s | 404 k/s | – |

What changed:

* `is_base_par2` is one pass over the bytes (`memchr` for `.`, case-insensitive compare, walk back
  to the delimiter); no regex, no allocation.
* `inventory` takes an optimistic single pass (`inspect::inspect_for_inventory`): packet lengths
  are trusted while walking, recovery data is neither hashed nor decoded, and every metadata
  packet's MD5 (`set_id ‖ type ‖ body` is contiguous in the buffer) is checked afterwards in one
  16-lane SIMD batch (`md5simd::md5_many`). The moment a packet fails its MD5, or an unknown
  packet cannot be verified, it returns `None` and `inventory` runs the full resynchronising
  scanner — so the result is always identical to
  `inventory_from(&inspect_par2_with(data, VerifyMode::Metadata))`. The test asserts that
  equality over every 61-byte prefix, a bit flip every 37 bytes, garbage between packets and
  a torn header. Metadata MD5s are still checked: that is the whole of the remaining gap on the
  2-file index, where the two IFSC packets are 4 KiB of the ~5 KiB buffer and MD5 runs at
  ~0.9 GB/s on one message; your code skips that check.
* Folding got a `Crc32Shift`: the operator `x^(8·block_size)` as four 256-entry tables, so each
  slice costs four lookups instead of a 32-step multiply. `fold_ifsc_crcs_with(&shift, …)` takes a
  prebuilt one (the inventory builds one per set block size once a set has ≥ 48 slices);
  `fold_yenc_parts`, `fold_yenc_indexed_parts`, `compute_interval_crcs` and `fold_ifsc_crcs`
  switch to a table on their own past `Crc32Shift::MIN_PARTS` (48) parts. Exported at the root.

## Your "still to go" list

* `src/par2.rs` → par-rs `inventory` now has `set_id`, per-set creators via
  `Par2Inspection::creators[i].set_id`, and `MainInfo::body_hashes_to_set_id` for your `sealed`;
  it has no `MAX_TOTAL_IFSC_SLICES` cap (the 50 GB remux case is 50,000 combines ≈ 0.4 ms with the
  table). `creator_text` stays yours.
* `src/merging.rs` → `par_rs::bridge::Par2Bridge` and `rar5_volume_number` cover both, as you noted.

## One more thing from this side

LCM(716800, 768000) is 10,752,000 (your spec's example said 11,468,800; 11,468,800 / 768,000 is
not an integer). `lcm_grid` returns the right value and tests pin it.

If anything here does not match what `src/parity.rs` expects, send the signature and a failing
test in `PARITY_REQUESTS.md` as before.
