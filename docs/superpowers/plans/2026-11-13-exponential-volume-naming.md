# Exponential volume naming implementation plan

> **For agentic workers:** use superpowers:executing-plans inline. Root owns the
> fresh independent review and publication. No helper agents.

**Goal:** add explicit reference-compatible exponential volume filename spelling
while preserving native names and existing complete options literals.

**Architecture:** existing creators delegate Native to additive entrypoints.
Both entrypoints use the same policy-aware width seam with the checked layout.
Only explicit Par2cmdlineExponential plus Exponential changes filename widths.

**Tech Stack:** existing Rust creators, packet parser, retained pinned references.

**Spec:** root's `phase3-par2-exponential-naming-source-brief.md` and accepted
proposal SHA `f6992100da3ce2d19f987ce915014320c097569b69196a5dac42d4869b7503e7`.
Base: `110d0f476fa0d4508efd062582eb5b066a055a55`.

## Global constraints

No public options fields, VolumeScheme variants, dependencies, resource limits,
layout/packet/RS/geometry/scanner/repairer/shutdown or caller changes. Native
outputs and complete CreateOptions/SetOptions literals remain valid. Preserve
cancel/progress/I/O behavior and the caller's separate staging/publication scope.
No source-binding, durability, rollback, or universal compatibility claim.

## Files and interfaces

- `src/create.rs`: `VolumeNaming::{Native, Par2cmdlineExponential}`, deriving
  Clone/Copy/Debug/PartialEq/Eq. Existing create/build_set delegate Native.
  Add create_with_volume_naming(sources,out_dir,base,opts,naming,cancel,progress)
  and build_set_with_volume_naming(base,sources,opts,naming), with incumbent types.
  Shared creation_volume_widths gains naming; explicit exponential uses independent
  decimal digits of admitted exclusive end and largest layout count, minimum1.
- `src/lib.rs`: export enum and both functions.
- `tests/volume_naming.rs`: public runtime RED/GREEN, both creators, native byte
  parity, complete literals, boundaries, other layouts, index-only/invalid cases,
  packet/report equality, and delegated cancellation/progress/I/O controls.
- `tests/par2cmdline.rs`: one narrow retained-reference naming comparison.
- Concise feature documentation and this plan. Follow GPL-2.0-or-later convention.

## Review focus

Sentinel exponent width at decimal boundaries; count width independently crossing
10/100; native complete-literal/default preservation; identical bytes and actual
report paths despite renamed volumes; unchanged pre-I/O rejection and error/cancel
behavior. Cover these in the single bounded naming task below.

## Task: explicit naming without allocation changes

- [ ] Run focused native legacy-name baseline at exact base. Add an actual R10
  public test through existing APIs and observe old padded count mismatch RED.
  Retain source, logs, deterministic fixtures, and their hashes before product edits.
- [ ] Add minimal enum/wrappers/shared-width policy and crate-root exports.
  Switch the same regression to explicit compatibility and observe runtime GREEN.
- [ ] Qualify both new APIs: native versus incumbent bytes/names; compatibility
  widths for R9/10/99/100, first7+R3, first90/91+R9, first17+R7,
  first65525+R10, and R17/25/227 max-count transitions. Keep complete literals.
- [ ] Assert actual report names, index equality, corresponding complete volume
  bytes, packet MD5/set IDs/critical packets/exponent counts/payloads. Qualify both
  policies for all other schemes, empty/index-only/zero recovery, and invalid
  geometry before I/O. Keep inherited tests intact and delegated error controls.
- [ ] With both retained pinned binaries, run only tiny necessary boundary creates
  to settle source-derived expectations; retain exact argv/cwd/status/output and
  tool/fixture hashes. Use existing cross-repair controls where needed.
- [ ] Run repository just ci with pinned Vale3.26, diff check, and local commit.
  Return exact clean HEAD/tree/sole parent, scope/coverage/command receipts and
  immutable evidence for root fresh review. No push, PR, or merge here.
