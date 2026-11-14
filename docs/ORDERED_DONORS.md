# Ordered donor admission

`Par2Repairer::add_extra_file_with_policy` admits an extra file with
`ExtraFileScanPolicy::Full` or `ExtraFileScanPolicy::OrderedPrefix`. The method
returns the number of previously missing source blocks supplied. Replacing an
existing location does not increase that count. It uses the existing observer,
finalization errors, cancellation token, and repair options.

The original `add_extra_file`, directory/split discovery, target verification,
`ScanConfig`, and `ScanReport` retain their contracts. `Full` delegates to the
original method: every matching checksum entry can receive a location, and a
previous location wins. Existing public structs have no new required fields.

## Prefix selection

`OrderedPrefix` admits one source prefix starting at donor offset zero. The
first selected entry must be that source's first block. Every later entry must
be its exact successor. The first absent or unexpected entry stops admission;
previous confirmed prefix entries can still be used. It never slides to a later
match or starts another source prefix in trailing bytes.

Equal CRC/MD5 candidates follow recoverable Main order and ascending block
order. Selection follows modern Parchive's suggested-terminal, nonterminal,
preferred-source, already-located, and complete-source branches. It chooses one
entry rather than every equal entry. An admitted entry replaces its selected
location, unlike full scanning. These decisions include earlier pending entries
and prior admitted donors. Donors are processed in caller-plan order.

A short final block uses its actual bytes followed by virtual zero padding.
Every actual payload byte must exist. This guard is stricter than the reference
terminal shortcut. A short terminal can match before donor EOF, but trailing
bytes prevent complete-file identity. Complete identity also requires the exact
file length and both full-file and 16 KiB descriptor MD5 hashes.

An early partial prefix has no complete hashes or identity. It launches no
further tail reads or background hashing after the decisive mismatch; existing
bounded read-ahead can already contain later bytes. Required checksum bytes
feed the existing fused hash window, including short terminal bytes. Complete
identity and eligible absent-IFSC fallback require successful full hashing.

## Metadata and state

A partial IFSC result suppresses whole-file fallback, including a first mismatch
with zero accepted entries. With no IFSC entries, or an empty no-match donor,
eligible fallback selects the first not-complete absent-IFSC source in Main order
whose size and both hashes match. It selects one identity rather than all equal
files. An empty identity supplies zero blocks. A donor whose length cannot match
any eligible fallback source needs no hash reads.

Locations and identities are staged until required reads succeed and cancellation
is checked. Failure leaves prior locations and admission bookkeeping intact, so
the failed operation can retry. Successfully admitted paths are idempotent across
policies for that repairer instance, even if they supplied zero blocks. A caller
must choose its policy before admitting a path; a second call does not upgrade
an already admitted prefix to a full scan.

The policy checks declared source geometry before allocation and admits at most
32768 source blocks. Pending entry/state capacities are charged to the existing
verification phase budget before choosing clamped scan windows. It retains the
64 KiB through 256 KiB window bounds and does not increase resource limits.
Existing packet/checksum metadata, names, allocator overhead, and other phases
are outside this buffer accounting. This is not a process RSS bound or an
arbitrary-I/O cancellation deadline.

Donor admission never moves, deletes, or overwrites paths. A later repair uses
the existing `rename_misnamed` and backup policies; disabling donor movement
still permits parity reconstruction. Reference qualification covers ordered
prefixes, shifted full-scan controls, missing sources, damaged named targets,
restored bytes, donor movement, and numbered backups. It does not claim identical
outcomes for every Turbo metadata/hash path or qualify source immutability,
transactional publication, profile flags, or archive preparation.
