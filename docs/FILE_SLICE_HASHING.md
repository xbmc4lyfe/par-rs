# Fused supplied-byte file and slice hashing

`FileSliceHasher` is exported from `hasher` and the crate root. It advances whole
CRC-32, MD5, and prefix MD5 while emitting PAR2 slice checksums from the same
caller-supplied byte stream. It performs no filesystem I/O and stores no input
or checksum collection. Existing hashing and creator APIs remain unchanged.

Construct it with a positive slice size divisible by four. Feed ordered chunks
with `update(bytes, cancel, emit)`, then consume it with `finish(cancel, emit)`.
Use the same callback/state across chunks. The callback receives a zero-based
slice index and `packet::SliceChecksum`; it owns record allocation and admission.
The helper has no Default, Clone, or resume interface.

Full slices emit during update. Only a nonempty incomplete tail receives virtual
zero padding at finish. Empty input emits no slice; an exact boundary emits no
extra slice. FileHashes contain only actual bytes, including the prefix hash of
the first min(length,16384) bytes. Padding never contributes to whole-file digests.

Each processing window is at most 64 KiB; zero-padding windows use fixed 4 KiB
scratch. Cancellation is checked for empty updates, between windows, around
callbacks, and before final success. Large geometry is caller-chosen work; bounded
polling does not imply a fixed CPU cost, callback deadline, or process memory cap.

Invalid geometry returns InvalidInput. Checked counter failure returns InvalidData;
observed cancellation returns Interrupted. Callback errors return unchanged even
when the callback also sets cancellation. Failure poisons the instance: subsequent
update/finish fails with Other before further digest work or callbacks. Emitted
records remain provisional caller state and are not rolled back. A failed finish
returns no FileHashes; cancellation set by the last callback prevents success.

A caller can read a held file into a bounded buffer and supply each byte once.
Independent oracle reads or later validation still cost I/O; this component result
is not an end-to-end performance claim. Callers own EOF, read allowances, identities,
writer exclusion, and catalog validation. This helper does not establish immutable
sources, source binding, strict packet completion, preparation, publication, or
durability. Those remain separate gates for the queued private preparation path.
