# Explicit donor data-read allowances

`Par2Repairer::add_extra_file_with_read_budget` adds a resource policy to explicit
Full or OrderedPrefix donor admission. Existing `add_extra_file`,
`add_extra_file_with_policy`, RepairOptions, and RepairError remain unchanged.

Create `DonorReadBudget::new(total_limit_bytes)` and pass the same mutable ledger
across donors and retries to enforce a shared allowance. The method also accepts
`per_call_limit_bytes: Option<u64>`; None removes only the per-call ceiling.
There is no engine default numeric allowance. Subtract saved `charged_bytes()`
from its later value to obtain a call's charge, including failed calls.

Each engine-issued primitive data-read attempt charges its entire requested
buffer length before invocation, once to both intersecting counters. An exposed
short read or Interrupted result requires a newly checked and charged attempt.
A request8 returning3, request5 returning Interrupted, then request5 returning5
charges18. Failed, EOF, short, and cancelled work never refunds spent allowance.
The counters measure conservative requested bytes, rather than returned bytes, or
physical device traffic. Standard-library clamping does not reduce a charge.

On Unix the primitive is one FileExt::read_at invocation; the engine's own
exact-fill loop handles exposed short and Interrupted results. Other platforms
use a locked seek/read equivalent. Kernel-internal retries, device traffic,
metadata/open/seek work, CPU, memory, and wall time are outside this allowance.

The entire next request must fit both remaining limits. Aggregate refusal wins
when both refuse; neither counter advances and no data read occurs. Limit errors
identify scope, limit, spent request bytes, and the refused next request. Arithmetic
overflow is a separate typed error with its original request length.

Existing prefetch requests remain: a small cap can refuse a short logical prefix
because a larger buffered read does not fit. The source's observed length stays
unchanged. A cap is never treated as EOF; no extra lookahead byte is read. All Full
windows and OrderedPrefix required/identity/fallback reads use the same ledger.
Virtual zero padding costs no source bytes. A partial ordered prefix does not
trigger a trailing hash-completion pass, but any initial read-ahead is charged.

The first terminal source fault is retained even when a scanner helper discards
its temporary I/O error. Required-read/cap/cancellation failures leave this donor's
locations, registry, counts, identity/status, and scanned marker unchanged.
Earlier admitted donors and spent allowance remain. Checkpoints use the current
repairer token; cancellation arriving after the final precommit check remains a
cooperative race. No callback/panic/OOM/process-termination rollback is promised.

This meters only explicit calls to the new method. Collection loading, initial
verify, implicit discovery, later repair reads, backups, and output are separate.
A metadata-length allowance is not this I/O allowance. Admission preserves donor
bytes and adds no moves or cleanup. Matching observed lengths and hashes do not
provide source binding or namespace immutability. Blocking file operations remain
cooperative; this API adds no process-wide memory bound or I/O deadline.
