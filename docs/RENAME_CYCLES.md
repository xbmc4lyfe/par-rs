# Complete-copy movement during repair

With the existing `rename_misnamed: true` option, repair can restore a permutation
of complete source files by moving their verified copies. A target rotation now
updates every complete-copy reference to that disk file, together with the disk
registry. For a swap, the second move can use the first target's backup directly.

A backup leaves the returned `leftovers` list only after a successful rename of
that exact backup into a repaired target. Repair does not delete a backup because
its bytes match another source. Preexisting backups and genuine damaged originals
keep the existing numbered, `.bak`, or delete-after-repair behavior. With
`rename_misnamed: false`, copying retains the existing backup behavior.

Shared block sources remain available to their other consumers. A completed target
also stays in place when equal empty sources have no blocks to express sharing.
The private movement indexes and additional complete-copy path capacity are
reserved fallibly under the existing phase budget before filesystem changes.
Reverse references update only the affected disk file's consumers; the shared
block check uses an index built once. This state drops before copy and recovery
buffers are allocated. Existing metadata and allocator overhead remain outside
the documented buffer limit; this does not establish a process-wide memory cap.

Cancellation and I/O errors can leave a partially repaired directory. Successful
moves update the in-memory references before their observer notification. A failed
move leaves its source backup available and does not mark it consumed. Repair
does not promise rollback, durability, or protection against concurrent filesystem
changes.
