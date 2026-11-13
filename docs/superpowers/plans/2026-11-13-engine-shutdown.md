# Reader-queue shutdown implementation plan

Execute inline with the executing-plans and test-driven-development skills.
Spec: controller-approved `phase3-par2-shutdown-fix-brief.md`.

Goal: unblock queued producers before scoped joins on early consumer exit.
Keep the public API, defaults, queue capacities, math, and creator I/O unchanged.

Scope: `src/reed_solomon.rs` receiver ownership and `tests/engine_shutdown.rs`.
Review focus: full queues, multiple readers, original error propagation,
resource retirement, and unchanged ordinary output. Arbitrary blocking readers
or callbacks remain outside a queue-shutdown guarantee.

- [x] Establish fresh ab508 baseline and add public child regressions with
  deterministic producer/consumer gates and finite owned-child containment.
- [x] Observe both cancellation and multi-reader I/O-error timeout REDs.
  Normal drain, pre-cancel, and single-reader error controls must finish.
- [x] Make the minimal receiver-lifetime correction, including early unwind.
- [x] Observe GREEN with original errors, no active read calls on return,
  failed-chunk output suppression, and literal exponent-zero output bytes.
- [x] Run exact final just-ci with pinned Vale3.26 and both reference suites.
- [ ] Commit the frozen tree and report commands, counts, hashes, and limits.
- [ ] Controller obtains one scoped independent review; fixes stay with the
  same implementer. Publishing and merge require separate serial-slot handoff.

Preserve original main and historical geometry/Limited worktrees and evidence.
No helper agents, source-binding API, process RSS promise, or publication change.
