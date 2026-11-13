# Checked source geometry implementation plan

Execute inline using the executing-plans and test-driven-development skills.

Goal: implement the approved pure numeric geometry and local loss queries.
Spec: `/Users/allen/git.xbmc4lyfe/PAR_RS_GEOMETRY_IMPLEMENTATION_BRIEF.md`.

Architecture: a public geometry module owns one vector sorted by opaque key.
Aligned size selection scans borrowed inputs. Queries sort and merge a single
local-range vector. Existing creators and signed damage APIs retain their behavior.

Constraints: native source limit 32768, slice bound 268435456, explicit positive
budgets, strict half-open physical ranges, and fallible bounded reservations.
Metadata accounting covers requested owned dynamic capacities per call, including
retained geometry, and reports actual vector capacity separately. Keys do not
prove binding, FileIds, RS order, availability, or workflow finality.

Review focus: integer overflow; many empty files; malformed EOF ranges; retained
capacity during queries; and allocator failure before a result exists.

## Task 1: checked numeric API and resources

Files: `src/geometry.rs`, root exports, `tests/source_geometry.rs`,
`tests/geometry_allocations.rs`, and `docs/SOURCE_GEOMETRY.md`.

- [x] Write public API tests for per-file rounding, exact/aligned sizes, golden
  100 GB/GiB and split-file arithmetic, limits, key order, and local loss unions.
- [x] Run missing-API RED. Add the public surface with provisional behavior;
  observe semantic RED before implementing geometry and loss mapping.
- [x] Implement checked sums, existing LCM reuse, monotone aligned search,
  typed errors, key sorting, and requested-capacity admission/getters.
- [x] Add isolated controlled allocation failures and allocation counts. Verify
  semantic/resource RED, then one geometry vector and one in-place loss vector.
- [x] Compare actual small physical-file Main, FileDesc, IFSC, and expected
  recovery geometry with both pinned references. Preserve legacy controls.
- [x] Document scope and resource boundaries. Run exact final `just ci` with
  pinned Vale 3.26 and both references, inspect the full diff, and commit locally.
- [ ] Deliver frozen HEAD/tree/report for the controller's independent API and
  resource review, then handle scoped fixes and coordinated publishing gates.

No creator I/O, source binding, poster policy, or finality implementation.
