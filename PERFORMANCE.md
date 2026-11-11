# Repair performance and resource use

## Bounded hashing and scanning

The repair command-line tool and `Par2Repairer` stream slices through bounded
buffers. SIMD MD5 state is retained between reads, with a scalar streaming path
for single-message jobs. Up to 16 consecutive ranges from one file share a
job. Each lane reads at most 64 KiB at a time, and message buffers share an
8 MiB working-space target. Workers retain one file handle between jobs.

The scanner uses read buffers between 64 KiB and 256 KiB. It allocates outgoing
and candidate buffers only when needed. Parallel scanners share the verification
working-space target. Candidate confirmation and outgoing-byte reads can reread
data when a slice exceeds the buffer. Existing resident bytes are reused.

Reconstruction chunks are capped at 256 KiB as well as the configured buffer
budget. This reduces the input pipeline and output working set for ordinary
1 MiB slices. Whole-file hash workers are also limited by their buffer costs.

Cancellation is checked between streaming chunks. A cancelled scan returns a
whole-file digest only if the file has already been completely hashed. It
stops without reading the remaining file just to finish that digest.

`--mem` controls the per-phase buffer budget, with a 16 MiB minimum.
Verification uses at most its 8 MiB working-space target for message buffers.
Matrices, metadata, thread stacks, and allocator overhead also consume memory.
Allocators can retain freed buffers between phases. These measurements cover
`Par2Repairer` and the repair command-line tool. APIs that accept or retain
complete slices have different memory requirements.

## Recovery-matrix limit

Disk repair and the high-level streaming repair planners now check matrix
memory before inversion. For `k` missing slices, the input matrix, augmented
matrix, and returned inverse can coexist and require `8 × k²` bytes. The
matrix cap equals the configured repair or solve budget, with a 16 MiB minimum.
An oversized solve returns `RecoveryMemoryLimit` with the missing-slice count,
required bytes, and limit. Disk repair checks before backups, renames, and target
creation. Streaming cutover checks before taking syndromes or opening targets.
The C API adds status 13 without changing existing status values.

The 16 MiB setting accepts up to 1,448 missing slices; 256 MiB accepts 5,792.
The tested 97.656 GiB cases need at most 160 and remain below either cap. Total
archive bytes and file count do not determine matrix size. A 32,768-slice
loss would previously attempt 8 GiB of matrices regardless of `--mem`.

This is a separate matrix cap, not a total-process RSS limit. During disk
reconstruction the retained inverse needs `2 × k²` bytes, at most one quarter
of the cap, in addition to engine buffers. Metadata, stacks, allocator retention,
and caller-owned data remain additional. Streaming APIs also retain syndromes
and reconstructed slices under their own contracts; this guard does not make
those APIs equivalent to bounded disk repair. Direct low-level matrix APIs
remain caller-managed.

The change rejects oversized planning before allocation; it does not change
the solve kernels for accepted repairs. The throughput measurements below
come from the preceding streamed-buffer implementation. CI checks both limit
boundaries, overflow, file preservation, streaming-syndrome preservation, and
successful reconstruction within the limit.

## Small archive comparison

The streaming SIMD implementation in `d8eeea4` was compared with `d10eb91`
(the first bounded-buffer change) and Turbo 1.5.0 on the same M4 host.
The main fixture has 10 independent random files of 100 MiB each, 1 MiB slices,
and 100 recovery slices. Tool order rotates between repetitions, and files are
warmed before each timed process. The table shows medians of three runs with
ten requested compute threads. Every repair passed a byte comparison.

| Budget MiB | Scenario | Turbo seconds | par-rs seconds | Turbo CPU seconds | par-rs CPU seconds | Turbo peak MiB | par-rs peak MiB |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | Intact verification | 0.785 | 0.087 | 1.436 | 0.558 | 6.4 | 8.2 |
| 16 | 40 damaged slices | 1.925 | 0.629 | 4.986 | 2.851 | 26.8 | 28.8 |
| 16 | One missing file | 1.478 | 1.492 | 6.022 | 4.149 | 23.3 | 31.2 |
| 256 | Intact verification | 0.774 | 0.068 | 1.420 | 0.568 | 5.4 | 8.2 |
| 256 | 40 damaged slices | 1.846 | 0.494 | 4.972 | 3.464 | 83.1 | 82.3 |
| 256 | One missing file | 1.530 | 0.920 | 6.458 | 6.536 | 139.2 | 123.1 |

At the 256 MiB setting, earlier peak RSS was 323.3 MiB for verification,
663.1 MiB for scattered damage, and 593.6 MiB for a missing file. The missing-file
repair takes about 11% longer than that earlier implementation while reducing
peak RAM about 79%. It remains faster than Turbo in these measurements.

A second fixture uses 64 files of 16 MiB, with one slice per file. At the
256 MiB setting, current verification takes 0.205 seconds, 1.738 CPU seconds,
and 3.6 MiB peak RSS. Turbo takes 1.185 seconds, 1.866 CPU seconds, and
35.3 MiB. This case exercises the scalar streaming path for singleton jobs.

The warm-cache SSD measurements leave cold-cache and rotational-disk throughput
unverified. Full measurements are in [the buffer-budget results](bench/results/buffer-budget-m4.json).

To repeat both layouts, build the baseline from `d10eb91` separately and supply
its executable along with the current build and Turbo.

```sh
python3 bench/buffer_budget.py --baseline /path/to/baseline/par-rs --current target/release/examples/par-rs --turbo /path/to/par2
python3 bench/buffer_budget.py --baseline /path/to/baseline/par-rs --current target/release/examples/par-rs --turbo /path/to/par2 --root /tmp/par-rs-single-slice --single-slice-files
```

## Large archive comparison

The workload contains 200 files of 500 MiB each, totaling 97.656 GiB.
The benchmark uses Apple M4, 32 GiB RAM, APFS, ten compute threads, and a
256 MiB repair-buffer budget. Turbo uses its default two verification threads.
Each scenario starts from fresh APFS clones of the same source files.
In the first pass, Turbo runs first, followed by `par-rs`. Each row is one measured run.

The source files share a random template with a unique 4 KiB marker in every
50 MiB segment. This exercises real hashing and reconstruction while limiting
fixture storage. APFS clones and filesystem cache affect the observed times
and physical I/O. The test checks repaired bytes against the original files
outside the timed interval.

The single-file scenario uses 50 MiB slices and ten recovery slices. Other
scenarios use 250 MiB slices, 400 source slices, and 160 recovery slices.

- One missing file loses all ten slices of a 500 MiB file.
- Scattered 10% damage overwrites 4 KiB inside one slice in each of 40 files.
- Whole-file 40% loss removes 80 files, requiring all 160 recovery slices.
- Mixed 40% loss removes 40 files and truncates 80 others to 250 MiB.
- Insufficient parity removes 80 files and withholds 20 recovery slices.
  Both tools must refuse repair and leave the missing files absent.

### Results with streamed SIMD buffers

These follow-up runs use `d8eeea4` and the same source fixture. The Turbo
reference measurements below are reused from the earlier pass, rather than
rerun alongside this executable. Each large scenario has one measured run,
so cache state and timing variation limit the comparison.

| Scenario | Turbo seconds | par-rs seconds | Turbo CPU seconds | par-rs CPU seconds | Turbo peak MiB | par-rs peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| One missing file | 125.8 | 89.2 | 229.0 | 130.3 | 367.2 | 65.9 |
| Scattered 10% damage | 457.6 | 191.9 | 916.5 | 905.1 | 1291.6 | 82.2 |
| Whole-file 40% loss | 288.5 | 251.0 | 1086.1 | 1175.6 | 772.0 | 156.1 |
| Mixed 40% loss | 310.1 | 281.3 | 1138.4 | 1359.3 | 772.2 | 146.9 |
| Insufficient parity | 116.0 | 31.2 | 162.6 | 111.3 | 503.5 | 4.7 |

Compared with the first bounded-buffer implementation below, successful
large repairs take 20–32% longer with the tighter chunk cap. Peak RSS falls
43–84%, and total CPU time falls or remains nearly unchanged. All these
repairs remain faster than the recorded Turbo runs. The smaller working set
trades some throughput for lower memory use.

A separate two-thread run with `--mem 16` and a 256-descriptor limit restored
the missing 500 MiB file in 258.3 seconds with 24.4 MiB peak RAM. It used 100.9 CPU seconds.

The final executable hash, correctness checks, read counters, and all six
runs are in [the streamed results](bench/results/large-streamed-m4.json).

The sampled process read counters for the final executable were as follows.

| Scenario | Turbo read GiB | par-rs read GiB |
| --- | ---: | ---: |
| One missing file | 194.9 | 195.0 |
| Scattered 10% damage | 258.0 | 237.0 |
| Whole-file 40% loss | 229.5 | 233.4 |
| Mixed 40% loss | 246.6 | 253.3 |
| Insufficient parity | 92.8 | 58.6 |

### First bounded-buffer results

These runs use the implementation in `f5566ce`, built with Rust 1.99.1,
and par2cmdline-turbo 1.5.0. Every expected repair or refusal passed validation.
CPU seconds include user and system time across all threads.

| Scenario | Turbo seconds | par-rs seconds | Turbo CPU seconds | par-rs CPU seconds | Turbo peak MiB | par-rs peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| One missing file | 125.8 | 67.6 | 229.0 | 248.0 | 367 | 275 |
| Scattered 10% damage | 457.6 | 148.9 | 916.5 | 909.0 | 1292 | 519 |
| Whole-file 40% loss | 288.5 | 208.4 | 1086.1 | 1289.4 | 772 | 275 |
| Mixed 40% loss | 310.1 | 221.4 | 1138.4 | 1419.7 | 772 | 277 |
| Insufficient parity | 116.0 | 20.2 | 162.6 | 93.0 | 503 | 13 |

The sampled process read counters were as follows.

| Scenario | Turbo read GiB | par-rs read GiB |
| --- | ---: | ---: |
| One missing file | 194.9 | 194.7 |
| Scattered 10% damage | 258.0 | 236.1 |
| Whole-file 40% loss | 229.5 | 232.8 |
| Mixed 40% loss | 246.6 | 252.2 |
| Insufficient parity | 92.8 | 58.6 |

The complete metrics and executable hashes are in
[the measurement file](bench/results/large-set-m4.json).

### First reduced-resource run

A separate run restored the missing 500 MiB file in the same 97.656 GiB set
with two threads, `--mem 16`, and a 256-descriptor soft limit. It passed the
byte comparison in 214.7 seconds, used 191.8 CPU seconds, and peaked at
24.3 MiB RSS. The earlier implementation failed this descriptor limit during
hashing. This run measures the configured repair path on the same M4 host.

### Earlier baseline

The earlier `par-rs` executable was built from `c19fb84`. Main at `7193e03`
contains the same repair algorithms, with updates to command-line naming and repository tooling. These earlier runs used the same layout and damage patterns with a
separately generated random template.

| Scenario | Turbo seconds | Earlier par-rs seconds | Turbo CPU seconds | Earlier par-rs CPU seconds | Turbo peak MiB | Earlier par-rs peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| One missing file | 129.3 | 67.8 | 233.7 | 247.4 | 367 | 1272 |
| Scattered 10% damage | 467.3 | 514.3 | 918.6 | 3485.6 | 1291 | 5007 |
| Whole-file 40% loss | 344.8 | 258.9 | 1311.4 | 1474.5 | 770 | 5274 |
| Mixed 40% loss | 440.0 | 285.2 | 1229.8 | 1644.9 | 771 | 5294 |
| Insufficient parity | 117.7 | 20.4 | 164.8 | 94.8 | 503 | 2504 |

## Reproduce the measurements

Build the release example with `just build-release`. Download the macOS ARM64
binary from the [par2cmdline-turbo v1.5.0 release](https://github.com/animetosho/par2cmdline-turbo/releases/tag/v1.5.0) and place it at
`/tmp/par-rs-large-set/par2`.

```sh
mkdir -p /tmp/par-rs-large-set
zsh bench/large_set_fixture.sh /tmp/par-rs-large-set /tmp/par-rs-large-set/par2
BENCH_ROOT=/tmp/par-rs-large-set python3 bench/large_set.py
```

The fixture script requires macOS and APFS clone support. Allow at least
120 GiB of free scratch space. Parity occupies approximately 40 GiB, and
Turbo's mixed case writes approximately 59 GiB of target files. The remaining
space covers source data, backups, metadata, and headroom. The harness removes each working copy after verification
and retains the source fixture, logs, and `results.jsonl`. Set `PAR_RS` and
`TURBO` to override binary paths. Use `--scenario` to select cases and `--mem`,
`--threads`, and `--nofile` to change limits for both tools.

Wall time includes the complete repair process. CPU time is user plus system
time from `wait4`. Peak RSS comes from the same process resource report.
Disk bytes come from sampled Darwin process counters. Buffered writes can be
underreported, so those counters do not establish total physical writes.
Wrapped negative accounting values are recorded as unavailable in the streamed
results, with the original unsigned value retained for inspection.

## Regression coverage

`just ci` runs allocation bounds, a 300-file descriptor test, bounded scanner
reads with shifted large slices and a padded tail, huge-slice CRC rejection,
and cancellation during a chunked read. Existing tests cover cross-tool repair,
renamed and split files, and Reed–Solomon reconstruction. The buffer regression
test also requests 64 verification threads with a 16 MiB budget and checks
aggregate live allocations during intact and damaged scans. Reconstruction
has a separate allocation ceiling. Scalar and SIMD hashes are checked against
independent digests at message, chunk, padding, and lane-count boundaries.

These deterministic checks run in ordinary CI. Timing comparisons use the
standalone harness because shared runner scheduling and cache state affect
wall-clock thresholds.
