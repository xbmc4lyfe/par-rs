# Repair performance and resource use

## Bounded hashing and scanning

The repair command-line tool and `Par2Repairer` stream large slices through bounded buffers.
Slices larger than 32 MiB use a 1 MiB hash buffer per worker. Smaller slices
retain the SIMD batch path, with at most 32 MiB of message storage per worker.
Hash workers retain one file handle between jobs. A streamed job can briefly
hold a second handle.

The scanner uses read buffers between 64 KiB and 8 MiB. It allocates outgoing
and candidate buffers only when needed, with at most three buffers per scanner.
This removes slice-sized allocations and the repeated movement of a large
sliding window. Candidate confirmation and outgoing-byte reads can reread data
when a slice exceeds the buffer. Existing resident bytes are reused.

Cancellation is checked between streaming chunks. A cancelled scan returns a
whole-file digest only if the file has already been completely hashed. It
stops without reading the remaining file just to finish that digest.

`--mem` controls the Reed–Solomon buffer budget, with a 16 MiB minimum.
Hashing, scanning, matrices, metadata, thread stacks, and allocator overhead
also consume memory. These measurements cover the repair command-line tool and
`Par2Repairer`. The separate APIs that accept or retain complete slices have
different memory requirements.

## Large archive comparison

The workload contains 200 files of 500 MiB each, totaling 97.656 GiB.
The benchmark uses Apple M4, 32 GiB RAM, APFS, ten compute threads, and a
256 MiB repair-buffer budget. Turbo uses its default two verification threads.
Each scenario starts from fresh APFS clones of the same source files.
Turbo runs first, followed by `par-rs`. Each row is one measured run.

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

### Results with bounded buffers

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

### Reduced-resource run

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

## Regression coverage

`just ci` runs allocation bounds, a 300-file descriptor test, bounded scanner
reads with shifted large slices and a padded tail, huge-slice CRC rejection,
and cancellation during a chunked read. Existing tests cover cross-tool repair,
renamed and split files, and Reed–Solomon reconstruction.

These deterministic checks run in ordinary CI. Timing comparisons use the
standalone harness because shared runner scheduling and cache state affect
wall-clock thresholds.
