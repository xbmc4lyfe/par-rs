"""Stress two PAR2 repair CLIs against a single 200-file synthetic set on macOS."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import random
import resource
import shutil
import struct
import subprocess
import time

ROOT = Path(os.environ.get("BENCH_ROOT", "/tmp/par-rs-large-set")).resolve()
SOURCE = ROOT / "source"
WORK = ROOT / "run"
TURBO = Path(os.environ.get("TURBO", ROOT / "par2")).resolve()
OURS = Path(os.environ.get("PAR_RS", str(Path(__file__).resolve().parents[1] / "target/release/examples/par-rs"))).resolve()
MIB = 1 << 20
GIB = 1 << 30
FILES = [f"part{i:03}.bin" for i in range(200)]
SCENARIOS = ("one-missing", "short-parity", "scattered-10", "missing-40", "mixed-40")

# Darwin rusage_info_v2 contains a UUID and 18 uint64 counters. The last two count disk I/O bytes.
class Usage(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16), ("values", ctypes.c_uint64 * 18)]

proc_pid_rusage = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True).proc_pid_rusage
proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
proc_pid_rusage.restype = ctypes.c_int

def validate_parity(stem, slice_size, count, volume_count):
    recovery = {}
    volumes = sorted(SOURCE.glob(f"{stem}.vol*.par2"))
    assert len(volumes) == volume_count, volumes
    for p in volumes:
        with p.open("rb") as f:
            end = p.stat().st_size
            while f.tell() < end:
                head = f.read(64)
                assert head[:8] == b"PAR2\x00PKT"
                size = struct.unpack_from("<Q", head, 8)[0]
                assert size >= 64 and f.tell() + size - 64 <= end
                if head[48:] == b"PAR 2.0\x00RecvSlic":
                    assert size == slice_size + 68
                    exponent = struct.unpack("<I", f.read(4))[0]
                    assert exponent not in recovery
                    recovery[exponent] = p
                    f.seek(size - 68, 1)
                else:
                    f.seek(size - 64, 1)
    assert set(recovery) == set(range(count))
    return volumes

def prepare(scenario, stem, slice_size, volumes):
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir()
    missing = set()
    if scenario == "one-missing":
        missing = {73}
    elif scenario in ("missing-40", "short-parity"):
        missing = set(range(60, 140))
    elif scenario == "mixed-40":
        missing = set(range(60, 100))
    touched = []
    rng = random.Random(162)
    corrupt_count = {"scattered-10": 40, "mixed-40": 80}.get(scenario, 0)
    corrupt_files = set(rng.sample([i for i in range(200) if i not in missing], corrupt_count))
    for i, name in enumerate(FILES):
        if i in missing:
            touched.append(name)
            continue
        subprocess.run(["/bin/cp", "-c", SOURCE / name, WORK / name], check=True)
        if i in corrupt_files:
            if scenario == "mixed-40":
                os.truncate(WORK / name, slice_size)
            else:
                with (WORK / name).open("r+b") as f:
                    f.seek(rng.randrange(2) * slice_size + 16384)
                    f.write(rng.randbytes(4096))
            touched.append(name)
    for parity in [SOURCE / f"{stem}.par2", *(volumes[:-1] if scenario == "short-parity" else volumes)]:
        # Both programs only read the parity files. Use independent APFS clones.
        subprocess.run(["/bin/cp", "-c", parity, WORK / parity.name], check=True)
    return touched

def measure(command, log_path, sample_interval=0.05):
    usage = Usage()
    samples = []
    peak_rss_sample = (0, 0.0)
    start = time.monotonic()
    with log_path.open("wb") as log:
        child = subprocess.Popen(command, cwd=WORK, stdout=log, stderr=subprocess.STDOUT)
        while True:
            if proc_pid_rusage(child.pid, 2, ctypes.byref(usage)) == 0:
                rss = usage.values[6]
                if rss > peak_rss_sample[0]:
                    peak_rss_sample = rss, time.monotonic() - start
                sample = tuple(usage.values[-2:])
                if not samples or sample != samples[-1]:
                    samples.append(sample)
            pid, status, result = os.wait4(child.pid, os.WNOHANG)
            if pid:
                child.returncode = os.waitstatus_to_exitcode(status)
                break
            time.sleep(sample_interval)
    return dict(returncode=child.returncode, wall_s=time.monotonic() - start,
                cpu_s=result.ru_utime + result.ru_stime, user_s=result.ru_utime,
                system_s=result.ru_stime, rss_bytes=result.ru_maxrss,
                block_in=result.ru_inblock, block_out=result.ru_oublock,
                sampled_peak_rss_bytes=peak_rss_sample[0], sampled_peak_rss_at_s=peak_rss_sample[1],
                disk_read_bytes=counter_peak(samples, 0),
                disk_write_bytes=counter_peak(samples, 1))

def counter_peak(samples, index):
    peak = max((sample[index] for sample in samples), default=None)
    # Darwin can report a wrapped negative accounting value as uint64.
    return peak if peak is None or peak < (1 << 63) else None

def same_bytes(first, second):
    if not second.is_file() or first.stat().st_size != second.stat().st_size:
        return False
    with first.open("rb") as a, second.open("rb") as b:
        while block := a.read(8 << 20):
            if block != b.read(len(block)):
                return False
    return True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=("both", "turbo", "par-rs"), default="both")
    parser.add_argument("--scenario", choices=SCENARIOS, nargs="+", default=list(SCENARIOS))
    parser.add_argument("--mem", type=int, default=256)
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--nofile", type=int, default=4096)
    args = parser.parse_args()
    tools = ("turbo", "par-rs") if args.tool == "both" else (args.tool,)
    # Keep the descriptor limit identical for both programs.
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (args.nofile, hard))
    for scenario in args.scenario:
        single = scenario == "one-missing"
        stem, slice_size, count, volume_count = (
            ("single", 50 * MIB, 10, 1) if single else ("bulk", 250 * MIB, 160, 8)
        )
        volumes = validate_parity(stem, slice_size, count, volume_count)
        print(f"Validated {count} recovery packets across {volume_count} volumes", flush=True)
        for tool in tools:
            touched = prepare(scenario, stem, slice_size, volumes)
            if tool == "turbo":
                command = [str(TURBO), "r", "-q", f"-t{args.threads}", f"-m{args.mem}", f"{stem}.par2"]
            else:
                command = [str(OURS), "repair", "--threads", str(args.threads), "--mem", str(args.mem), f"{stem}.par2"]
            label = f"{tool}-{scenario}-m{args.mem}-t{args.threads}-fd{args.nofile}"
            print(f"Starting {label} ({len(touched)} affected files)", flush=True)
            log = ROOT / f"{label}.log"
            row = measure(command, log)
            row.update(tool=tool, scenario=scenario, mem_mib=args.mem, threads=args.threads,
                       command=command, log=str(log), soft_nofile=args.nofile, slice_bytes=slice_size, recovery_slices=count)
            # Record metrics before doing output comparisons, outside the timed repair.
            print(json.dumps(row), flush=True)
            if scenario == "short-parity":
                msg = log.read_text(errors="replace").lower()
                row["correct"] = row["returncode"] != 0 and (
                    "not possible" in msg or "not enough" in msg or "impossible" in msg
                ) and all(not (WORK / name).exists() for name in touched)
            else:
                row["correct"] = row["returncode"] == 0 and all(
                    same_bytes(SOURCE / name, WORK / name)
                    for name in touched
                ) and all((WORK / name).is_file() for name in FILES)
                row["compared_files"] = len(touched)
            with (ROOT / "results.jsonl").open("a") as f:
                f.write(json.dumps(row) + "\n")
            print(f"{label}: {'verified' if row['correct'] else 'FAILED'}", flush=True)
            if not row["correct"]:
                print(log.read_text(errors="replace")[-2200:], flush=True)
                raise SystemExit("repair verification failed")
            shutil.rmtree(WORK)

if __name__ == "__main__":
    main()
