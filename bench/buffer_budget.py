#!/usr/bin/env python3
"""Compare repair buffer budgets on a warm 1000 MiB set using macOS process metrics."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

import large_set


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--current", required=True, type=Path)
    parser.add_argument("--turbo", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path("/tmp/par-rs-buffer-budget"))
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--single-slice-files", action="store_true")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    root = args.root.resolve()
    source = root / "source"
    source.mkdir(parents=True, exist_ok=True)
    work = root / "run"
    large_set.WORK = work
    file_count, file_mib, slice_mib, recovery = (64, 16, 16, 26) if args.single_slice_files else (10, 100, 1, 100)
    scenarios = ("verify",) if args.single_slice_files else ("verify", "scattered", "missing")
    names = [f"part{i}.bin" for i in range(file_count)]
    for name in names:
        path = source / name
        if not path.exists():
            with path.open("wb") as stream:
                for _ in range(file_mib):
                    stream.write(os.urandom(1 << 20))
        assert path.stat().st_size == file_mib << 20
    turbo = args.turbo.resolve()
    if not (source / "set.par2").exists():
        with (root / "create.log").open("wb") as log:
            subprocess.run([str(turbo), "c", "-q", "-t10", "-m256", f"-s{slice_mib << 20}",
                            f"-c{recovery}", "-n1", "set.par2", *names], cwd=source,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
    tools = [("turbo", turbo), ("baseline", args.baseline.resolve()),
             ("current", args.current.resolve())]
    for memory in (16, 256):
        for scenario in scenarios:
            for repeat in range(args.runs):
                order = tools[repeat % len(tools):] + tools[:repeat % len(tools)]
                for name, binary in order:
                    if work.exists():
                        shutil.rmtree(work)
                    work.mkdir()
                    for path in source.iterdir():
                        subprocess.run(["/bin/cp", "-c", path, work / path.name], check=True)
                    touched = []
                    if scenario == "missing":
                        touched = ["part4.bin"]
                        (work / touched[0]).unlink()
                    elif scenario == "scattered":
                        touched = [f"part{i}.bin" for i in (1, 3, 5, 7)]
                        for filename in touched:
                            with (work / filename).open("r+b") as stream:
                                for block in range(10):
                                    stream.seek((block * 9 + 3) * (1 << 20) + 777)
                                    stream.write(b"\xab" * 4096)
                    for path in work.iterdir():
                        with path.open("rb") as stream:
                            while stream.read(8 << 20):
                                pass
                    if name == "turbo":
                        operation = "v" if scenario == "verify" else "r"
                        command = [str(binary), operation, "-q", "-t10", f"-m{memory}", "set.par2"]
                    else:
                        operation = "verify" if scenario == "verify" else "repair"
                        command = [str(binary), operation, "--threads", "10", "--mem", str(memory), "set.par2"]
                    label = f"{name}-{scenario}-m{memory}-{repeat}"
                    result = large_set.measure(command, root / f"{label}.log", sample_interval=0.001)
                    result.update(tool=name, scenario=scenario, mem_mib=memory, threads=10, repeat=repeat, files=file_count, file_mib=file_mib, slice_mib=slice_mib)
                    result["correct"] = result["returncode"] == 0 and all(
                        large_set.same_bytes(source / filename, work / filename) for filename in touched
                    )
                    with (root / "results.jsonl").open("a") as stream:
                        stream.write(json.dumps(result) + "\n")
                    print(label, json.dumps(result), flush=True)
                    if not result["correct"]:
                        raise SystemExit(f"verification failed for {label}")
    shutil.rmtree(work)


if __name__ == "__main__":
    main()
