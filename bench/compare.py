#!/usr/bin/env python3
"""PAR2 benchmark harness: create / verify / repair across tools, warm page cache, best-of-N.

Usage: `[RUNS=3] python3 bench/compare.py [tool ...]`
Environment: `DATA` (directory of input files), `WORK` (scratch directory), and the tool binaries
`PAR_RS`, `PARFAST` (nzbfast), `TURBO` (par2cmdline-turbo), `PARPAR`, and `PARMESAN`. Tools whose binary is
missing are skipped. Each run copies the data set fresh, warms the page cache, and times one
process; repairs are checked against the originals' MD5s.
"""
import os, shutil, subprocess, sys, time, hashlib, glob, json

DATA = os.path.abspath(os.environ.get("DATA", "bench/data"))
WORK = os.path.abspath(os.environ.get("WORK", "bench/work"))
def tool(env, default):
    """Binary from the environment or `default`; made absolute because tools run inside the work dirs."""
    b = os.environ.get(env, default)
    return os.path.abspath(b) if os.path.isfile(b) else b

OURS = tool("PAR_RS", "target/release/examples/par-rs")
PARFAST = tool("PARFAST", "parfast")
TURBO = tool("TURBO", "par2")
PARPAR = tool("PARPAR", "parpar")
PARMESAN = tool("PARMESAN", "parmesan")
SLICE = 1 << 20
RECOV = 100
RUNS = int(os.environ.get("RUNS", "3"))
ONLY = set(sys.argv[1:])  # tool names filter
FILES = sorted(os.listdir(DATA))
os.makedirs(WORK, exist_ok=True)

def available(binary):
    return os.path.isfile(binary) or shutil.which(binary) is not None

def sh(cmd, cwd, env=None):
    t = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    return time.perf_counter() - t, p.returncode, p.stdout.decode(errors="replace")

def fresh(dirname, with_data=True, par_from=None):
    d = f"{WORK}/{dirname}"
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    if with_data:
        for f in FILES:
            shutil.copyfile(f"{DATA}/{f}", f"{d}/{f}")
    if par_from:
        for p in glob.glob(f"{par_from}/*.par2"):
            shutil.copyfile(p, f"{d}/{os.path.basename(p)}")
    return d

def warm(d):
    for f in os.listdir(d):
        with open(f"{d}/{f}", "rb") as fh:
            while fh.read(1 << 24):
                pass

def md5dir(d):
    out = {}
    for f in FILES:
        h = hashlib.md5()
        with open(f"{d}/{f}", "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 22), b""):
                h.update(chunk)
        out[f] = h.hexdigest()
    return out

ORIG = None
def orig():
    global ORIG
    if ORIG is None:
        ORIG = md5dir(DATA)
    return ORIG

TOOLS = {
    "ours":     {"create": lambda d: [OURS, "create", "-s", str(SLICE), "-r", str(RECOV), "-n", "single", f"{d}/set.par2"] + FILES,
                 "verify": lambda d: [OURS, "verify", "--mem", "2048", f"{d}/set.par2"],
                 "repair": lambda d: [OURS, "repair", "--mem", "2048", f"{d}/set.par2"]},
    "nzbfast":  {"create": lambda d: [PARFAST, "c", "-q", "-s"+str(SLICE), "-c"+str(RECOV), "-n1", "set.par2"] + FILES,
                 "verify": lambda d: [PARFAST, "v", "-q", "set.par2"],
                 "repair": lambda d: [PARFAST, "r", "-q", "set.par2"]},
    "turbo":    {"create": lambda d: [TURBO, "c", "-q", "-s"+str(SLICE), "-c"+str(RECOV), "-n1", "set.par2"] + FILES,
                 "verify": lambda d: [TURBO, "v", "-q", "set.par2"],
                 "repair": lambda d: [TURBO, "r", "-q", "set.par2"]},
    "parpar":   {"create": lambda d: [PARPAR, "-s", str(SLICE) + "b", "-r", str(RECOV), "-n", "-o", "set.par2"] + FILES},
    "parmesan": {"create": lambda d: [PARMESAN, "create", "-s", str(SLICE), "--recovery-count", str(RECOV), "-m", "8 GiB"] + FILES,
                 "verify": lambda d: [PARMESAN, "verify", "set.par2"],
                 "repair": lambda d: [PARMESAN, "repair", "set.par2"]},
}

def damage_corrupt(d):
    # 40 corrupted blocks: 10 in each of 4 files, 4 KiB garbage at block starts
    for fi in (1, 3, 5, 7):
        with open(f"{d}/part{fi}.bin", "r+b") as fh:
            for b in range(10):
                fh.seek((b * 9 + 3) * SLICE + 777)
                fh.write(b"\xAB" * 4096)

def damage_missing(d):
    os.remove(f"{d}/part4.bin")

def count_blocks_in_set(d):
    return sum(os.path.getsize(p) for p in glob.glob(f"{d}/*.par2"))

results = {}
def rec(tool, phase, secs, ok):
    results.setdefault(tool, {}).setdefault(phase, []).append((secs, ok))
    print(f"  {tool:9s} {phase:14s} {secs:7.2f}s {'ok' if ok else 'FAIL'}", flush=True)

# ---- create: each tool its own set
ref_set = None
TOOL_BIN = {"ours": OURS, "nzbfast": PARFAST, "turbo": TURBO, "parpar": PARPAR, "parmesan": PARMESAN}
for tool in list(TOOLS):
    if not available(TOOL_BIN[tool]):
        print(f"  {tool:9s} skipped (binary not found: {TOOL_BIN[tool]})")
        del TOOLS[tool]
for tool, t in TOOLS.items():
    if ONLY and tool not in ONLY: continue
    if "create" not in t: continue
    for r in range(RUNS):
        d = fresh(f"create-{tool}")
        warm(d)
        secs, rc, out = sh(t["create"](d), d)
        pars = glob.glob(f"{d}/*.par2")
        ok = rc == 0 and len(pars) > 0
        if not ok: print(out[-2000:])
        rec(tool, "create", secs, ok)
    if tool == "turbo" and all(ok for _, ok in results[tool]["create"]):
        ref_set = d
    results[tool]["create_bytes"] = count_blocks_in_set(d)

# reference set for verify/repair = turbo's (standard par2cmdline output)
if ref_set is None:
    ref_tool = "turbo" if "turbo" in TOOLS else "ours"
    ref_set = fresh(f"create-{ref_tool}")
    sh(TOOLS[ref_tool]["create"](ref_set), ref_set)

for tool, t in TOOLS.items():
    if ONLY and tool not in ONLY: continue
    if "verify" not in t: continue
    for r in range(RUNS):
        d = fresh(f"verify-{tool}", par_from=ref_set)
        warm(d)
        secs, rc, out = sh(t["verify"](d), d)
        if rc != 0: print(out[-2000:])
        rec(tool, "verify-intact", secs, rc == 0)
    for scen, dmg in (("repair-corrupt40", damage_corrupt), ("repair-missing1", damage_missing)):
        for r in range(RUNS):
            d = fresh(f"{scen}-{tool}", par_from=ref_set)
            dmg(d)
            warm(d)
            secs, rc, out = sh(t["repair"](d), d)
            ok = rc == 0
            if ok:
                try:
                    ok = md5dir(d) == orig()
                except FileNotFoundError:
                    ok = False
            if not ok: print(out[-3000:])
            rec(tool, scen, secs, ok)

print("\n=== best of", RUNS, "(seconds) ===")
phases = ["create", "verify-intact", "repair-corrupt40", "repair-missing1"]
print(f"{'tool':9s}" + "".join(f"{p:>18s}" for p in phases))
for tool, ph in results.items():
    row = f"{tool:9s}"
    for p in phases:
        v = ph.get(p)
        if v:
            best = min(s for s, ok in v)
            allok = all(ok for s, ok in v)
            row += f"{best:>16.2f}{'' if allok else '!':>2s}"
        else:
            row += f"{'-':>18s}"
    print(row)
json.dump(results, open(f"{WORK}/results.json", "w"), indent=1)
