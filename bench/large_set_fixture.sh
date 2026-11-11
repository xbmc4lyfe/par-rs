#!/bin/zsh
# Build the same archive layout in a new scratch directory using Turbo 1.5.0.
set -eu
scratch=${1:A}
turbo=${2:A}
mkdir "$scratch/source"
python3 - "$scratch/source" <<'PY'
import hashlib
import os
from pathlib import Path
import subprocess
import sys

source = Path(sys.argv[1])
template = source / 'template'
with template.open('wb') as f:
    for _ in range(500):
        f.write(os.urandom(1 << 20))
for i in range(200):
    path = source / f'part{i:03}.bin'
    subprocess.run(['/bin/cp', '-c', template, path], check=True)
    with path.open('r+b') as f:
        for b in range(10):
            f.seek(b * (50 << 20) + 8192)
            f.write(hashlib.shake_256(f'{i}:{b}'.encode()).digest(4096))
template.unlink()
PY
cd "$scratch/source"
ulimit -n 4096
"$turbo" c -q -t10 -m1024 -s52428800 -c10 -n1 single.par2 part*.bin
"$turbo" c -q -t10 -m4096 -s262144000 -c160 -u -n8 bulk.par2 part*.bin
