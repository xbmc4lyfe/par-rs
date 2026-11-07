#!/usr/bin/env bash
# Build nzbget-parity and its competitors on an x86_64 Linux box and run bench/compare.py.
#
# Usage (on the server, from the repo root):  bash bench/remote-x86.sh [runs]
# Needs: git, curl, gcc/cc, xz. Installs rustup under $HOME if cargo is missing. Fetches
# nzbfast (built from source), par2cmdline-turbo and ParPar (prebuilt releases) into
# $BENCH_HOME (default ~/par2-bench). Prints CPU features so the ISA level is on record.
set -euo pipefail
RUNS="${1:-3}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_HOME="${BENCH_HOME:-$HOME/par2-bench}"
mkdir -p "$BENCH_HOME"

echo "== host"
uname -a
grep -m1 "model name" /proc/cpuinfo || true
echo -n "cores: "; nproc
echo -n "isa: "; grep -o -w -E "ssse3|sse4_2|pclmulqdq|avx2|avx512bw|gfni|vpclmulqdq" /proc/cpuinfo | sort -u | tr '\n' ' '; echo
free -g | head -2

if ! command -v cargo >/dev/null 2>&1; then
  if [ -x "$HOME/.cargo/bin/cargo" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
  else
    echo "== installing rust"
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
fi
cargo --version

echo "== building nzbget-parity"
(cd "$REPO" && cargo build --release --examples 2>&1 | tail -1)

echo "== nzbfast (parfast)"
if [ ! -x "$BENCH_HOME/nzbfast/target/release/parfast" ]; then
  [ -d "$BENCH_HOME/nzbfast" ] || git clone --depth 1 https://github.com/nzbfast/nzbfast "$BENCH_HOME/nzbfast"
  # nzbfast pins a toolchain in rust-toolchain.toml; use whatever cargo is installed.
  (cd "$BENCH_HOME/nzbfast" && RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-$(rustc --version | awk '{print $2}')}" cargo build --release -p parfast 2>&1 | tail -1) || \
  (cd "$BENCH_HOME/nzbfast" && cargo build --release -p parfast 2>&1 | tail -1)
fi
"$BENCH_HOME/nzbfast/target/release/parfast" -V | head -1

echo "== par2cmdline-turbo"
if [ ! -x "$BENCH_HOME/turbo/par2" ]; then
  mkdir -p "$BENCH_HOME/turbo"
  TURBO_URL=$(curl -s https://api.github.com/repos/animetosho/par2cmdline-turbo/releases/latest | grep -o 'https://[^"]*linux-amd64[^"]*' | head -1)
  curl -sL "$TURBO_URL" -o "$BENCH_HOME/turbo/turbo.archive"
  (cd "$BENCH_HOME/turbo" && { tar xf turbo.archive 2>/dev/null || unxz -k turbo.archive 2>/dev/null || unzip -o turbo.archive >/dev/null; } && f=$(find . -type f -name 'par2*' ! -name '*.archive' | head -1) && mv "$f" par2 && chmod +x par2)
fi
"$BENCH_HOME/turbo/par2" -V | head -1

echo "== ParPar"
if [ ! -x "$BENCH_HOME/parpar/parpar" ]; then
  mkdir -p "$BENCH_HOME/parpar"
  PP_URL=$(curl -s https://api.github.com/repos/animetosho/ParPar/releases/latest | grep -o 'https://[^"]*linux-static-amd64[^"]*' | head -1)
  curl -sL "$PP_URL" -o "$BENCH_HOME/parpar/parpar.xz" && (cd "$BENCH_HOME/parpar" && unxz -f parpar.xz && chmod +x parpar)
fi
"$BENCH_HOME/parpar/parpar" --version | head -1 || true

echo "== data (10 x 100 MiB random)"
DATA="$BENCH_HOME/data"
mkdir -p "$DATA"
for i in 0 1 2 3 4 5 6 7 8 9; do
  [ -s "$DATA/part$i.bin" ] || head -c 104857600 /dev/urandom > "$DATA/part$i.bin"
done

echo "== benchmark (best of $RUNS)"
cd "$REPO"
DATA="$DATA" WORK="$BENCH_HOME/work" \
NZBPAR="$REPO/target/release/examples/nzbpar" \
PARFAST="$BENCH_HOME/nzbfast/target/release/parfast" \
TURBO="$BENCH_HOME/turbo/par2" \
PARPAR="$BENCH_HOME/parpar/parpar" \
PARMESAN="${PARMESAN:-parmesan}" \
RUNS="$RUNS" python3 bench/compare.py
