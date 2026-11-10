#!/usr/bin/env python3
"""Test the command-line tool through the public task runner."""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CommandLine(unittest.TestCase):
    def run_cli(self, *args, expected=0):
        result = subprocess.run(
            ["just", "run", *map(str, args)], cwd=ROOT,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_roundtrip_with_quoted_paths(self):
        with tempfile.TemporaryDirectory(prefix="par-rs cli ") as directory:
            root = Path(directory)
            source = root / "sample 'quoted' $data.bin"
            original = bytes(range(256)) * 128
            source.write_bytes(original)
            par = root / "sample set.par2"
            self.run_cli("create", "-s", "4096", "-r", "2", "-n", "single", par, source)
            self.run_cli("info", par)
            self.run_cli("verify", par)
            self.run_cli("rename", "--dry-run", root)
            damaged = bytearray(original)
            damaged[123:456] = b"X" * 333
            source.write_bytes(damaged)
            self.run_cli("verify", par, expected=1)
            self.run_cli("repair", par)
            self.assertEqual(source.read_bytes(), original)
            self.run_cli("verify", par)

    def test_usage(self):
        result = self.run_cli(expected=2)
        self.assertIn("usage: par-rs create", result.stderr)


if __name__ == "__main__":
    unittest.main()
