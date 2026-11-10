#!/usr/bin/env python3
"""Test the syntax boundaries of the repository's prose checks."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProseCoverage(unittest.TestCase):
    def lint(self, suffix, content):
        with tempfile.TemporaryDirectory(prefix="par-rs-prose-") as directory:
            source = Path(directory) / ("fixture" + suffix)
            source.write_text(content, encoding="utf-8")
            result = subprocess.run(
                ["vale", "--no-global", "--config", str(ROOT / ".vale.ini"),
                 "--output=JSON", str(source)],
                text=True, capture_output=True, check=False, cwd=ROOT,
            )
            self.assertIn(result.returncode, (0, 1), result.stderr + result.stdout)
            alerts = json.loads(result.stdout)
            return result.returncode, [alert for group in alerts.values() for alert in group]

    def assert_latin(self, suffix, content):
        code, alerts = self.lint(suffix, content)
        self.assertEqual(code, 1, alerts)
        self.assertIn("Google.Latin", [alert["Check"] for alert in alerts])

    def test_markdown(self):
        self.assert_latin(".md", "Use e.g. this example.\n")

    def test_rust_comments(self):
        self.assert_latin(".rs", "// Use e.g. this example.\nfn main() {}\n")
        self.assert_latin(".rs", "/* Use e.g. this example. */\nfn main() {}\n")
        self.assert_latin(".rs", "//! Use e.g. this example.\nfn main() {}\n")

    def test_rust_messages(self):
        for expression in (
            'println!("Use e.g. this example.");',
            'eprintln!("Use e.g. this example.");',
            'std::println!("Use e.g. this example.");',
            'format!("Use e.g. this example.");',
            'println!(r#"Use e.g. this example."#);',
            'observer.message(Level::Info, "Use e.g. this example.");',
            'observer.progress(Stage::Scan, 0, 1, "Use e.g. this example.");',
            'formatter.write_str("Use e.g. this example.");',
            'formatter.write_str(r#"Use e.g. this example."#);',
        ):
            with self.subTest(expression=expression):
                self.assert_latin(".rs", "fn main() { " + expression + " }\n")
        self.assert_latin(".rs", '#[error("Use e.g. this example.")]\nstruct Error;\n')
        self.assert_latin(".rs", '#[error(r#"Use e.g. this example."#)]\nstruct Error;\n')

    def test_rust_data_is_not_prose(self):
        code, alerts = self.lint(".rs", 'const DATA: &str = "// e.g. file(s)";\n')
        self.assertEqual((code, alerts), (0, []))

    def test_python_comments_and_docstrings(self):
        self.assert_latin(".py", "# Use e.g. this example.\n")
        self.assert_latin(".py", '\"\"\"Use e.g. this example.\"\"\"\n')
        self.assert_latin(".py", 'def sample():\n    \"\"\"Use e.g. this example.\"\"\"\n    pass\n')
        code, alerts = self.lint(".py", 'DATA = "# e.g. file(s)"\n')
        self.assertEqual((code, alerts), (0, []))

    def test_shell_comments(self):
        self.assert_latin(".sh", "#!/bin/sh\n# Use e.g. this example.\n")
        code, alerts = self.lint(".sh", 'for i in 1 2; do echo "$i"; done\n')
        self.assertEqual((code, alerts), (0, []))

    def test_markdown_code_is_not_prose(self):
        code, alerts = self.lint(".md", "Use `file(s)` as a literal.\n\n```text\ne.g. file(s)\n```\n")
        self.assertEqual((code, alerts), (0, []))


if __name__ == "__main__":
    unittest.main()
