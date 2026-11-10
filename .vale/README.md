# Prose checks

The repository vendors [Google style rules v0.7.1](https://github.com/vale-cli/Google/releases/tag/v0.7.1)
under `styles/Google`, including the upstream license. Vale 3.26.0 reads the local
configuration and rules without a network request. Run `vale sync` to restore the
pinned upstream rules.

`just fmt` formats Rust and checks prose. `just fmt-check` performs the same checks
without changing Rust files. Both commands fail on Google warnings and errors.
Suggestions remain advisory and are available with `vale --no-global --minAlertLevel=suggestion`.

The syntax-aware views cover Rust comments and printed, formatted, observer, and
error messages. Python comments and docstrings, shell comments, task descriptions,
and Markdown are also checked. Code spans, fenced examples, and command argument
placeholders retain their literal spelling. Build output and vendored style rules
are outside the prose scope.

`just test` includes regression tests for the prose boundaries and the command-line
tool. These tests check that prose violations fail while identifiers, data strings,
and command arguments keep their meaning.
