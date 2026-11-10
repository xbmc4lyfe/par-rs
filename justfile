# Show the available commands.
[default]
default:
    @just --list

# Build and run the release command-line tool with optional arguments.
[positional-arguments]
run *args:
    cargo run --locked --release --example par-rs -- "$@"

# Build the release library and command-line tool.
build-release:
    cargo build --locked --release --lib --example par-rs

# Build the debug library and command-line tool.
build-debug:
    cargo build --locked --lib --example par-rs

# Format Rust and check prose against the Google style rules.
fmt:
    cargo fmt --all
    just prose

# Check formatting and prose without changing files.
fmt-check:
    cargo fmt --all -- --check
    just prose

# Check Markdown, source comments, and command-line messages.
prose:
    vale --no-global README.md docs src tests examples bench scripts .github justfile .vale/README.md

# Run Rust tests, Clippy, and prose coverage tests.
test:
    cargo test --locked --all-features
    cargo clippy --locked --all-targets --all-features -- -D warnings
    python3 -B -m unittest discover -s scripts -p 'test_*.py'

# Run the same checks as GitHub CI.
ci: fmt-check test build-release
