#!/bin/sh
set -eu
# Run from the assigned isolated checkout, with all build artifacts on native Linux.
cd "$(dirname "$0")/../../.."
: "${CARGO_HOME:?Set CARGO_HOME to the installed Rust 1.90 cargo directory}"
: "${RUSTUP_HOME:?Set RUSTUP_HOME to the installed Rust 1.90 rustup directory}"
export PATH="$CARGO_HOME/bin:$PATH"
export CARGO_TARGET_DIR="${HEREDOC_TARGET_DIR:-/tmp/weld-heredoc-oracle-target}"
rustfmt +1.90.0 --edition 2024 tests/heredoc_cli.rs
cargo +1.90.0 clippy --offline --locked --test heredoc_cli -- -D warnings
cargo +1.90.0 clippy --offline --locked --test heredoc_cli --target x86_64-pc-windows-gnu -- -D warnings
# Candidate execution is separate: parent integrates implementation before running tests.
