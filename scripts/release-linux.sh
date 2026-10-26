#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(uname -m)" = x86_64
if [ -n "$(git status --porcelain)" ]; then
  echo 'Release builds require a clean, committed checkout.' >&2
  exit 1
fi
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}
RPWELD_BUILD_ID=$(git rev-parse HEAD)
export RPWELD_BUILD_ID
export RUSTFLAGS='-C target-feature=+crt-static'
cargo fetch --locked
cargo build --locked --release --target x86_64-unknown-linux-gnu --bin rpweld
python3 scripts/package-linux.py \
  --binary "${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-gnu/release/rpweld" \
  --output "${1:-target/packages}"
