#!/usr/bin/env bash
# Immutable v0.1.0 only, tiny fixture validation; these are not performance results.
set -euo pipefail
archive=$(realpath "$1")
fixture_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
expected=02396ce9ccd9800377fe4e0b0e49f42dd0ca221bccb6facec8ba86d390b861ee
test "$(sha256sum "$archive" | cut -d ' ' -f 1)" = "$expected"
stage=$(mktemp -d /var/tmp/v02-baseline-unit.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
tar -xzf "$archive" -C "$stage"
export RPWELD_V02_BASELINE="$stage/rpweld-0.1.0-linux-amd64/bin/rpweld"
export RPWELD_V02_BASELINE_SHA256=24c09bd3b805a525d447f5c568991dc50da417fdd299445b52c981087a273686
cd "$fixture_dir"
python3 -B -m unittest -v test_fixture
