#!/usr/bin/env bash
# Invoke over SSH after upload and parent GO. Creation/deletion lives outside the Pod.
set -euo pipefail
umask 022
fixture_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for tool in python3 tar findmnt sha256sum; do
    command -v "$tool" >/dev/null
done
test "$(id -u)" = 0
python3 -B -c 'import sys; assert sys.version_info >= (3, 11), sys.version'
tar --version | head -n 1
# run.py verifies frozen binary hashes, native disk, free space, parent GO,
# exact metadata, and its experiment deadline before accepting measurements.
exec python3 -B "$fixture_dir/run.py" "$@"
