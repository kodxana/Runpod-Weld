#!/bin/sh
# Opt-in destructive-to-the-rootfs test: use a fresh disposable Ubuntu rootfs.
# Requires root, working DNS in ROOTFS/etc/resolv.conf, and network apt mirrors.
set -eu
if [ "$#" -ne 3 ]; then
    echo "usage: private_root_smoke.sh EXAMPLES_DIR ROOTFS STATE_DIR" >&2
    exit 2
fi
examples=$(realpath "$1")
root=$(realpath "$2")
state=$(realpath "$3")

# Validate executor path constraints before device preparation mutates the root.
"$examples/exec_root" "$root" "$state" 0 0 5 ':'
"$examples/prepare_root" "$root"
"$examples/prepare_root" "$root" # Preparation must be idempotent.
"$examples/exec_root" "$root" "$state" 0 0 300 '
set -eu
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends hello python3 python3-venv ca-certificates build-essential
hello
python3 -m venv /tmp/weld-venv
/tmp/weld-venv/bin/python -m pip --version
printf "int main(void) { return 0; }\n" > /tmp/weld-compile.c
cc /tmp/weld-compile.c -o /tmp/weld-compile
/tmp/weld-compile
'
"$examples/exec_root" "$root" "$state" 1234 1234 15 '
set -eu
test -c /dev/null && test -c /dev/zero && test -c /dev/random && test -c /dev/urandom
echo discarded > /dev/null
dd if=/dev/null of=/tmp/weld-null-read bs=1 count=1 2>/dev/null
test ! -s /tmp/weld-null-read
dd if=/dev/zero of=/tmp/weld-zero-read bs=1 count=32 2>/dev/null
test "$(wc -c < /tmp/weld-zero-read)" -eq 32
dd if=/dev/urandom of=/tmp/weld-random-read bs=1 count=32 2>/dev/null
test "$(wc -c < /tmp/weld-random-read)" -eq 32
python3 -c "import os; assert os.getuid() == 1234; assert len(os.urandom(32)) == 32"
echo PRIVATE_ROOT_SMOKE_OK
'
