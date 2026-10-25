#!/bin/sh
# Offline, native-filesystem check. Arguments: binary, local Alpine OCI, new work dir.
set -eu
test "$(id -u)" = 0
binary="$1"
base="$2"
destination="$3"
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$binary:$base:$destination" in /*:/*:/*) ;; *) exit 2;; esac
test -f "$base/index.json"
mkdir "$destination"
for mask in 022 077; do
    (
        umask "$mask"
        area="$destination/mask-$mask"
        mkdir "$area"
        for attempt in first repeat; do
            if ! RPWELD_HOME="$area/store" timeout --signal=TERM --kill-after=5 120 \
                "$binary" build -t test/user-umask:latest --no-host-dns --platform linux/amd64 --run-timeout-seconds 20 \
                --base "alpine=$base" --work-dir "$area/work-$attempt" \
                --output "$area/output-$attempt" -f "$here/Dockerfile.runtime" "$here" > "$area/build-$attempt.log" 2>&1; then
                cat "$area/build-$attempt.log"
                exit 1
            fi
            cat "$area/build-$attempt.log"
            test "$(stat -c %a "$area/work-$attempt/rootfs")" = 755
            test "$(stat -c %u:%g "$area/work-$attempt/rootfs/qa/inherited")" = 12001:12006
            if [ "$mask" = 077 ]; then
                test "$(stat -c %a "$area/work-$attempt")" = 700
            fi
        done
        grep -Fq 'CACHED (verified local stage)' "$area/build-repeat.log"
        mkdir "$area/context"
        printf '%s\n' 'FROM alpine' 'RUN test "$(id -u)" = 12001 && test "$(id -g)" = 12006 && test "$(stat -c %a /)" = 755 && touch /qa/umask-roundtrip' > "$area/context/Dockerfile"
        RPWELD_HOME="$area/store" timeout --signal=TERM --kill-after=5 120 \
            "$binary" build -t test/user-umask:latest --no-host-dns --platform linux/amd64 --run-timeout-seconds 20 \
            --base "alpine=$area/output-repeat" --work-dir "$area/work-roundtrip" \
            --output "$area/output-roundtrip" "$area/context"
    )
done
python3 "$here/verify-root-modes.py" "$base" "$destination"
printf '%s\n' 'USER umask 022/077, exported root mode, cache checkpoints and inherited-base runtime acceptance passed.'
