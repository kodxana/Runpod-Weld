#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
artifacts=$(realpath "${1:-target/packages}")
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
cp /usr/bin/busybox "$fixture/busybox"
tar -xzf "$artifacts/rpweld-$version-linux-amd64.tar.gz" -C "$fixture"
bundle="$fixture/rpweld-$version-linux-amd64"
for format in portable deb; do
  docker run --rm --network none --cap-add SYS_PTRACE --cap-add SYS_ADMIN \
    --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    --mount "type=bind,source=$PWD,target=/src,readonly" \
    --mount "type=bind,source=$bundle,target=/bundle,readonly" \
    --mount "type=bind,source=$artifacts,target=/artifacts,readonly" \
    --mount "type=bind,source=$fixture/busybox,target=/fixture-busybox,readonly" \
    -e FORMAT="$format" -e VERSION="$version" python:3.12-bookworm bash -euc '
      if [ "$FORMAT" = deb ]; then
        dpkg -i "/artifacts/rpweld_${VERSION}_amd64.deb"
        test -z "$(dpkg --verify rpweld)"
        weld=/usr/bin/rpweld
      else
        weld=/bundle/bin/rpweld
      fi
      test ! -e /usr/bin/skopeo
      python3 /src/tests/release_package.py --weld "$weld" --busybox /fixture-busybox
      mkdir -p /etc/containers
      cp /bundle/lib/rpweld/policy.json /etc/containers/policy.json
      python3 /src/tests/registry_preflight_https.py --weld "$weld"
      if [ "$FORMAT" = deb ]; then
        mkdir -p /root/.local/share/rpweld
        echo preserve > /root/.local/share/rpweld/package-removal-canary
        dpkg -r rpweld
        test "$(cat /root/.local/share/rpweld/package-removal-canary)" = preserve
        test ! -e /usr/bin/rpweld
      fi
    '
done
python3 tests/registry_preflight_https.py --weld "$bundle/bin/rpweld"
