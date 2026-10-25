#!/usr/bin/env bash
# Build on Debian/Ubuntu amd64 with Rust 1.90 and dpkg-deb available.
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(dpkg --print-architecture)" = amd64
libc_min=$(getconf GNU_LIBC_VERSION)
libc_min=${libc_min#glibc }
cargo build --locked --release --bin rpweld
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/doc/rpweld"
install -m 0755 "${CARGO_TARGET_DIR:-target}/release/rpweld" "$stage/usr/bin/rpweld"
install -m 0644 README.md "$stage/usr/share/doc/rpweld/README.md"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: rpweld
Version: 0.1.0~dev
Section: devel
Priority: optional
Architecture: amd64
Maintainer: Runpod Weld contributors
Depends: skopeo (>= 1.13), ca-certificates, libc6 (>= $libc_min), libgcc-s1
Description: Experimental OCI image builder with integrated registry authentication
 Builds trusted multi-stage Dockerfiles and publishes images over verified TLS.
CONTROL
mkdir -p target/packages
dpkg-deb --root-owner-group --build "$stage" target/packages/rpweld_0.1.0~dev_amd64.deb
printf 'Install with: apt install ./target/packages/rpweld_0.1.0~dev_amd64.deb\n'
