#!/usr/bin/env bash
# Debian and portable packages carry the same offline bundle.
set -euo pipefail
exec bash "$(dirname "$0")/release-linux.sh" "${1:-target/packages}"
