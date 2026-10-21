#!/usr/bin/env bash
# Start the standalone development fabric.  This intentionally never uses the
# production/default aperture: it is safe to leave running in one terminal.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bin=${QRMEM_BIN:-"$here/build/qrmem"}
aperture=${QRMEM_APERTURE:-/qrmem-dev}
socket=${QRMEM_SOCKET:-/tmp/qrmem-dev.sock}

if [[ ! -x $bin ]]; then
    printf 'QRMem binary not found: %s\nRun: make\n' "$bin" >&2
    exit 1
fi

printf 'Starting development QRMem fabric\n  aperture: %s\n  socket:   %s\n' \
    "$aperture" "$socket"
exec "$bin" --serve --aperture "$aperture" --socket "$socket" --no-snapshot
