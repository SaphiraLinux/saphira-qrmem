#!/usr/bin/env bash
# Export one RED QR plane tile, verify it independently, then display it.
# The red plane is deliberately exported alone: occupancy/change layers are
# useful to models but must never be composited into a phone-scanning image.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bin=${QRMEM_BIN:-"$here/build/qrmem"}
aperture=${QRMEM_APERTURE:-/qrmem-dev}
tile=${1:-0:0:0}
viewer=${QR_VIEWER:-imv}
stamp=$(date +%Y%m%d-%H%M%S)
out=${QRMEM_QR_OUTPUT:-"/tmp/qrmem-${tile//:/-}-${stamp}.pbm"}

if [[ ! -x $bin ]]; then
    printf 'QRMem binary not found: %s\nRun: make\n' "$bin" >&2
    exit 1
fi

"$bin" --export-tile "$tile" --output "$out" --aperture "$aperture"
printf 'Image: %s\n' "$out"

if command -v zbarimg >/dev/null 2>&1; then
    printf '%s\n' 'Independent ZBar decode:'
    zbarimg --quiet --raw "$out" || {
        printf '%s\n' 'No QR decoded: the selected tile may be empty.' >&2
        exit 2
    }
fi

if command -v "$viewer" >/dev/null 2>&1; then
    exec "$viewer" "$out"
fi
printf 'Viewer %q is unavailable; open %s with an image viewer.\n' "$viewer" "$out"
