#!/usr/bin/env bash
# export-ndpi-debs.sh
#
# Extracts the cached nDPI .deb files from the backend image and saves them as
# images/ndpi-debs.tar.gz for transfer to offline machines.
#
# Run this on an internet-connected machine after building the backend image
# (pull-and-save-images.sh already does this automatically).
#
# Usage (standalone):
#   bash scripts/export-ndpi-debs.sh
#
# Output:
#   images/ndpi-debs.tar.gz   — contains ndpi_*.deb + dep debs + VERSION file

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
IMAGES_DIR="$ROOT_DIR/images"
OUTPUT="$IMAGES_DIR/ndpi-debs.tar.gz"
BACKEND_IMAGE="tracepcap-backend:latest"

mkdir -p "$IMAGES_DIR"

echo "Extracting nDPI debs from $BACKEND_IMAGE ..."

# Run a temporary container, tar the deb cache directory, pipe to host.
docker run --rm "$BACKEND_IMAGE" \
    tar -czf - -C /opt/ndpi-debs . \
    > "$OUTPUT"

VERSION=$(docker run --rm "$BACKEND_IMAGE" cat /opt/ndpi-debs/VERSION 2>/dev/null || echo "unknown")
echo "  Exported nDPI ${VERSION} debs -> images/ndpi-debs.tar.gz"
