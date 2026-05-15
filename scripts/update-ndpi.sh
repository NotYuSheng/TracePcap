#!/usr/bin/env bash
# update-ndpi.sh
#
# Installs or upgrades nDPI inside the running backend container from a
# pre-exported images/ndpi-debs.tar.gz package bundle.
#
# Run this on the offline machine after transferring images/ndpi-debs.tar.gz.
# No internet connection or image rebuild required.
#
# Usage:
#   bash scripts/update-ndpi.sh
#
# What it does:
#   1. Copies ndpi-debs.tar.gz into the running backend container.
#   2. Unpacks the .deb files and installs them with dpkg.
#   3. Restarts the backend container so ndpiReader picks up the new binaries.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DEBS_TARBALL="$ROOT_DIR/images/ndpi-debs.tar.gz"
CONTAINER="tracepcap-backend"

if [ ! -f "$DEBS_TARBALL" ]; then
  echo "ERROR: $DEBS_TARBALL not found."
  echo "Transfer images/ndpi-debs.tar.gz from the internet-connected build machine first."
  exit 1
fi

if ! docker inspect "$CONTAINER" &>/dev/null; then
  echo "ERROR: Container '$CONTAINER' is not running."
  echo "Start the stack first: docker compose -f docker-compose.offline.yml up -d"
  exit 1
fi

NEW_VERSION=$(tar -xOzf "$DEBS_TARBALL" ./VERSION 2>/dev/null || echo "unknown")
CURRENT_VERSION=$(docker exec "$CONTAINER" cat /opt/ndpi-debs/VERSION 2>/dev/null || echo "none")

echo "Current nDPI in container : ${CURRENT_VERSION}"
echo "nDPI version to install   : ${NEW_VERSION}"

if [ "$CURRENT_VERSION" = "$NEW_VERSION" ]; then
  echo "Already up to date. Nothing to do."
  exit 0
fi

echo ""
echo "Installing nDPI ${NEW_VERSION} into $CONTAINER ..."

# Copy the tarball into the container and install via dpkg.
docker cp "$DEBS_TARBALL" "$CONTAINER:/tmp/ndpi-debs.tar.gz"
docker exec --user root "$CONTAINER" bash -c '
  set -e
  TMPDIR=$(mktemp -d)
  tar -xzf /tmp/ndpi-debs.tar.gz -C "$TMPDIR"
  dpkg -i "$TMPDIR"/*.deb
  cp "$TMPDIR/VERSION" /opt/ndpi-debs/VERSION
  rm -rf "$TMPDIR" /tmp/ndpi-debs.tar.gz
'

echo "Restarting $CONTAINER ..."
docker restart "$CONTAINER"

echo ""
echo "Done. nDPI ${NEW_VERSION} is now active."
echo "Verify with: docker exec $CONTAINER ndpiReader --version"
