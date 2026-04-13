#!/usr/bin/env bash
# load-images.sh
#
# Run this on the OFFLINE machine after copying the images/ folder here.
#
# What it does:
#   Loads every .tar file in ./images/ into the local Docker daemon.
#
# Usage:
#   bash scripts/load-images.sh
#
# After loading, start the stack with:
#   docker compose -f docker-compose.offline.yml up -d

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
IMAGES_DIR="$ROOT_DIR/images"

if [ ! -d "$IMAGES_DIR" ]; then
  echo "Error: images/ directory not found at $IMAGES_DIR"
  echo "Make sure you copied the images/ folder from the internet-connected machine."
  exit 1
fi

# Collect .tar files
shopt -s nullglob
TAR_FILES=("$IMAGES_DIR"/*.tar)
shopt -u nullglob

if [ ${#TAR_FILES[@]} -eq 0 ]; then
  echo "Error: No .tar files found in $IMAGES_DIR/"
  echo "Run pull-and-save-images.sh on an internet-connected machine first."
  exit 1
fi

echo "=== Loading Docker images from images/ ==="
echo ""
for tarfile in "${TAR_FILES[@]}"; do
  echo "  Loading $(basename "$tarfile")..."
  docker load -i "$tarfile"
done

echo ""
echo "=== All images loaded successfully ==="
echo ""
echo "Start the application with:"
echo "  docker compose -f docker-compose.offline.yml up -d"
