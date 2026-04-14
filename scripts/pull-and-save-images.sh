#!/usr/bin/env bash
# pull-and-save-images.sh
#
# Run this on an internet-connected machine BEFORE transferring to the offline host.
#
# What it does:
#   1. Pulls all third-party images from Docker Hub
#   2. Builds the backend and nginx images locally
#   3. Saves every image as a .tar file under ./images/
#
# Usage:
#   bash scripts/pull-and-save-images.sh
#
# Build args for nginx are read from .env (if present) — copy .env.example first
# if you haven't already configured it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
IMAGES_DIR="$ROOT_DIR/images"

BACKEND_IMAGE="tracepcap-backend:latest"
NGINX_IMAGE="tracepcap-nginx:latest"

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
save_image() {
  local image="$1"
  local filename="$2"
  echo "  Saving  $image  ->  images/$filename"
  docker save "$image" -o "$IMAGES_DIR/$filename"
}

# ---------------------------------------------------------------------------
# Load build-arg overrides from .env when available
# ---------------------------------------------------------------------------
if [ -f "$ROOT_DIR/.env" ]; then
  echo "Loading build args from .env"
  set -a
  # shellcheck source=/dev/null
  source "$ROOT_DIR/.env"
  set +a
fi

mkdir -p "$IMAGES_DIR"

# ---------------------------------------------------------------------------
# 1. Pull third-party images
# ---------------------------------------------------------------------------
echo ""
echo "=== [1/3] Pulling third-party images ==="

# --- Docker Hub ---
DOCKERHUB_IMAGES=(
  "postgres:15-alpine"
  "minio/minio:RELEASE.2024-11-07T00-52-20Z"
  "minio/mc:RELEASE.2024-11-21T17-21-54Z"
)

for img in "${DOCKERHUB_IMAGES[@]}"; do
  echo "  Pulling $img (Docker Hub)..."
  docker pull "$img"
done

# ---------------------------------------------------------------------------
# 2. Build local images
# ---------------------------------------------------------------------------
echo ""
echo "=== [2/3] Building local images ==="
cd "$ROOT_DIR"

echo "  Building backend..."
docker build \
  -t "$BACKEND_IMAGE" \
  ./backend

echo "  Building nginx (frontend)..."
docker build \
  --build-arg "VITE_API_BASE_URL=${VITE_API_BASE_URL:-/api}" \
  --build-arg "VITE_SUPPORTED_FILE_TYPES=${VITE_SUPPORTED_FILE_TYPES:-.pcap,.pcapng,.cap}" \
  --build-arg "VITE_ANALYSIS_OPTIONS=${VITE_ANALYSIS_OPTIONS:-false}" \
  --build-arg "VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT=${VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT:-false}" \
  -t "$NGINX_IMAGE" \
  -f ./nginx/Dockerfile \
  .

# ---------------------------------------------------------------------------
# 3. Save all images as tars
# ---------------------------------------------------------------------------
echo ""
echo "=== [3/3] Saving images to images/ ==="

for img in "${DOCKERHUB_IMAGES[@]}"; do
  filename="$(echo "$img" | tr '/:' '_').tar"
  save_image "$img" "$filename"
done
save_image "$BACKEND_IMAGE" "tracepcap-backend.tar"
save_image "$NGINX_IMAGE"   "tracepcap-nginx.tar"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Done ==="
echo ""
echo "Transfer the following to the offline machine:"
echo "  images/                    (all .tar files)"
echo "  docker-compose.offline.yml"
echo "  .env                       (or .env.example — configure before starting)"
echo "  scripts/load-images.sh"
echo ""
echo "Then on the offline machine run:"
echo "  bash scripts/load-images.sh"
echo "  docker compose -f docker-compose.offline.yml up -d"
