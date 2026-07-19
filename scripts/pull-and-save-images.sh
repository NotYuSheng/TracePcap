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
# Windows: run this in Git Bash or WSL — not CMD or PowerShell.
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
# 1. Pull third-party images — versions read from docker-compose.offline.yml
# ---------------------------------------------------------------------------
echo ""
echo "=== [1/3] Pulling third-party images ==="

# Parse third-party image tags directly from the offline compose file so that
# the script and the compose file never get out of sync.
OFFLINE_COMPOSE="$ROOT_DIR/docker-compose.offline.yml"
mapfile -t DOCKERHUB_IMAGES < <(
  grep '^[[:space:]]*image:' "$OFFLINE_COMPOSE" | \
  sed -E 's/^[[:space:]]*image:[[:space:]]*"?([^" #]+)"?.*/\1/' | \
  grep -v '^tracepcap-' | \
  sort -u
)

# Optionally include Keycloak, for an authenticated offline deployment. The image
# tag is read from docker-compose.prod.yml (the auth overlay) so it never drifts.
# Appending to DOCKERHUB_IMAGES means the pull and save loops below both pick it
# up automatically. Set INCLUDE_KEYCLOAK=true|false to skip the prompt (e.g. CI).
PROD_COMPOSE="$ROOT_DIR/docker-compose.prod.yml"
KEYCLOAK_IMAGE="$(
  grep -E '^[[:space:]]*image:[[:space:]]*.*keycloak' "$PROD_COMPOSE" 2>/dev/null | \
  sed -E 's/^[[:space:]]*image:[[:space:]]*"?([^" #]+)"?.*/\1/' | head -n1 || true
)"

want_keycloak() {
  [ -n "$KEYCLOAK_IMAGE" ] || return 1
  # Explicit override wins (true/1/yes vs anything else).
  if [ -n "${INCLUDE_KEYCLOAK:-}" ]; then
    case "$INCLUDE_KEYCLOAK" in [tT][rR][uU][eE]|1|[yY][eE][sS]|[yY]) return 0 ;; *) return 1 ;; esac
  fi
  # No TTY (piped/CI) and no override: default to excluding, so existing automated
  # runs are unchanged.
  if [ ! -t 0 ]; then
    echo "  (no TTY; skipping Keycloak — set INCLUDE_KEYCLOAK=true to include it)"
    return 1
  fi
  local reply=""
  read -r -p "  Include Keycloak ($KEYCLOAK_IMAGE) for authenticated offline use? [y/N] " reply || true
  case "$reply" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

SAVE_KEYCLOAK=0
if want_keycloak; then
  echo "  Including Keycloak: $KEYCLOAK_IMAGE"
  DOCKERHUB_IMAGES+=("$KEYCLOAK_IMAGE")
  SAVE_KEYCLOAK=1
fi

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
echo ""
if [ "$SAVE_KEYCLOAK" = "1" ]; then
  echo "Keycloak image was saved. To run auth offline you must ALSO transfer:"
  echo "  keycloak/realm-export.json"
  echo "and start with an auth-enabled compose (add the Keycloak service + auth env,"
  echo "and rebuild nginx with the VITE_AUTH_* args). Saving the image alone is not"
  echo "enough — see docs/configuration/authentication.rst."
  echo ""
fi
echo "To refresh nDPI: rebuild the backend image (it installs the latest nDPI),"
echo "re-run this script, transfer images/tracepcap-backend.tar, and load-images.sh."
