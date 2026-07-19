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
# Auth-enabled frontend, built only when Keycloak is included. Kept as a separate
# tag so the auth-off offline stack keeps using the plain nginx image unchanged.
NGINX_AUTH_IMAGE="tracepcap-nginx-auth:latest"

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
# tag is read from docker-compose.offline-prod.yml — the SAME file the offline host
# starts — so the saved image can never drift from what the offline stack expects.
# Appending to DOCKERHUB_IMAGES means the pull and save loops below both pick it
# up automatically. Set INCLUDE_KEYCLOAK=true|false to skip the prompt (e.g. CI).
OFFLINE_PROD_COMPOSE="$ROOT_DIR/docker-compose.offline-prod.yml"
KEYCLOAK_IMAGE="$(
  grep -E '^[[:space:]]*image:[[:space:]]*.*keycloak' "$OFFLINE_PROD_COMPOSE" 2>/dev/null | \
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

# vite.config.ts REQUIRES a version at build time and falls back to `git describe`,
# which is unavailable inside the Docker builder (no .git in the build context) —
# so resolve it here (git works in this checkout) and pass it explicitly, else the
# frontend build fails. Override by exporting VITE_APP_VERSION.
VITE_APP_VERSION="${VITE_APP_VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo "offline-build")}"

echo "  Building nginx (frontend)..."
docker build \
  --build-arg "VITE_API_BASE_URL=${VITE_API_BASE_URL:-/api/v1}" \
  --build-arg "VITE_SUPPORTED_FILE_TYPES=${VITE_SUPPORTED_FILE_TYPES:-.pcap,.pcapng,.cap}" \
  --build-arg "VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT=${VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT:-false}" \
  --build-arg "VITE_APP_VERSION=${VITE_APP_VERSION}" \
  -t "$NGINX_IMAGE" \
  -f ./nginx/Dockerfile \
  .

if [ "$SAVE_KEYCLOAK" = "1" ]; then
  echo "  Building nginx (frontend, auth-enabled)..."
  docker build \
    --build-arg "VITE_API_BASE_URL=${VITE_API_BASE_URL:-/api/v1}" \
    --build-arg "VITE_SUPPORTED_FILE_TYPES=${VITE_SUPPORTED_FILE_TYPES:-.pcap,.pcapng,.cap}" \
    --build-arg "VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT=${VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT:-false}" \
    --build-arg "VITE_APP_VERSION=${VITE_APP_VERSION}" \
    --build-arg "VITE_AUTH_ENABLED=true" \
    --build-arg "VITE_OIDC_CLIENT_ID=tracepcap-frontend" \
    --build-arg "VITE_OIDC_REALM=tracepcap" \
    -t "$NGINX_AUTH_IMAGE" \
    -f ./nginx/Dockerfile \
    .
fi

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
if [ "$SAVE_KEYCLOAK" = "1" ]; then
  save_image "$NGINX_AUTH_IMAGE" "tracepcap-nginx-auth.tar"
fi

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
  echo "Keycloak (auth) was included. To run authenticated offline, ALSO transfer:"
  echo "  docker-compose.offline-prod.yml"
  echo "  keycloak/realm-export.json"
  echo ""
  echo "and start with the auth overlay, setting PUBLIC_URL to the exact origin"
  echo "you browse to (scheme + host + port):"
  echo "  PUBLIC_URL=http://<host>:8888 \\"
  echo "    docker compose -f docker-compose.offline.yml -f docker-compose.offline-prod.yml up -d"
  echo ""
  echo "Then manage users at <PUBLIC_URL>/admin — see docs/configuration/user-management.rst."
  echo ""
fi
echo "To refresh nDPI: rebuild the backend image (it installs the latest nDPI),"
echo "re-run this script, transfer images/tracepcap-backend.tar, and load-images.sh."
