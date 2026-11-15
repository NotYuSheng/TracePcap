#!/usr/bin/env bash
# check_minio_volume_upgrade.sh — MinIO must start on a volume left by the pre-#838 image (#854).
#
# The Chainguard image runs MinIO as UID 65532; the old quay.io image ran it as root, so every
# existing minio_data volume is root-owned and MinIO crash-loops on it ("file access denied").
# CI otherwise only ever starts from empty volumes, which is why that shipped. This seeds a volume
# exactly as the old image left it (root:root, 755 dirs / 644 files), brings up `minio` from each
# given compose file under a throwaway project, and asserts it goes healthy — i.e. that the
# minio-volume-perms job ran and repaired ownership. It then starts it a second time to check the
# repair is idempotent.
#
# Usage: bash scripts/check_minio_volume_upgrade.sh [compose-file ...]
#        (defaults to docker-compose.yml and docker-compose.offline.yml)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
[ "$#" -gt 0 ] || set -- docker-compose.yml docker-compose.offline.yml

PROJECT="tp-minio-upgrade-$$"
IMAGE="cgr.dev/chainguard/minio:latest-dev"
OVERRIDE="$(mktemp)"
# Fixed container_names and the published console port would collide with a stack already running
# on this host, so the throwaway project renames the one and drops the other.
cat > "$OVERRIDE" <<YAML
services:
  minio:
    container_name: ${PROJECT}-minio
    ports: !reset []
  minio-volume-perms:
    container_name: ${PROJECT}-perms
YAML

compose() { docker compose -p "$PROJECT" -f "$1" -f "$OVERRIDE" "${@:2}"; }
current=""
cleanup() {
  [ -n "$current" ] && compose "$current" down -v >/dev/null 2>&1 || true
  rm -f "$OVERRIDE"
}
trap cleanup EXIT

fail=0
for file in "$@"; do
  current="$file"
  echo "=== $file"
  docker volume create "${PROJECT}_minio_data" >/dev/null
  docker run --rm -u 0 -v "${PROJECT}_minio_data:/data" --entrypoint sh "$IMAGE" -c '
    mkdir -p /data/.minio.sys/tmp /data/tracepcap-files/sample
    echo legacy > /data/tracepcap-files/sample/object
    chown -R 0:0 /data
    find /data -type d -exec chmod 755 {} +
    find /data -type f -exec chmod 644 {} +'

  for run in upgrade restart; do
    if compose "$file" up -d --wait --wait-timeout 120 minio >/dev/null 2>&1; then
      echo "  $run: minio healthy — $(docker logs "${PROJECT}-perms" 2>&1 | tail -n 1)"
    else
      echo "  $run: FAIL — minio did not become healthy on a root-owned volume" >&2
      docker logs "${PROJECT}-perms" 2>&1 | sed 's/^/    perms: /' >&2 || true
      docker logs "${PROJECT}-minio" 2>&1 | tail -n 5 | sed 's/^/    minio: /' >&2 || true
      fail=1
      break
    fi
    compose "$file" down >/dev/null 2>&1
  done
  compose "$file" down -v >/dev/null 2>&1
  current=""
done

exit "$fail"
