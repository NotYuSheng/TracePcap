#!/usr/bin/env bash
# restore.sh
#
# Restores a tarball produced by scripts/backup.sh: the PostgreSQL database, the
# MinIO PCAP objects, and signatures.yml.
#
# Usage:
#   bash scripts/restore.sh backups/tracepcap-backup-20260728-030000.tar.gz
#   bash scripts/restore.sh --list backups/…tar.gz     # show manifest, restore nothing
#   FORCE=1 bash scripts/restore.sh …                  # skip the confirmation prompt (cron/CI)
#
# THIS IS DESTRUCTIVE. It drops and recreates the objects in the target database
# and overwrites objects in the bucket. It prompts before doing so unless FORCE=1.
#
# The backend should be stopped while this runs, so nothing writes underneath the
# restore:
#   docker compose stop backend
#   bash scripts/restore.sh <archive>
#   docker compose start backend

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source ./.env; set +a
fi

POSTGRES_DB="${POSTGRES_DB:-tracepcap}"
POSTGRES_USER="${POSTGRES_USER:-tracepcap_user}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:-minioadmin}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-minioadmin}"
MINIO_BUCKET="${MINIO_BUCKET:-tracepcap-files}"

PG_CONTAINER="${PG_CONTAINER:-tracepcap-postgres}"
MINIO_CONTAINER="${MINIO_CONTAINER:-tracepcap-minio}"
BACKEND_CONTAINER="${BACKEND_CONTAINER:-tracepcap-backend}"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

LIST_ONLY=0
[[ "${1:-}" == "--list" ]] && { LIST_ONLY=1; shift; }

ARCHIVE="${1:-}"
[[ -n "$ARCHIVE" ]] || fail "usage: bash scripts/restore.sh [--list] <archive.tar.gz>"
[[ -f "$ARCHIVE" ]] || fail "archive not found: $ARCHIVE"

WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

log "Extracting $ARCHIVE…"
tar -xzf "$ARCHIVE" -C "$WORK_DIR" || fail "extraction failed — archive may be corrupt"

STAGE="$(find "$WORK_DIR" -maxdepth 1 -type d -name 'tracepcap-backup-*' | head -1)"
[[ -n "$STAGE" ]] || fail "archive does not look like a TracePcap backup (no tracepcap-backup-* directory)"
[[ -f "$STAGE/manifest.txt" ]] || fail "archive is missing manifest.txt — refusing to restore an unrecognised archive"

echo
echo "--- backup manifest ---"
cat "$STAGE/manifest.txt"
echo "-----------------------"
echo

[[ "$LIST_ONLY" -eq 1 ]] && { log "--list given; nothing restored."; exit 0; }

# Warn (don't block) when restoring into a differently-named database: it is a
# legitimate thing to do when cloning to a staging box, but it should never be
# silent, because the backend's DATABASE_URL must agree with the target.
MANIFEST_DB=$(grep '^postgres_db=' "$STAGE/manifest.txt" | cut -d= -f2)
if [[ "$MANIFEST_DB" != "$POSTGRES_DB" ]]; then
  log "WARNING: backup came from database '$MANIFEST_DB' but this deployment uses '$POSTGRES_DB'."
  log "         The backend will only see the data if DATABASE_URL points at '$POSTGRES_DB'."
fi

require_container() {
  docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -q true \
    || fail "container '$1' is not running — start postgres and minio before restoring"
}
require_container "$PG_CONTAINER"
require_container "$MINIO_CONTAINER"

if docker inspect -f '{{.State.Running}}' "$BACKEND_CONTAINER" 2>/dev/null | grep -q true; then
  log "WARNING: '$BACKEND_CONTAINER' is running. Stop it first (docker compose stop backend)"
  log "         so it cannot write to the database while it is being replaced."
fi

if [[ "${FORCE:-0}" != "1" ]]; then
  echo "This will REPLACE the contents of database '$POSTGRES_DB' and bucket '$MINIO_BUCKET'."
  read -r -p "Type 'restore' to continue: " CONFIRM
  [[ "$CONFIRM" == "restore" ]] || fail "aborted by user"
fi

# --- 1. PostgreSQL ---------------------------------------------------------
# --clean --if-exists drops existing objects first, so restoring over a populated
# database succeeds instead of failing on every duplicate.
log "Restoring PostgreSQL…"
docker exec -i -e PGPASSWORD="${POSTGRES_PASSWORD:-tracepcap_pass}" "$PG_CONTAINER" \
  pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner \
  < "$STAGE/postgres.dump" \
  || log "  pg_restore reported warnings (usually harmless 'does not exist' on --clean)"

# Confirm the restore actually produced tables, rather than trusting the exit code.
TABLE_COUNT=$(docker exec -e PGPASSWORD="${POSTGRES_PASSWORD:-tracepcap_pass}" "$PG_CONTAINER" \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
[[ "$TABLE_COUNT" -gt 0 ]] || fail "restore left 0 tables in '$POSTGRES_DB' — restore did NOT succeed"
log "  tables restored: $TABLE_COUNT"

# --- 2. MinIO objects ------------------------------------------------------
if [[ -d "$STAGE/minio" ]]; then
  log "Restoring MinIO objects…"
  docker exec "$MINIO_CONTAINER" rm -rf /tmp/mc-restore || true
  docker cp "$STAGE/minio" "$MINIO_CONTAINER:/tmp/mc-restore" >/dev/null \
    || fail "copying objects into the MinIO container failed"

  docker exec "$MINIO_CONTAINER" sh -c '
    set -e
    mc alias set rs http://localhost:9000 "$0" "$1" >/dev/null
    mc mb --ignore-existing "rs/$2" >/dev/null
    mc mirror --overwrite --quiet /tmp/mc-restore "rs/$2" >/dev/null
    rm -rf /tmp/mc-restore
  ' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" "$MINIO_BUCKET" \
    || fail "mc mirror (restore) failed"

  RESTORED=$(docker exec "$MINIO_CONTAINER" sh -c '
    mc alias set rs http://localhost:9000 "$0" "$1" >/dev/null
    mc ls --recursive "rs/$2" | wc -l
  ' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" "$MINIO_BUCKET")
  log "  objects in bucket: $RESTORED"
else
  log "No MinIO objects in this archive — skipping."
fi

# --- 3. Config -------------------------------------------------------------
if [[ -n "$(ls -A "$STAGE/config" 2>/dev/null)" ]]; then
  if docker inspect -f '{{.State.Running}}' "$BACKEND_CONTAINER" 2>/dev/null | grep -q true; then
    log "Restoring config files…"
    docker cp "$STAGE/config/." "$BACKEND_CONTAINER:/app/config/" >/dev/null \
      && log "  config restored (restart the backend to pick up signatures.yml)"
  else
    log "Backend not running — skipping config restore. Start it and re-run to restore signatures.yml."
  fi
fi

log "Restore complete."
log "Start the backend if it is stopped:  docker compose start backend"
