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

# .env is Compose's format, not shell — parsed rather than sourced so a password
# containing $(...), a backtick or a space cannot execute or break the script, and
# so the caller's environment wins over the file. See backup.sh for the full note.
load_env_file() {
  local file="$1" line key value
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" != *=* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ "$value" == \"*\" && ${#value} -ge 2 ]]; then value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && ${#value} -ge 2 ]]; then value="${value:1:${#value}-2}"
    fi
    [[ -n "${!key+x}" ]] || export "$key=$value"
  done < "$file"
}
load_env_file ./.env

POSTGRES_DB="${POSTGRES_DB:-tracepcap}"
POSTGRES_USER="${POSTGRES_USER:-tracepcap_user}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-tracepcap_pass}"
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

MANIFEST_BUCKET=$(grep '^minio_bucket=' "$STAGE/manifest.txt" | cut -d= -f2)
if [[ -n "$MANIFEST_BUCKET" && "$MANIFEST_BUCKET" != "$MINIO_BUCKET" ]]; then
  log "WARNING: backup came from bucket '$MANIFEST_BUCKET' but this deployment uses '$MINIO_BUCKET'."
  log "         Objects will be restored into '$MINIO_BUCKET'; the backend must be configured to read it."
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
PG_ERR="$WORK_DIR/pg_restore.err"
docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner \
  < "$STAGE/postgres.dump" 2> "$PG_ERR" || true

# pg_restore exits non-zero for harmless reasons under --clean --if-exists (it reports
# every "does not exist" as an error), so the exit code alone is unusable. Filter those
# out and treat anything remaining as a real failure — otherwise a genuine break (disk
# full, truncated dump, wrong user) would be indistinguishable from routine noise, and
# the table count below would still pass on the objects --clean had already dropped.
REAL_ERRORS=$(grep -c '^pg_restore: error:' "$PG_ERR" 2>/dev/null || true)
BENIGN=$(grep -c 'does not exist' "$PG_ERR" 2>/dev/null || true)
if [[ "${REAL_ERRORS:-0}" -gt "${BENIGN:-0}" ]]; then
  log "  pg_restore reported errors beyond the expected '--clean' notices:"
  grep '^pg_restore: error:' "$PG_ERR" | grep -v 'does not exist' | head -5 | sed 's/^/    /'
  fail "pg_restore failed — the database may be partially restored. Do NOT start the backend against it."
fi
[[ "${BENIGN:-0}" -gt 0 ]] && log "  ($BENIGN expected '--clean' notices ignored)"

# Independently confirm the restore produced tables, rather than trusting exit codes.
TABLE_COUNT=$(docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
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

  # --remove makes this a true replacement, matching what the prompt and the docs
  # promise. Without it the restore is additive: rolling back a bad import would
  # leave that import's objects orphaned in the bucket, invisible to the restored
  # database (which has no rows for them) and never reclaimed.
  docker exec "$MINIO_CONTAINER" sh -c '
    set -e
    mc alias set rs http://localhost:9000 "$0" "$1" >/dev/null
    mc mb --ignore-existing "rs/$2" >/dev/null
    mc mirror --overwrite --remove --quiet /tmp/mc-restore "rs/$2" >/dev/null
    rm -rf /tmp/mc-restore
  ' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" "$MINIO_BUCKET" \
    || fail "mc mirror (restore) failed"

  RESTORED=$(docker exec "$MINIO_CONTAINER" sh -c '
    mc alias set rs http://localhost:9000 "$0" "$1" >/dev/null
    mc ls --recursive "rs/$2" | wc -l
  ' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" "$MINIO_BUCKET" | tr -d '[:space:]')
  log "  objects in bucket: $RESTORED"

  # The manifest records what was captured precisely so the restore can be checked
  # against it. An interrupted transfer that restores 3 of 50 PCAPs must not report
  # success — that is the failure the operator would only discover at recovery time.
  EXPECTED_OBJ=$(grep '^minio_object_count=' "$STAGE/manifest.txt" | cut -d= -f2 | tr -d '[:space:]')
  if [[ -n "$EXPECTED_OBJ" && "$RESTORED" != "$EXPECTED_OBJ" ]]; then
    fail "expected $EXPECTED_OBJ object(s) from the manifest but the bucket holds $RESTORED — restore is INCOMPLETE"
  fi
else
  log "No MinIO objects in this archive — skipping."
fi

# --- 3. Config -------------------------------------------------------------
if [[ -n "$(ls -A "$STAGE/config" 2>/dev/null)" ]]; then
  if docker inspect -f '{{.State.Running}}' "$BACKEND_CONTAINER" 2>/dev/null | grep -q true; then
    log "Restoring config files…"
    # Explicit || — a bare `&&` would swallow the failure and still let the script
    # print "Restore complete.", leaving signatures.yml quietly missing.
    if docker cp "$STAGE/config/." "$BACKEND_CONTAINER:/app/config/" >/dev/null 2>&1; then
      log "  config restored (restart the backend to pick up signatures.yml)"
    else
      fail "config restore failed — signatures.yml was NOT restored"
    fi
  else
    log "Backend not running — skipping config restore. Start it and re-run to restore signatures.yml."
  fi
fi

log "Restore complete."
log "Start the backend if it is stopped:  docker compose start backend"
