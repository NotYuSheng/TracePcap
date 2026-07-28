#!/usr/bin/env bash
# backup.sh
#
# Backs up everything TracePcap cannot regenerate:
#   1. PostgreSQL  — analysis results, conversations, monitor snapshots, human labels
#   2. MinIO       — the raw PCAP objects
#   3. config_data — signatures.yml (custom detection rules)
#
# Produces ONE timestamped tarball per run, then prunes runs older than
# BACKUP_RETENTION_DAYS. Designed to be driven by cron or a systemd timer; see
# docs/operations/backup-restore.rst.
#
# Usage:
#   bash scripts/backup.sh                 # writes to ./backups
#   BACKUP_DIR=/mnt/nas/tracepcap bash scripts/backup.sh
#
# Credentials are read from .env (or the environment) — never hard-coded here.
#
# Exit codes: 0 ok, non-zero on any failure (so cron reports it).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

# --- configuration ---------------------------------------------------------
# Load .env if present so cron (which has almost no environment) sees the same
# credentials as an interactive `docker compose` run.
#
# .env is Compose's format, NOT shell. It is parsed line by line rather than
# sourced: `source` would execute it, so a password containing $(...) or a
# backtick would run as a command, and one containing a space would abort the
# script with a confusing syntax error. Parsing also lets the real environment
# win — systemd's Environment= and any explicit `VAR=x scripts/backup.sh` must
# override .env, not the reverse, or the unit's BACKUP_DIR would be silently
# discarded and archives would land on the local disk instead of off-host storage.
load_env_file() {
  local file="$1" line key value
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"          # strip leading whitespace
    [[ -z "$line" || "$line" == \#* ]] && continue   # skip blanks and comments
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" != *=* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key%"${key##*[![:space:]]}"}"             # strip trailing whitespace
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    # Strip one layer of matching quotes, as Compose does.
    if [[ "$value" == \"*\" && ${#value} -ge 2 ]]; then value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && ${#value} -ge 2 ]]; then value="${value:1:${#value}-2}"
    fi
    # Only set if not already present: the caller's environment takes precedence.
    [[ -n "${!key+x}" ]] || export "$key=$value"
  done < "$file"
}
load_env_file ./.env

BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

POSTGRES_DB="${POSTGRES_DB:-tracepcap}"
POSTGRES_USER="${POSTGRES_USER:-tracepcap_user}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-tracepcap_pass}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:-minioadmin}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-minioadmin}"
# Matches the backend's hard-coded bucket in docker-compose.yml. Overriding this
# without changing the backend would back up a bucket the app does not use.
MINIO_BUCKET="${MINIO_BUCKET:-tracepcap-files}"

PG_CONTAINER="${PG_CONTAINER:-tracepcap-postgres}"
MINIO_CONTAINER="${MINIO_CONTAINER:-tracepcap-minio}"
BACKEND_CONTAINER="${BACKEND_CONTAINER:-tracepcap-backend}"

STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="$BACKUP_DIR/tracepcap-backup-$STAMP.tar.gz"

mkdir -p "$BACKUP_DIR"

# Serialise runs. The timer's Type=oneshot won't overlap itself, but the docs also
# document a cron line and a manual `systemctl start`, so two runs can coincide —
# and with one-second stamp resolution they could write the same archive path,
# truncating each other. Take the lock or exit quietly; a skipped duplicate run is
# correct behaviour, not an error worth waking anyone for.
exec 9>"$BACKUP_DIR/.backup.lock"
if ! flock -n 9; then
  echo "Another backup is already running (lock held on $BACKUP_DIR/.backup.lock); exiting."
  exit 0
fi

# Stage under BACKUP_DIR, not /tmp. The staging directory holds a full uncompressed
# copy of every PCAP object before tar runs, so peak usage is roughly twice the data
# set. /tmp is tmpfs (RAM-backed) on many server images, where a large capture set
# would exhaust memory and take the running stack down with it. BACKUP_DIR is the
# path the operator has already sized for this data.
WORK_DIR="$(mktemp -d "$BACKUP_DIR/.staging-$STAMP.XXXXXX")"
STAGE="$WORK_DIR/tracepcap-backup-$STAMP"

# Always clean up the staging directory, including on failure — it holds a full
# copy of the PCAP set and would otherwise fill /tmp after a few failed runs.
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

require_container() {
  docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -q true \
    || fail "container '$1' is not running — start the stack before backing up"
}

mkdir -p "$BACKUP_DIR" "$STAGE"

log "Backup starting → $ARCHIVE"
require_container "$PG_CONTAINER"
require_container "$MINIO_CONTAINER"

# --- 1. PostgreSQL ---------------------------------------------------------
# Custom format (-Fc): compressed, and restorable with pg_restore --clean, which
# lets the restore drop existing objects rather than erroring on conflicts.
log "Dumping PostgreSQL database '$POSTGRES_DB'…"
docker exec -e PGPASSWORD="${POSTGRES_PASSWORD:-tracepcap_pass}" "$PG_CONTAINER" \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc \
  > "$STAGE/postgres.dump" \
  || fail "pg_dump failed"

# A near-empty dump means the dump silently produced nothing useful.
PG_SIZE=$(stat -c%s "$STAGE/postgres.dump")
[[ "$PG_SIZE" -gt 1024 ]] || fail "postgres dump is only ${PG_SIZE}B — refusing to record this as a good backup"
log "  PostgreSQL dump: $(numfmt --to=iec "$PG_SIZE")"

# --- 2. MinIO objects ------------------------------------------------------
# `mc mirror` into a container-local path, then copy out. Credentials go in via
# `mc alias set` inside the container so they never appear in a shell command
# assembled on the host.
log "Mirroring MinIO bucket '$MINIO_BUCKET'…"
docker exec "$MINIO_CONTAINER" sh -c '
  set -e
  rm -rf /tmp/mc-backup
  mkdir -p /tmp/mc-backup
  mc alias set bk http://localhost:9000 "$0" "$1" >/dev/null
  mc mirror --quiet "bk/$2" /tmp/mc-backup >/dev/null
' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" "$MINIO_BUCKET" \
  || fail "mc mirror failed — check MINIO_ROOT_USER / MINIO_ROOT_PASSWORD"

docker cp "$MINIO_CONTAINER:/tmp/mc-backup" "$STAGE/minio" >/dev/null \
  || fail "copying MinIO objects out of the container failed"
docker exec "$MINIO_CONTAINER" rm -rf /tmp/mc-backup || true

OBJ_COUNT=$(find "$STAGE/minio" -type f | wc -l)
log "  MinIO objects: $OBJ_COUNT"

# An empty mirror is indistinguishable from a successful one at the exit-code level:
# a wrong bucket name mirrors nothing and still exits 0. Cross-check against what the
# bucket actually holds, so a backup that captured no PCAPs is never recorded as good
# while the database — which would restore fine — hides the loss until recovery day.
BUCKET_COUNT=$(docker exec "$MINIO_CONTAINER" sh -c '
  mc alias set bk http://localhost:9000 "$0" "$1" >/dev/null
  mc ls --recursive "bk/$2" 2>/dev/null | wc -l
' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" "$MINIO_BUCKET" | tr -d '[:space:]')

if [[ "$OBJ_COUNT" -ne "$BUCKET_COUNT" ]]; then
  fail "captured $OBJ_COUNT object(s) but bucket '$MINIO_BUCKET' holds $BUCKET_COUNT — refusing to record an incomplete backup"
fi

# --- 3. Config volume (signatures.yml) -------------------------------------
# Best-effort: a deployment that has never customised signatures has no file,
# and that is not a backup failure.
log "Capturing config volume…"
mkdir -p "$STAGE/config"
if docker inspect -f '{{.State.Running}}' "$BACKEND_CONTAINER" 2>/dev/null | grep -q true; then
  docker cp "$BACKEND_CONTAINER:/app/config/." "$STAGE/config/" 2>/dev/null \
    || log "  (no config files to capture)"
else
  log "  (backend not running — skipping config capture)"
fi

# --- 4. Manifest -----------------------------------------------------------
# Recorded so a restore can be checked against what was actually captured, and
# so the restore script can refuse a backup taken from a different database.
cat > "$STAGE/manifest.txt" <<EOF
tracepcap_backup_version=1
created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
host=$(hostname)
postgres_db=$POSTGRES_DB
postgres_user=$POSTGRES_USER
postgres_dump_bytes=$PG_SIZE
minio_bucket=$MINIO_BUCKET
minio_object_count=$OBJ_COUNT
EOF

# --- 5. Archive ------------------------------------------------------------
log "Creating archive…"
tar -czf "$ARCHIVE" -C "$WORK_DIR" "tracepcap-backup-$STAMP" \
  || fail "tar failed"

# Verify the archive is readable before we prune anything on its strength.
tar -tzf "$ARCHIVE" >/dev/null || fail "archive verification failed — $ARCHIVE is unreadable"

ARCHIVE_SIZE=$(stat -c%s "$ARCHIVE")
log "Archive: $ARCHIVE ($(numfmt --to=iec "$ARCHIVE_SIZE"))"

# --- 6. Prune old backups --------------------------------------------------
# Only after the new archive is verified, so a failing backup never destroys the
# last known-good one.
# Age is read from the timestamp in the FILENAME, not the filesystem mtime. Copying
# archives to a NAS (or restoring them from other media) rewrites mtime, which would
# reset every archive's retention clock and let BACKUP_DIR grow until the disk fills
# — breaking the next backup. The embedded stamp is authoritative and travels with
# the file.
if [[ "$BACKUP_RETENTION_DAYS" -gt 0 ]]; then
  CUTOFF=$(date -d "$BACKUP_RETENTION_DAYS days ago" +%Y%m%d)
  PRUNED=0
  for f in "$BACKUP_DIR"/tracepcap-backup-*.tar.gz; do
    [[ -e "$f" ]] || continue
    base="$(basename "$f")"
    file_date="${base#tracepcap-backup-}"
    file_date="${file_date%%-*}"
    [[ "$file_date" =~ ^[0-9]{8}$ ]] || continue   # unparseable name: leave it alone
    if [[ "$file_date" -lt "$CUTOFF" ]]; then
      rm -f "$f" && PRUNED=$((PRUNED + 1))
    fi
  done
  [[ "$PRUNED" -gt 0 ]] && log "Pruned $PRUNED backup(s) older than ${BACKUP_RETENTION_DAYS}d"
fi

log "Backup complete."
