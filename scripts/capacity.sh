#!/usr/bin/env bash
# capacity.sh
#
# Reports where TracePcap's storage stands and projects where it is heading.
#
# Read-only: it runs SELECTs and `mc du`, and changes nothing. Safe to run on a
# live deployment, from cron, or from a monitoring check.
#
# Usage:
#   bash scripts/capacity.sh
#   bash scripts/capacity.sh --quiet     # one summary line, for cron/monitoring
#
# Exit codes:
#   0  headroom OK
#   1  could not gather (stack down, bad credentials)
#   2  WARNING  — disk above WARN_PERCENT, or projected to fill within WARN_DAYS
#   3  CRITICAL — disk above CRIT_PERCENT, or not enough room to stage a backup
#
# The non-zero codes make it usable as a cron canary:
#   0 7 * * * cd /path/to/TracePcap && bash scripts/capacity.sh --quiet || mail -s ...

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

# .env is Compose's format, not shell — parsed rather than sourced so a password
# containing $(...), a backtick or a space cannot execute or break the script, and
# so the caller's environment wins over the file. Mirrors scripts/backup.sh.
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

# Retention settings, read the same way the backend does.
FILE_RETENTION_ENABLED="${FILE_RETENTION_ENABLED:-true}"
FILE_RETENTION_HOURS="${FILE_RETENTION_HOURS:-12}"

# Thresholds (override in .env or the environment).
WARN_PERCENT="${CAPACITY_WARN_PERCENT:-75}"
CRIT_PERCENT="${CAPACITY_CRIT_PERCENT:-90}"
WARN_DAYS="${CAPACITY_WARN_DAYS:-30}"
RATE_WINDOW_DAYS="${CAPACITY_RATE_WINDOW_DAYS:-7}"

# Storage the deployment actually consumes per byte of PCAP ingested: the object
# itself (1x) plus a database that grows to roughly 1-1.5x the capture (see
# docs/operations/scalability.rst). 2.5 is the conservative end.
STORAGE_MULTIPLIER="${CAPACITY_STORAGE_MULTIPLIER:-2.5}"

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

say() { [[ "$QUIET" -eq 1 ]] || printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

human() { numfmt --to=iec --suffix=B "${1:-0}" 2>/dev/null || echo "${1:-0}B"; }

require_container() {
  docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -q true \
    || fail "container '$1' is not running — start the stack first"
}
require_container "$PG_CONTAINER"
require_container "$MINIO_CONTAINER"

psql_q() {
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "$1" 2>/dev/null | tr -d '[:space:]'
}

# --- gather ----------------------------------------------------------------
DB_BYTES=$(psql_q "SELECT pg_database_size('$POSTGRES_DB')") \
  || fail "could not query PostgreSQL — check POSTGRES_USER / POSTGRES_PASSWORD"
[[ -n "$DB_BYTES" ]] || fail "could not query PostgreSQL — check POSTGRES_USER / POSTGRES_PASSWORD"

# `packets` is LIST-partitioned per file (#394), so the parent relation is empty.
# Size has to be summed across the partitions via pg_inherits, or it reads as ~0.
PACKETS_BYTES=$(psql_q "
  SELECT COALESCE(SUM(pg_total_relation_size(c.oid)), 0)
  FROM pg_class c
  JOIN pg_inherits i ON i.inhrelid = c.oid
  JOIN pg_class p ON p.oid = i.inhparent
  WHERE p.relname = 'packets'")
PARTITIONS=$(psql_q "
  SELECT COUNT(*) FROM pg_inherits i
  JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'packets'")

FILE_COUNT=$(psql_q "SELECT COUNT(*) FROM files")
PCAP_BYTES=$(psql_q "SELECT COALESCE(SUM(file_size), 0) FROM files")
RECENT_BYTES=$(psql_q "
  SELECT COALESCE(SUM(file_size), 0) FROM files
  WHERE uploaded_at > now() - interval '$RATE_WINDOW_DAYS days'")

MINIO_RAW=$(docker exec "$MINIO_CONTAINER" sh -c '
  mc alias set cap http://localhost:9000 "$0" "$1" >/dev/null 2>&1
  mc du "cap/$2" 2>/dev/null
' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" "$MINIO_BUCKET" || true)
MINIO_HUMAN=$(awk '{print $1}' <<<"$MINIO_RAW")
MINIO_OBJECTS=$(awk '{print $2}' <<<"$MINIO_RAW")
[[ -n "$MINIO_HUMAN" ]] || { MINIO_HUMAN="unknown"; MINIO_OBJECTS="?"; }

# Disk backing the Docker volumes — where both Postgres and MinIO actually live.
DOCKER_ROOT=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)
read -r DISK_TOTAL DISK_USED DISK_FREE <<<"$(df -PB1 "$DOCKER_ROOT" 2>/dev/null | awk 'NR==2{print $2, $3, $4}')"
[[ -n "${DISK_FREE:-}" ]] || fail "could not read disk usage for $DOCKER_ROOT"
DISK_PCT=$(awk -v u="$DISK_USED" -v t="$DISK_TOTAL" 'BEGIN{printf "%.0f", (t>0? u*100/t : 0)}')

# --- report ----------------------------------------------------------------
say "TracePcap capacity — $(date '+%Y-%m-%d %H:%M')"
say ""
say "  PostgreSQL   $(human "$DB_BYTES")   (packets $(human "$PACKETS_BYTES") across $PARTITIONS partition(s))"
say "  MinIO        ${MINIO_HUMAN}   (${MINIO_OBJECTS} objects)"
say "  Captures     $FILE_COUNT file(s), $(human "$PCAP_BYTES") of PCAP ingested"
say "  Disk         $(human "$DISK_FREE") free of $(human "$DISK_TOTAL")  (${DISK_PCT}% used, $DOCKER_ROOT)"
say ""

STATUS=0
NOTES=()

# Backup staging headroom: backup.sh stages an uncompressed copy under BACKUP_DIR
# before archiving, so a run needs roughly twice the live data set free.
NEED_BACKUP=$(awk -v d="$DB_BYTES" -v m="$PCAP_BYTES" 'BEGIN{printf "%d", (d+m)*2}')
if [[ "$DISK_FREE" -lt "$NEED_BACKUP" ]]; then
  NOTES+=("CRITICAL: not enough free disk to stage a backup (needs ~$(human "$NEED_BACKUP"))")
  STATUS=3
fi

# --- projection ------------------------------------------------------------
DAILY=$(awk -v b="$RECENT_BYTES" -v d="$RATE_WINDOW_DAYS" 'BEGIN{printf "%.0f", (d>0? b/d : 0)}')

if [[ "$DAILY" -le 0 ]]; then
  say "  No captures ingested in the last ${RATE_WINDOW_DAYS} days — no growth rate to project from."
  say "  Re-run after a representative period of use."
else
  GROWTH=$(awk -v r="$DAILY" -v m="$STORAGE_MULTIPLIER" 'BEGIN{printf "%.0f", r*m}')
  say "  Ingest rate  $(human "$DAILY")/day over the last ${RATE_WINDOW_DAYS} days"
  say "               → ~$(human "$GROWTH")/day of storage (PCAP + database, x${STORAGE_MULTIPLIER})"
  say ""

  if [[ "${FILE_RETENTION_ENABLED,,}" == "false" ]]; then
    # Nothing is ever reclaimed: growth is unbounded and the disk is the only limit.
    DAYS=$(awk -v f="$DISK_FREE" -v g="$GROWTH" 'BEGIN{printf "%.0f", (g>0? f/g : 0)}')
    say "  Retention is DISABLED — storage grows without bound."
    say "  At this rate the disk fills in ~${DAYS} days ($(awk -v d="$DAYS" 'BEGIN{printf "%.1f", d/7}') weeks)."
    if [[ "$DAYS" -lt "$WARN_DAYS" ]]; then
      NOTES+=("WARNING: projected to fill within ${DAYS} days")
      [[ "$STATUS" -lt 2 ]] && STATUS=2
    fi
  else
    # Retention caps the working set: steady state is one retention window of ingest.
    RET_DAYS=$(awk -v h="$FILE_RETENTION_HOURS" 'BEGIN{printf "%.4f", h/24}')
    STEADY=$(awk -v g="$GROWTH" -v d="$RET_DAYS" 'BEGIN{printf "%.0f", g*d}')
    say "  Retention is ENABLED at ${FILE_RETENTION_HOURS}h, so the working set is bounded."
    say "  Steady-state size ≈ $(human "$STEADY") (${RET_DAYS} days of ingest)."
    if [[ "$STEADY" -gt "$DISK_FREE" ]]; then
      NOTES+=("CRITICAL: steady-state size exceeds free disk — lower FILE_RETENTION_HOURS")
      STATUS=3
    fi
    say ""
    say "  Monitor-mode snapshots are exempt from this window and are NOT bounded by it"
    say "  (MONITOR_FILE_RETENTION_HOURS defaults to 0 = never). On a monitor-heavy"
    say "  deployment they are what actually accumulates."
  fi
fi

# --- thresholds ------------------------------------------------------------
if [[ "$DISK_PCT" -ge "$CRIT_PERCENT" ]]; then
  NOTES+=("CRITICAL: disk ${DISK_PCT}% used (threshold ${CRIT_PERCENT}%)")
  STATUS=3
elif [[ "$DISK_PCT" -ge "$WARN_PERCENT" ]]; then
  NOTES+=("WARNING: disk ${DISK_PCT}% used (threshold ${WARN_PERCENT}%)")
  [[ "$STATUS" -lt 2 ]] && STATUS=2
fi

if [[ ${#NOTES[@]} -gt 0 ]]; then
  say ""
  for n in "${NOTES[@]}"; do say "  ** $n"; done
fi

if [[ "$QUIET" -eq 1 ]]; then
  if [[ ${#NOTES[@]} -gt 0 ]]; then
    printf 'tracepcap capacity: %s | disk %s%% used, %s free\n' \
      "${NOTES[0]}" "$DISK_PCT" "$(human "$DISK_FREE")"
  else
    printf 'tracepcap capacity: OK | disk %s%% used, %s free\n' "$DISK_PCT" "$(human "$DISK_FREE")"
  fi
fi

exit "$STATUS"
