#!/bin/sh
set -e

MEM=${APP_MEMORY_MB:-2048}

# JVM heap fraction of the container memory budget. Deliberately NOT 75%: the backend shells out
# to native subprocesses (tshark, ndpi, Suricata, tcpflow — see PcapParserService, NdpiService,
# TsharkEnrichmentService, SessionReconstructionService, SuricataService, …) whose RSS lives
# *outside* the JVM heap, and the JVM itself needs non-heap room (metaspace, thread stacks, code
# cache, direct buffers ≈ 250–400 MB). At 75% a Suricata-heavy analysis pushed the container past
# its budget; once a hard memory limit exists that becomes a reliable OOM-kill instead of a
# diffuse host-level problem. Budget: ~50% heap / ~20% JVM non-heap / ~30% native subprocesses.
# See issue #378 and docs/operations/production-hardening.rst (Container Resource Limits).
JVM_HEAP_PERCENT=${JVM_HEAP_PERCENT:-50}

# Prefer the real cgroup limit over APP_MEMORY_MB. The JRE (Temurin 21) is container-aware, so
# -XX:MaxRAMPercentage sizes the heap from the limit the kernel will actually enforce. This keeps
# the heap correct even when the compose/k8s memory limit and APP_MEMORY_MB disagree — the failure
# mode that makes hand-computed -Xmx dangerous. Falls back to APP_MEMORY_MB arithmetic when the
# container runs unlimited (no limit set), where there is no cgroup value worth reading.
#
# cgroup v2 exposes "max" (literal string) when unlimited; v1 reports a sentinel near LONG_MAX.
CGROUP_LIMIT_BYTES=""
if [ -r /sys/fs/cgroup/memory.max ]; then
  CGROUP_LIMIT_BYTES=$(cat /sys/fs/cgroup/memory.max)
elif [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
  CGROUP_LIMIT_BYTES=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
fi

case "$CGROUP_LIMIT_BYTES" in
  # Unlimited ("max", empty, or an implausibly large v1 sentinel): no enforced limit to read.
  ''|max|[0-9]*[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])
    MEM_MODE="APP_MEMORY_MB (no container memory limit detected)"
    JVM_HEAP_MB=$(( MEM * JVM_HEAP_PERCENT / 100 ))
    JVM_MEM_OPTS="-Xms${JVM_HEAP_MB}m -Xmx${JVM_HEAP_MB}m"
    ;;
  *)
    MEM_MODE="cgroup limit ($(( CGROUP_LIMIT_BYTES / 1024 / 1024 )) MB)"
    JVM_HEAP_MB=$(( CGROUP_LIMIT_BYTES / 1024 / 1024 * JVM_HEAP_PERCENT / 100 ))
    # InitialRAMPercentage mirrors Max so the heap is still pre-committed, matching the previous
    # -Xms == -Xmx behaviour (no heap-growth pauses mid-analysis).
    JVM_MEM_OPTS="-XX:InitialRAMPercentage=${JVM_HEAP_PERCENT} -XX:MaxRAMPercentage=${JVM_HEAP_PERCENT}"
    ;;
esac

# Max upload = 25% of APP_MEMORY_MB, expressed in bytes
MAX_UPLOAD_BYTES=$(( MEM * 25 / 100 * 1024 * 1024 ))

# Analysis/proxy timeout: 45% of APP_MEMORY_MB, clamped to [300, 900] seconds
TIMEOUT=$(( MEM * 45 / 100 ))
if [ "$TIMEOUT" -lt 300 ]; then TIMEOUT=300; fi
if [ "$TIMEOUT" -gt 900 ]; then TIMEOUT=900; fi

# Ensure signatures.yml exists and is writable by the spring user.
# Runs as root so it can fix ownership regardless of how the named volume was seeded.
if [ ! -f /app/config/signatures.yml ] && [ -f /app/config-defaults/signatures.yml ]; then
  cp /app/config-defaults/signatures.yml /app/config/signatures.yml
fi
chown spring:spring /app/config/signatures.yml 2>/dev/null || true
chmod 664 /app/config/signatures.yml 2>/dev/null || true

# Ensure the log directory exists and is writable by the spring user. The prod Spring profile
# logs to a file (${LOG_DIR}/application.log, default /app/logs); the default dev profile is
# console-only so this is a harmless no-op there. Runs as root so it can create + chown it.
#
# Fail fast rather than swallow errors: an immutable mount, a read-only volume, or a dir
# pre-owned by another user would otherwise let the app boot with no file logging or crash
# deep inside Logback init. Verify the spring user can actually create the log file before exec.
export LOG_DIR="${LOG_DIR:-/app/logs}"
if ! mkdir -p "${LOG_DIR}"; then
  echo "FATAL: cannot create log directory ${LOG_DIR}" >&2
  exit 1
fi
if ! chown spring:spring "${LOG_DIR}"; then
  echo "FATAL: cannot chown log directory ${LOG_DIR} to spring:spring (immutable/read-only mount, or owned by another user?)" >&2
  exit 1
fi
# Prove the spring user can actually create a file in the dir the prod profile will log into,
# then clean up the probe. Catches read-only/immutable mounts that survive mkdir + chown.
if ! gosu spring sh -c "touch \"${LOG_DIR}/.write-probe\" && rm -f \"${LOG_DIR}/.write-probe\""; then
  echo "FATAL: spring user cannot write into log directory ${LOG_DIR}" >&2
  exit 1
fi

echo "TracePcap backend starting:"
echo "  APP_MEMORY_MB        = ${MEM} MB"
echo "  Memory budget from   = ${MEM_MODE}"
echo "  JVM heap             = ${JVM_HEAP_MB} MB (${JVM_HEAP_PERCENT}% of budget)"
echo "  Native headroom      = $(( 100 - JVM_HEAP_PERCENT ))% for JVM non-heap + tshark/ndpi/Suricata"
echo "  Max upload size      = $(( MAX_UPLOAD_BYTES / 1024 / 1024 )) MB"
echo "  Analysis timeout     = ${TIMEOUT} s"

# shellcheck disable=SC2086 # JVM_MEM_OPTS is intentionally word-split into separate flags
exec gosu spring java \
  ${JVM_MEM_OPTS} \
  -DMAX_UPLOAD_SIZE_BYTES=${MAX_UPLOAD_BYTES} \
  -DANALYSIS_TIMEOUT_SECONDS=${TIMEOUT} \
  -jar app.jar
