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

# Validate before use: this value is interpolated into arithmetic and into -XX:MaxRAMPercentage.
# A non-numeric value would abort mid-script under `set -e`, and a value >90 would size the heap
# at or above the cgroup limit — an immediate OOM-kill that `restart: unless-stopped` converts
# into a crash loop. Fail loudly here instead, where the reason is visible in the logs.
case "${JVM_HEAP_PERCENT}" in
  ''|*[!0-9]*)
    echo "FATAL: JVM_HEAP_PERCENT must be an integer, got '${JVM_HEAP_PERCENT}'" >&2
    exit 1 ;;
esac
if [ "${JVM_HEAP_PERCENT}" -lt 10 ] || [ "${JVM_HEAP_PERCENT}" -gt 90 ]; then
  echo "FATAL: JVM_HEAP_PERCENT must be between 10 and 90, got ${JVM_HEAP_PERCENT}. Above ~90 leaves" >&2
  echo "       no room for JVM non-heap + native tshark/ndpi/Suricata and will OOM-kill the container." >&2
  exit 1
fi

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
  # Unlimited ("max", empty, or the cgroup v1 no-limit sentinel): no enforced limit to read.
  # v1 reports PAGE_COUNTER_MAX (LONG_MAX rounded down to a page multiple), which varies with page
  # size, so match the two known 19-digit forms rather than a length-based glob.
  ''|max|9223372036854771712|9223372036854775807)
    MEM_MODE="APP_MEMORY_MB (no container memory limit detected)"
    EFFECTIVE_MEM_MB=${MEM}
    JVM_HEAP_MB=$(( EFFECTIVE_MEM_MB * JVM_HEAP_PERCENT / 100 ))
    JVM_MEM_OPTS="-Xms${JVM_HEAP_MB}m -Xmx${JVM_HEAP_MB}m"
    ;;
  *)
    EFFECTIVE_MEM_MB=$(( CGROUP_LIMIT_BYTES / 1024 / 1024 ))
    MEM_MODE="cgroup limit (${EFFECTIVE_MEM_MB} MB)"
    JVM_HEAP_MB=$(( EFFECTIVE_MEM_MB * JVM_HEAP_PERCENT / 100 ))
    # InitialRAMPercentage mirrors Max so the heap is still pre-committed, matching the previous
    # -Xms == -Xmx behaviour (no heap-growth pauses mid-analysis).
    JVM_MEM_OPTS="-XX:InitialRAMPercentage=${JVM_HEAP_PERCENT} -XX:MaxRAMPercentage=${JVM_HEAP_PERCENT}"
    ;;
esac

# Everything below derives from EFFECTIVE_MEM_MB — the budget actually enforced on this container —
# NOT from APP_MEMORY_MB. These must not diverge: if the cgroup limit is lowered below
# APP_MEMORY_MB (e.g. BACKEND_MEM_LIMIT=1g with APP_MEMORY_MB=2048), sizing the upload from
# APP_MEMORY_MB would permit a 512 MB upload inside a 1024 MB container whose heap already claims
# 512 MB — consuming the entire native headroom this change exists to protect. Deriving both from
# the same effective budget keeps the 50/25 split coherent at any limit.
#
# Max upload = 25% of the effective budget, expressed in bytes
# 16%, not 25%: stage 2 holds the whole capture in heap, so an accepted file must fit in a
# third of it (#92's original rule). That held when the heap was 75%; #586 lowered it to 50%
# for native subprocesses without revisiting this, and a 468MB capture was accepted and then
# died of OutOfMemoryError 25 minutes into parsing (#779). scripts/check_memory_budget.py
# now fails the build if these two drift apart again.
MAX_UPLOAD_BYTES=$(( EFFECTIVE_MEM_MB * 16 / 100 * 1024 * 1024 ))

# Analysis/proxy timeout: 45% of the effective budget, clamped to [300, 900] seconds
TIMEOUT=$(( EFFECTIVE_MEM_MB * 45 / 100 ))
if [ "$TIMEOUT" -lt 300 ]; then TIMEOUT=300; fi
if [ "$TIMEOUT" -gt 900 ]; then TIMEOUT=900; fi

# Max length (chars) of a single JSON string value across the API — currently only reachable via
# the PDF report's base64-encoded topology diagram, which a dense capture can inflate past
# Jackson's own fixed 20MB default. That default doesn't know how much heap it's borrowing
# against, so it's too generous on a small deployment and an arbitrary ceiling on a large one.
# 2.5% of the effective budget, clamped to [8, 256] MB (#792). Unlike the upload path, parsing
# one JSON string only needs a small multiple of its own size in transient buffer growth (no
# whole-capture object graph held alongside it), so this stays well under the heap fraction the
# upload cap uses — see MAX_UPLOAD_BYTES above.
#
# GlobalExceptionHandler mirrors this formula (divisor 40, clamp 256) to recommend an
# APP_MEMORY_MB when a request trips the cap — keep the two in sync if this changes.
JACKSON_MAX_STRING_MB=$(( EFFECTIVE_MEM_MB / 40 ))
if [ "$JACKSON_MAX_STRING_MB" -lt 8 ]; then JACKSON_MAX_STRING_MB=8; fi
if [ "$JACKSON_MAX_STRING_MB" -gt 256 ]; then JACKSON_MAX_STRING_MB=256; fi
JACKSON_MAX_STRING_BYTES=$(( JACKSON_MAX_STRING_MB * 1024 * 1024 ))

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
echo "  Effective budget     = ${EFFECTIVE_MEM_MB} MB (drives heap, upload and timeout)"
if [ "${EFFECTIVE_MEM_MB}" -ne "${MEM}" ]; then
  echo "  NOTE: the enforced container limit differs from APP_MEMORY_MB (${MEM} MB); the enforced"
  echo "        limit wins so upload/timeout stay in proportion to the memory actually available."
fi
echo "  JVM heap             = ${JVM_HEAP_MB} MB (${JVM_HEAP_PERCENT}% of budget)"
echo "  Native headroom      = $(( 100 - JVM_HEAP_PERCENT ))% for JVM non-heap + tshark/ndpi/Suricata"
echo "  Max upload size      = $(( MAX_UPLOAD_BYTES / 1024 / 1024 )) MB"
echo "  Analysis timeout     = ${TIMEOUT} s"
echo "  Max JSON string      = ${JACKSON_MAX_STRING_MB} MB (report topology diagram)"

# Die on heap exhaustion instead of limping (#779).
#
# A capture larger than the heap threw OutOfMemoryError inside a request thread and killed Tomcat's
# http-nio-8080-Poller. The container stayed "running" and healthy to `docker compose ps` while
# serving nothing: every API call timed out, and recovery needed a human noticing and restarting it.
# One oversized upload took the service down for everyone, silently.
#
# Exiting turns that into something the platform can act on — `restart: unless-stopped` is set on
# this service, so the container comes back by itself. A JVM whose heap is exhausted has no
# reliable path back to health anyway; the only question is whether the failure is visible.
#
# Deliberately no -XX:+HeapDumpOnOutOfMemoryError: the dump is roughly heap-sized (~1 GB at the
# default budget) and would land on a volume that already has to hold captures. Enable it by hand
# when actually diagnosing one.
JVM_MEM_OPTS="${JVM_MEM_OPTS} -XX:+ExitOnOutOfMemoryError"

# shellcheck disable=SC2086 # JVM_MEM_OPTS is intentionally word-split into separate flags
exec gosu spring java \
  ${JVM_MEM_OPTS} \
  -DMAX_UPLOAD_SIZE_BYTES=${MAX_UPLOAD_BYTES} \
  -DANALYSIS_TIMEOUT_SECONDS=${TIMEOUT} \
  -DJACKSON_MAX_STRING_LENGTH=${JACKSON_MAX_STRING_BYTES} \
  -jar app.jar
