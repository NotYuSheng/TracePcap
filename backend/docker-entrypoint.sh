#!/bin/sh
set -e

MEM=${APP_MEMORY_MB:-2048}

# JVM heap = 75% of APP_MEMORY_MB
JVM_HEAP_MB=$(( MEM * 75 / 100 ))

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

echo "TracePcap backend starting:"
echo "  APP_MEMORY_MB        = ${MEM} MB"
echo "  JVM heap (-Xms/-Xmx) = ${JVM_HEAP_MB} MB"
echo "  Max upload size      = $(( MAX_UPLOAD_BYTES / 1024 / 1024 )) MB"
echo "  Analysis timeout     = ${TIMEOUT} s"

exec gosu spring java \
  -Xmx${JVM_HEAP_MB}m \
  -Xms${JVM_HEAP_MB}m \
  -DMAX_UPLOAD_SIZE_BYTES=${MAX_UPLOAD_BYTES} \
  -DANALYSIS_TIMEOUT_SECONDS=${TIMEOUT} \
  -jar app.jar
