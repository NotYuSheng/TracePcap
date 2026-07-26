#!/bin/sh
set -e

# Must mirror the BACKEND's effective memory budget, not this container's own. nginx cannot read
# the backend's cgroup limit (different container), so BACKEND_MEM_LIMIT is passed in and the same
# precedence rule as backend/docker-entrypoint.sh is applied here: the enforced backend cap wins
# over APP_MEMORY_MB when the two differ.
#
# If this diverges from the backend, nginx accepts a body that Spring's max-file-size then
# rejects — the user waits out a full multi-hundred-MB upload only to fail at the end, and
# /system/limits (which reports the backend's value) disagrees with what the edge allows.
MEM=${APP_MEMORY_MB:-2048}

# BACKEND_MEM_LIMIT is a docker memory string (e.g. "1g", "512m", "2048m", or plain bytes).
# Normalise to MB; anything unparseable falls back to APP_MEMORY_MB rather than guessing.
if [ -n "${BACKEND_MEM_LIMIT}" ]; then
  case "${BACKEND_MEM_LIMIT}" in
    *[gG]) EFFECTIVE_MEM_MB=$(( ${BACKEND_MEM_LIMIT%[gG]} * 1024 )) ;;
    *[mM]) EFFECTIVE_MEM_MB=${BACKEND_MEM_LIMIT%[mM]} ;;
    *[kK]) EFFECTIVE_MEM_MB=$(( ${BACKEND_MEM_LIMIT%[kK]} / 1024 )) ;;
    *[0-9]) EFFECTIVE_MEM_MB=$(( BACKEND_MEM_LIMIT / 1024 / 1024 )) ;;
    *)     EFFECTIVE_MEM_MB=${MEM} ;;
  esac
  # Guard against a malformed value collapsing the limit to 0.
  [ "${EFFECTIVE_MEM_MB}" -gt 0 ] 2>/dev/null || EFFECTIVE_MEM_MB=${MEM}
else
  EFFECTIVE_MEM_MB=${MEM}
fi

# Max upload = 25% of the effective backend budget, in MB
MAX_UPLOAD_MB=$(( EFFECTIVE_MEM_MB * 25 / 100 ))

# Nginx body limit = max upload + 50 MB multipart overhead buffer
NGINX_MAX_BODY_SIZE="$(( MAX_UPLOAD_MB + 50 ))M"

# Proxy timeout = max(45% of the effective backend budget, LLM_TIMEOUT + 60s buffer), floor 300s.
# Same budget as the backend's ANALYSIS_TIMEOUT_SECONDS so the proxy cannot time out first.
NGINX_PROXY_TIMEOUT=$(( EFFECTIVE_MEM_MB * 45 / 100 ))
if [ "$NGINX_PROXY_TIMEOUT" -lt 300 ]; then NGINX_PROXY_TIMEOUT=300; fi
LLM_TIMEOUT_S=${LLM_TIMEOUT:-300}
LLM_PROXY_TIMEOUT=$(( LLM_TIMEOUT_S + 60 ))
if [ "$NGINX_PROXY_TIMEOUT" -lt "$LLM_PROXY_TIMEOUT" ]; then NGINX_PROXY_TIMEOUT=$LLM_PROXY_TIMEOUT; fi

export NGINX_MAX_BODY_SIZE
export NGINX_PROXY_TIMEOUT

echo "TracePcap nginx starting:"
echo "  APP_MEMORY_MB    = ${MEM} MB"
echo "  Backend budget   = ${EFFECTIVE_MEM_MB} MB (drives upload limit + proxy timeout)"
if [ "${EFFECTIVE_MEM_MB}" -ne "${MEM}" ]; then
  echo "  NOTE: mirroring BACKEND_MEM_LIMIT (${BACKEND_MEM_LIMIT}) rather than APP_MEMORY_MB so the"
  echo "        edge body limit matches what the backend will actually accept."
fi
echo "  Max upload size  = ${MAX_UPLOAD_MB} MB"
echo "  Nginx body limit = ${NGINX_MAX_BODY_SIZE}"
echo "  Proxy timeout    = ${NGINX_PROXY_TIMEOUT} s"

envsubst '${NGINX_MAX_BODY_SIZE} ${NGINX_PROXY_TIMEOUT}' \
  < /etc/nginx/templates/nginx.conf.template \
  > /etc/nginx/conf.d/default.conf

exec "$@"
