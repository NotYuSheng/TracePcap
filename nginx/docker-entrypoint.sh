#!/bin/sh
set -e

MEM=${APP_MEMORY_MB:-2048}

# Max upload = 25% of APP_MEMORY_MB in MB
MAX_UPLOAD_MB=$(( MEM * 25 / 100 ))

# Nginx body limit = max upload + 50 MB multipart overhead buffer
NGINX_MAX_BODY_SIZE="$(( MAX_UPLOAD_MB + 50 ))M"

# Proxy timeout = 45% of APP_MEMORY_MB, clamped to [300, 900] seconds
NGINX_PROXY_TIMEOUT=$(( MEM * 45 / 100 ))
if [ "$NGINX_PROXY_TIMEOUT" -lt 300 ]; then NGINX_PROXY_TIMEOUT=300; fi
if [ "$NGINX_PROXY_TIMEOUT" -gt 900 ]; then NGINX_PROXY_TIMEOUT=900; fi

export NGINX_MAX_BODY_SIZE
export NGINX_PROXY_TIMEOUT

echo "TracePcap nginx starting:"
echo "  APP_MEMORY_MB    = ${MEM} MB"
echo "  Max upload size  = ${MAX_UPLOAD_MB} MB"
echo "  Nginx body limit = ${NGINX_MAX_BODY_SIZE}"
echo "  Proxy timeout    = ${NGINX_PROXY_TIMEOUT} s"

envsubst '${NGINX_MAX_BODY_SIZE} ${NGINX_PROXY_TIMEOUT}' \
  < /etc/nginx/templates/nginx.conf.template \
  > /etc/nginx/conf.d/default.conf

exec "$@"
