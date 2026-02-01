#!/bin/sh
set -e

# Convert MAX_UPLOAD_SIZE_BYTES to MB for nginx
# Default to 536870912 bytes (512MB) if not set
BYTES=${MAX_UPLOAD_SIZE_BYTES:-536870912}

# Convert bytes to MB (divide by 1024^2)
# Using awk for floating point division
MAX_UPLOAD_SIZE_NGINX=$(awk "BEGIN {printf \"%.0fM\", $BYTES / 1024 / 1024}")

# Export for envsubst
export MAX_UPLOAD_SIZE_NGINX

# Substitute environment variables in nginx config template
envsubst '${MAX_UPLOAD_SIZE_NGINX}' < /etc/nginx/templates/nginx.conf.template > /etc/nginx/conf.d/default.conf

# Execute the main command (start nginx)
exec "$@"
