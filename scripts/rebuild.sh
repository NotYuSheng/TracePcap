#!/usr/bin/env bash
# Rebuild and restart the stack, building one image at a time.
#
# `docker compose up -d --build` builds every image at once (Compose hands builds to Bake, which
# runs them in parallel), and build steps aren't bound by deploy.resources. Building the backend
# (Maven + an nDPI compile) and the frontend (tsc + vite) together, next to a running stack, has
# frozen a 15 GB machine. The build stages also cap their own heaps (BUILD_* in .env.example).
#
# Usage: scripts/rebuild.sh [extra compose args, e.g. -f docker-compose.yml -f docker-compose.prod.yml]
set -euo pipefail
cd "$(dirname "$0")/.."

compose=(docker compose "$@")
for service in $("${compose[@]}" config --services); do
  # Only services with a build section; the rest are pulled images.
  if "${compose[@]}" config --format json | python3 -c "import json,sys; s=json.load(sys.stdin)['services']['$service']; sys.exit(0 if 'build' in s else 1)"; then
    echo "==> building $service"
    "${compose[@]}" build "$service"
  fi
done
echo "==> starting"
"${compose[@]}" up -d
