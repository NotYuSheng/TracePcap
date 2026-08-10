#!/usr/bin/env bash
# check-env-passthrough.sh
#
# Fails if the backend reads an environment variable that no compose file passes
# into the container.
#
# This failure mode is silent: the variable is documented, an operator sets it in
# .env, nothing happens, and the deployment quietly runs on the default. It has
# shipped twice — the retention settings (#628) and eleven more including
# CORS_ALLOWED_ORIGINS and GEO_ENRICHMENT_ENABLED (#641) — so it is worth a check
# rather than a third discovery.
#
# Usage:  bash scripts/check-env-passthrough.sh
# Exit:   0 clean, 1 unreachable variables found

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP=backend/src/main/resources/application.yml
COMPOSE=(docker-compose.yml docker-compose.offline.yml
         docker-compose.prod.yml docker-compose.offline-prod.yml)

# Variables the container gets by other legitimate means. Each needs a reason —
# if you are adding to this list, be sure it is genuinely supplied, not merely
# unimportant.
declare -A EXEMPT=(
  [MAX_UPLOAD_SIZE_BYTES]="passed as -D by backend/docker-entrypoint.sh, derived from the memory budget"
  [ANALYSIS_TIMEOUT_SECONDS]="passed as -D by backend/docker-entrypoint.sh, derived from the memory budget"
  [SERVER_PORT]="internal; fixed at 8080 behind nginx"
  [SPRING_PROFILES_ACTIVE]="set per compose file to select the profile"
)

mapfile -t READ < <(grep -oE '\$\{[A-Z][A-Z0-9_]*[:}]' "$APP" \
                    | tr -d '${:}' | sort -u)

# Check each deployable STACK independently, not the union of all files. A variable
# present only in the offline file is still unreachable in the base stack — the bug
# this exists to catch. Overlays are checked with the base they layer on.
declare -A STACKS=(
  ["base"]="docker-compose.yml docker-compose.prod.yml"
  ["offline"]="docker-compose.offline.yml docker-compose.offline-prod.yml"
)

missing=()
for stack in "${!STACKS[@]}"; do
  # shellcheck disable=SC2086
  passed="$(grep -hoE '^\s{6}[A-Z][A-Z0-9_]*:|\$\{[A-Z][A-Z0-9_]*[:}]' ${STACKS[$stack]} \
            | tr -d '${:} ' | sort -u)"
  for v in "${READ[@]}"; do
    [[ -n "${EXEMPT[$v]+x}" ]] && continue
    grep -qx "$v" <<<"$passed" || missing+=("$stack:$v")
  done
done

if [[ ${#missing[@]} -eq 0 ]]; then
  echo "OK — every variable $APP reads is passed by a compose file (or exempt)."
  exit 0
fi

echo "FAIL — the backend reads these, but no compose file passes them in."
echo "They are unreachable: setting them in .env has no effect."
echo
for entry in "${missing[@]}"; do
  printf '  %-10s %s\n' "${entry%%:*} stack" "${entry#*:}"
done
echo
echo "Fix: add each to the backend environment in docker-compose.yml (and"
echo "docker-compose.offline.yml), using \${VAR:-default} with the default from"
echo "$APP. If it is supplied another way, add it to EXEMPT here with the reason."
exit 1
