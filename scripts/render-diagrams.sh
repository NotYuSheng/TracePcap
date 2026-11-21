#!/usr/bin/env bash
# Renders the architecture diagrams (docs/architecture/c4/*.puml) to SVG next to each source.
#
#   scripts/render-diagrams.sh           render
#   scripts/render-diagrams.sh --check   fail if a committed SVG doesn't match its .puml (CI)
#
# Uses a pinned PlantUML image, so no Java is needed and every machine draws the same SVG. The
# diagrams include the C4 library bundled inside PlantUML (!include <C4/...>), and the container
# runs with no network: rendering never fetches anything.
set -euo pipefail

IMAGE="plantuml/plantuml:1.2025.4"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/docs/architecture/c4"

render() {
  local out="$1"
  docker run --rm --network none -u "$(id -u):$(id -g)" -v "$out:/w" "$IMAGE" -tsvg /w/*.puml >/dev/null
}

if [[ "${1:-}" == "--check" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cp "$DIR"/*.puml "$tmp"/
  chmod a+rwx "$tmp"
  render "$tmp"
  stale=0
  for svg in "$tmp"/*.svg; do
    name="$(basename "$svg")"
    if ! cmp -s "$svg" "$DIR/$name"; then
      echo "stale: docs/architecture/c4/$name doesn't match its .puml"
      stale=1
    fi
  done
  if [[ $stale -ne 0 ]]; then
    echo "Run scripts/render-diagrams.sh and commit the SVGs."
    exit 1
  fi
  echo "Diagrams are up to date."
else
  render "$DIR"
  echo "Rendered: $(cd "$DIR" && ls *.svg | tr '\n' ' ')"
fi
