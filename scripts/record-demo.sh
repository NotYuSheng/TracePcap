#!/usr/bin/env bash
#
# Records the README demo GIF end to end:
#   Playwright drives the app and records WebM -> ffmpeg encodes an optimized GIF.
#
# Prerequisites:
#   - the stack is up:            docker compose up -d --build
#   - Playwright chromium:        (cd frontend && npx playwright install chromium)
#   - ffmpeg on PATH:             sudo apt install ffmpeg
#
# Usage: scripts/record-demo.sh [output.gif]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$REPO_ROOT/sample-files/TracePcap-Demo.gif}"
VIDEO_DIR="$REPO_ROOT/frontend/test-results"
BASE_URL="${E2E_BASE_URL:-http://localhost:8888}"

# Tuning knobs. 800px matches the previous README GIF; 10fps/128 colors keeps a
# ~25s walkthrough near ~3MB, which is about where GitHub stops rendering it
# promptly. Raising any of these grows the file fast — check the printed size.
WIDTH="${DEMO_WIDTH:-800}"
FPS="${DEMO_FPS:-10}"
MAX_COLORS="${DEMO_COLORS:-96}"

command -v ffmpeg >/dev/null || { echo "error: ffmpeg not found. sudo apt install ffmpeg" >&2; exit 1; }

if ! curl -fsS -o /dev/null "$BASE_URL/" 2>/dev/null; then
  echo "error: app not reachable at $BASE_URL — run 'docker compose up -d' first." >&2
  exit 1
fi

# The demo seeds its own data and expects an otherwise-empty stack. Node roles
# are keyed by file_id (not network_id), so pre-existing labels on the sample
# captures show up in the GIF, and the recording writes labels back into files
# other networks share. Warn rather than block: the operator may be re-recording
# on a stack the demo itself populated, which is fine.
NETWORK_COUNT="$(curl -fsS "$BASE_URL/api/v1/monitor/networks" 2>/dev/null \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);console.log((Array.isArray(j)?j:j.data??[]).length)}catch{console.log(0)}})' || echo 0)"
if [ "${NETWORK_COUNT:-0}" -gt 1 ]; then
  echo "warning: $NETWORK_COUNT monitor networks already exist." >&2
  echo "         The demo records best against an empty stack:" >&2
  echo "           docker compose down -v && docker compose up -d" >&2
  echo "         (this destroys all uploaded pcaps and monitor data)" >&2
fi

echo "==> Recording walkthrough (Playwright)"
# Clear stale videos so the newest-file pick below can't grab a previous run's.
rm -rf "$VIDEO_DIR"
(cd "$REPO_ROOT/frontend" && npm run demo:record)

WEBM="$(find "$VIDEO_DIR" -name '*.webm' -type f -print0 2>/dev/null | xargs -0 ls -t 2>/dev/null | head -1 || true)"
[ -n "$WEBM" ] || { echo "error: no video produced under $VIDEO_DIR" >&2; exit 1; }
echo "==> Captured $WEBM"

PALETTE="$(mktemp --suffix=.png)"
TRIMMED="$(mktemp --suffix=.mp4)"
trap 'rm -f "$PALETTE" "$TRIMMED"' EXIT

# Fast-forward the dead spans the spec logged (LLM waits, mostly). This is a
# separate pass on purpose: the trim/concat graph has to run before fps/scale,
# and mixing it into the palette passes below makes the filter graph unreadable.
TIMELINE="$VIDEO_DIR/demo-timeline.json"
DURATION="$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$WEBM")"
FF_FILTER="$(node "$REPO_ROOT/scripts/build-ff-filter.mjs" "$TIMELINE" "$DURATION" || true)"
if [ -n "$FF_FILTER" ]; then
  echo "==> Fast-forwarding waits:"
  node -e '
    const {spans} = require(process.argv[1]);
    for (const s of spans) {
      console.log(`      ${s.label}: ${(s.end-s.start).toFixed(1)}s at ${s.speed}x`);
    }
  ' "$TIMELINE"
  ffmpeg -v error -y -i "$WEBM" -filter_complex "$FF_FILTER" -map "[ff]" "$TRIMMED"
  SOURCE="$TRIMMED"
  echo "==> Runtime ${DURATION}s -> $(ffprobe -v error -show_entries format=duration -of csv=p=0 "$SOURCE")s"
else
  SOURCE="$WEBM"
fi

echo "==> Encoding GIF (${WIDTH}px, ${FPS}fps, ${MAX_COLORS} colors)"

# Two passes: build a palette tuned to this video, then apply it. A single-pass
# GIF uses a generic palette and visibly banners flat UI backgrounds.
FILTERS="fps=${FPS},scale=${WIDTH}:-1:flags=lanczos"
ffmpeg -v error -y -i "$SOURCE" \
  -vf "${FILTERS},palettegen=max_colors=${MAX_COLORS}:stats_mode=diff" "$PALETTE"

# dither=none is both smaller and sharper here (measured: ~700KB cheaper than
# bayer). Dithering pays off on photographic gradients; on flat UI panels its
# pattern perturbs pixels across otherwise-identical frames, which defeats GIF
# inter-frame compression. diff_mode=rectangle then skips the unchanged region
# between held frames.
ffmpeg -v error -y -i "$SOURCE" -i "$PALETTE" \
  -lavfi "${FILTERS}[x];[x][1:v]paletteuse=dither=none:diff_mode=rectangle" \
  -loop 0 "$OUT"

echo "==> Wrote $OUT ($(du -h "$OUT" | cut -f1))"
