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

# Tuning knobs for the full eleven-section walkthrough (~75s once the LLM waits
# are raced). Expect ~7MB. That is above the ~3MB where GitHub renders a GIF
# promptly — the walkthrough covers the whole product, and cutting it to 3MB
# means cutting sections, not settings. Check the printed size after any change.
#
# Per-10s-segment cost is near-uniform (0.6–1.6MB), so there is no expensive
# section to trim: the levers here are all global. Measured on this walkthrough,
# against the fast-forwarded source:
#           256c    128c
#   640/6fps  9.1M   6.6M
#   640/5fps  8.2M   6.2M
#   560/6fps  7.5M     —
#   480/6fps  5.8M     —
# Resolution is the weakest lever of the three and the most costly: this is a UI
# demo, so text legibility is the point, and 480px starts to blur it.
#
# MAX_COLORS is the strongest lever, contrary to what a single-frame measurement
# suggests. The topology graph does carry ~15k distinct colours in one frame, but
# it is a few seconds of a 75s tour; across the whole walkthrough 256->128 costs
# ~40dB PSNR on the *worst* frames (topology, world map, pie charts) — visually
# indistinguishable — and saves 2.5MB. Going below 96 does start to posterise the
# graph, so 128 is the floor worth taking.
WIDTH="${DEMO_WIDTH:-640}"
FPS="${DEMO_FPS:-6}"
MAX_COLORS="${DEMO_COLORS:-128}"

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
# stats_mode=full, not diff: `diff` weights the palette toward pixels that change
# between frames, which on a mostly-static UI means colours that appear only
# briefly (a chart, a highlighted badge) get approximated from the palette of
# whatever was on screen longest. Measured across a moving clip, `full` tracks
# the source more closely (mean error 1.58 vs 1.69 per channel) for ~12% more
# bytes — worth it, since colour drift is the thing viewers notice.
ffmpeg -v error -y -i "$SOURCE" \
  -vf "${FILTERS},palettegen=max_colors=${MAX_COLORS}:stats_mode=full" "$PALETTE"

# dither=none is both smaller and sharper here (measured: ~700KB cheaper than
# bayer). Dithering pays off on photographic gradients; on flat UI panels its
# pattern perturbs pixels across otherwise-identical frames, which defeats GIF
# inter-frame compression. diff_mode=rectangle then skips the unchanged region
# between held frames.
ffmpeg -v error -y -i "$SOURCE" -i "$PALETTE" \
  -lavfi "${FILTERS}[x];[x][1:v]paletteuse=dither=none:diff_mode=rectangle" \
  -loop 0 "$OUT"

echo "==> Wrote $OUT ($(du -h "$OUT" | cut -f1))"
