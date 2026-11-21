#!/usr/bin/env bash
#
# Records the README demo GIF, or the demo video, end to end:
#   Playwright drives the app and records WebM -> ffmpeg encodes an optimized GIF, or an MP4.
#
# Prerequisites:
#   - the stack is up:            docker compose up -d --build
#   - Playwright chromium:        (cd frontend && npx playwright install chromium)
#   - ffmpeg on PATH:             sudo apt install ffmpeg
#
# Usage: scripts/record-demo.sh [output.gif|output.mp4]
#        DEMO_SPEC=hero scripts/record-demo.sh sample-files/TracePcap-Hero.gif   (the short hero)
#
# An output ending in .mp4 writes the video instead (the YouTube demo the README's GIFs link to):
# the recording's native 1280x720 at 25 fps, H.264, no sound, and each fast-forwarded wait captioned
# ("Fast-forwarded 120x · Story being written") so a viewer knows time was skipped. Size knobs
# below are GIF-only. Record once and encode both from it:
#   scripts/record-demo.sh demo.mp4 && DEMO_ENCODE_ONLY=1 scripts/record-demo.sh sample-files/TracePcap-Demo.gif
# The video isn't committed (YouTube hosts it); the GIF is.
#
# The README walkthrough (2026-11-16) is the STRRAT incident from docs/demos/strrat-you-dirty-rat.rst,
# which isn't committed (real malware traffic). Download it as that page says, convert it to pcapng
# (a new hash, so it doesn't clash with an existing upload), then:
#   DEMO_CAPTURE=/path/strrat-you-dirty-rat.pcapng \
#   DEMO_QUESTION="Which host is the victim, and what is it talking to? Give me a Wireshark filter for the C2 traffic." \
#   E2E_BASE_URL=http://localhost DEMO_WIDTH=960 DEMO_FPS=6 DEMO_COLORS=128 DEMO_LOSSY=80 \
#   scripts/record-demo.sh sample-files/TracePcap-Demo.gif
# The story's wait was then re-encoded at 120x (edit its span's speed in
# frontend/test-results/demo-timeline.json) with DEMO_ENCODE_ONLY=1, which re-encodes the last
# recording without recording again. 960px, 100s, 7.8 MB.
# Re-recorded 2026-11-21 as strrat-infection.pcapng (a fresh name and hash: the recording deletes
# any upload with the demo's name, and the operator's own strrat-you-dirty-rat.pcapng is starred
# and kept). The MP4 from the same take is the YouTube demo. 82 s: GIF 7.8 MB, MP4 9.9 MB.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$REPO_ROOT/sample-files/TracePcap-Demo.gif}"
case "$OUT" in *.mp4) VIDEO=1 ;; *) VIDEO=0 ;; esac
VIDEO_DIR="$REPO_ROOT/frontend/test-results"
BASE_URL="${E2E_BASE_URL:-http://localhost:8888}"

# Tuning knobs for the full eleven-section walkthrough (~118s once the LLM waits
# are raced). Expect ~5MB, which GitHub renders inline fine (the limit is ~10MB).
# Check the printed size after any change.
#
# Per-10s-segment cost is near-uniform, so there is no expensive section to trim:
# the levers here are all global. Measured on the current walkthrough, against
# the fast-forwarded source:
#             256c   128c
#   640/6fps   7.2M   5.3M
#   640/5fps     —    5.0M
#   560/6fps     —    4.8M
#   480/6fps     —    3.3M
# Resolution is the weakest lever and the most costly: this is a UI demo, so text
# legibility is the point, and 480px starts to blur it.
#
# MAX_COLORS is the strongest lever. 256 -> 128 costs ~40dB PSNR on the worst
# frames (topology, world map, pie charts) — the colour-coded views still read
# correctly — and saves ~2MB. Below 96 the graph visibly posterises. Raise it
# with DEMO_COLORS=256 if the gradients matter more than the download.
WIDTH="${DEMO_WIDTH:-640}"
# Seconds to skip at the start of the (fast-forwarded) video, e.g. a sliver of a loading spinner.
# The first frame is what many sites use as the GIF's preview.
START="${DEMO_START:-0}"
FPS="${DEMO_FPS:-6}"
MAX_COLORS="${DEMO_COLORS:-128}"
# Optional gifsicle lossy pass (0 = off). GitHub caps README images and GIFs at
# 10MB, and the lossy pass is what lets a native-resolution (1280px) clip fit:
# the hero at 1280px/8fps/128c is 13MB plain, 7.2MB at DEMO_LOSSY=60, with no
# visible damage to text or the graph. Needs gifsicle (sudo apt install gifsicle).
LOSSY="${DEMO_LOSSY:-0}"

command -v ffmpeg >/dev/null || { echo "error: ffmpeg not found. sudo apt install ffmpeg" >&2; exit 1; }
if [ "$LOSSY" != "0" ]; then
  command -v gifsicle >/dev/null || { echo "error: DEMO_LOSSY needs gifsicle. sudo apt install gifsicle" >&2; exit 1; }
fi

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

if [ "${DEMO_ENCODE_ONLY:-0}" = "1" ]; then
  # Re-encode the last recording (and its timeline) without recording again.
  echo "==> Encoding the existing recording under $VIDEO_DIR"
else
  # A recording runs a video-recording browser while the stack analyses a capture: it needs headroom.
  "$REPO_ROOT/scripts/mem-guard.sh" "the demo recording" 5

  echo "==> Recording walkthrough (Playwright)"
  # Clear stale videos so the newest-file pick below can't grab a previous run's.
  rm -rf "$VIDEO_DIR"
  # DEMO_SPEC=hero records the short network-diagram GIF instead of the full walkthrough.
  if [ "${DEMO_SPEC:-demo}" = "hero" ]; then
    (cd "$REPO_ROOT/frontend" && npm run demo:hero)
  else
    (cd "$REPO_ROOT/frontend" && npm run demo:record)
  fi
fi

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
  # One segment at a time, each from a seek: a single filter graph with one trim per segment makes
  # ffmpeg queue the later segments' decoded frames in memory (a 9-minute recording filled a 15 GB
  # machine). Each part is encoded on its own, then the parts are joined without re-encoding.
  PARTS_DIR="$(mktemp -d)"
  trap 'rm -rf "$PALETTE" "$TRIMMED" "$PARTS_DIR"' EXIT
  i=0
  while read -r from to speed label; do
    part="$PARTS_DIR/part$(printf %03d $i).mp4"
    vf="setpts=(PTS-STARTPTS)/${speed}"
    if [ "$VIDEO" = "1" ] && [ "$speed" != "1" ]; then
      # The caption comes from a file: a label's colons, commas and quotes would need escaping
      # inside the filter graph.
      printf 'Fast-forwarded %sx · %s' "$speed" "${label:-waiting}" > "$PARTS_DIR/caption$i.txt"
      vf="$vf,drawtext=textfile=$PARTS_DIR/caption$i.txt:font=Sans:fontsize=22:fontcolor=white:box=1:boxcolor=0x1f2937@0.85:boxborderw=12:x=w-tw-28:y=h-th-28"
    fi
    ffmpeg -nostdin -v error -y -ss "$from" -to "$to" -i "$WEBM" -an \
      -vf "$vf" -r 25 -c:v libx264 -preset veryfast -crf 18 -pix_fmt yuv420p "$part"
    echo "file '$part'" >> "$PARTS_DIR/list.txt"
    i=$((i + 1))
  done < <(node "$REPO_ROOT/scripts/build-ff-filter.mjs" "$TIMELINE" "$DURATION" --parts)
  ffmpeg -v error -y -f concat -safe 0 -i "$PARTS_DIR/list.txt" -c copy "$TRIMMED"
  SOURCE="$TRIMMED"
  echo "==> Runtime ${DURATION}s -> $(ffprobe -v error -show_entries format=duration -of csv=p=0 "$SOURCE")s"
else
  SOURCE="$WEBM"
fi

if [ "$VIDEO" = "1" ]; then
  echo "==> Encoding MP4 (native size, H.264)"
  # High quality for an upload that YouTube re-encodes anyway; faststart so it plays while loading.
  ffmpeg -v error -y -ss "$START" -i "$SOURCE" -an -r 25 -c:v libx264 -preset slow -crf 16 \
    -pix_fmt yuv420p -movflags +faststart "$OUT"
  echo "==> Wrote $OUT ($(du -h "$OUT" | cut -f1), $(ffprobe -v error -show_entries format=duration -of csv=p=0 "$OUT")s)"
  exit 0
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
ffmpeg -v error -y -ss "$START" -i "$SOURCE" \
  -vf "${FILTERS},palettegen=max_colors=${MAX_COLORS}:stats_mode=full" "$PALETTE"

# dither=none is both smaller and sharper here (measured: ~700KB cheaper than
# bayer). Dithering pays off on photographic gradients; on flat UI panels its
# pattern perturbs pixels across otherwise-identical frames, which defeats GIF
# inter-frame compression. diff_mode=rectangle then skips the unchanged region
# between held frames.
ffmpeg -v error -y -ss "$START" -i "$SOURCE" -i "$PALETTE" \
  -lavfi "${FILTERS}[x];[x][1:v]paletteuse=dither=none:diff_mode=rectangle" \
  -loop 0 "$OUT"

if [ "$LOSSY" != "0" ]; then
  echo "==> gifsicle -O3 --lossy=${LOSSY}"
  gifsicle -O3 --lossy="$LOSSY" -b "$OUT"
fi

echo "==> Wrote $OUT ($(du -h "$OUT" | cut -f1))"
