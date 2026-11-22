#!/usr/bin/env node
/**
 * Builds the ffmpeg filter_complex that fast-forwards the dead spans the demo
 * spec recorded in demo-timeline.json, and prints it on stdout.
 *
 * Splitting the video into trim segments and concatenating them is the only
 * approach that gets the timestamps right: setpts has to be applied *per
 * segment* after trim resets each one to zero. A global filter (mpdecimate,
 * a single setpts) rescales the whole timeline instead and stretches the video.
 *
 * Usage: build-ff-filter.mjs <timeline.json> <video-duration-seconds>
 * Prints nothing (exit 0) when there is nothing to speed up, so the caller can
 * fall back to a plain filter chain.
 */
import fs from 'node:fs';

const [, , timelinePath, durationArg] = process.argv;
const duration = Number(durationArg);

if (!timelinePath || !fs.existsSync(timelinePath) || !Number.isFinite(duration)) {
  process.exit(0);
}

const { spans = [] } = JSON.parse(fs.readFileSync(timelinePath, 'utf8'));
const sorted = spans
  .filter(s => s.end > s.start && s.start < duration)
  .map(s => ({ ...s, end: Math.min(s.end, duration) }))
  .sort((a, b) => a.start - b.start);

if (sorted.length === 0) process.exit(0);

// Walk the timeline, alternating normal segments and sped-up spans.
const parts = [];
let cursor = 0;
for (const span of sorted) {
  // Overlapping/rounding artefacts would produce a negative-length trim.
  if (span.start > cursor + 0.05) {
    parts.push({ from: cursor, to: span.start, speed: 1, label: '' });
  }
  parts.push({ from: Math.max(span.start, cursor), to: span.end, speed: span.speed, label: span.label ?? '' });
  cursor = span.end;
}
if (duration > cursor + 0.05) parts.push({ from: cursor, to: duration, speed: 1, label: '' });

// --parts: one "from to speed label" line per segment (the label, possibly empty, is the rest of
// the line: the video captions a sped-up part with it), for cutting them one at a time (the filter below
// decodes once into N trims, and ffmpeg then queues every later segment's frames in memory: on a
// 9-minute recording that filled a 15 GB machine, 2026-11-16).
if (process.argv.includes('--parts')) {
  for (const p of parts) process.stdout.write(`${p.from.toFixed(3)} ${p.to.toFixed(3)} ${p.speed} ${p.label.replace(/\s+/g, ' ')}\n`);
  process.exit(0);
}

const chains = parts.map((p, i) => {
  const pts = p.speed === 1 ? 'PTS-STARTPTS' : `(PTS-STARTPTS)/${p.speed}`;
  return `[0:v]trim=${p.from.toFixed(3)}:${p.to.toFixed(3)},setpts=${pts}[s${i}]`;
});
const labels = parts.map((_, i) => `[s${i}]`).join('');

process.stdout.write(
  `${chains.join(';')};${labels}concat=n=${parts.length}:v=1:a=0[ff]`
);
