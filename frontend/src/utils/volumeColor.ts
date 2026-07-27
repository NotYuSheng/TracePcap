// Imported from the umbrella `d3` package (a declared dependency with @types/d3)
// rather than `d3-scale`/`d3-interpolate`, which are only present transitively.
// Vite tree-shakes the unused modules out of the bundle.
import { scaleSequentialLog, interpolateRgbBasis } from 'd3';

/**
 * Shared sequential colour scale for traffic **volume** (magnitude).
 *
 * One hue (blue), light→dark, used everywhere volume is encoded as colour:
 * the node-to-node heatmap, volume-coloured diagram edges, Network Intelligence
 * cluster nodes and the country map. Previously each of those hand-rolled its own
 * linear `trafficColor` — this replaces them so a given shade always means the
 * same number across views.
 *
 * Two properties matter and neither was true of the old helper:
 *
 * 1. **Log, not linear.** Traffic volume is heavily skewed — a handful of pairs
 *    carry most of the bytes. A linear ramp yields one dark cell and a wash of
 *    pale ones. `scaleSequentialLog` spreads the mid-range out.
 * 2. **Dark-mode anchors flip.** Magnitude reads as *distance from the surface*,
 *    so on a light surface "loud" is dark blue, and on a dark surface it is
 *    bright blue. A dark-mode ramp is not an inverted light ramp; it is its own.
 *
 * Ramps are validated against the light (#ffffff) and dark (#0d1117) chart
 * surfaces for single-hue, monotone lightness and visible step gaps.
 */

/**
 * Cell ramps — for filled areas (heatmap cells, cluster node backgrounds).
 * The end nearest the surface is deliberately allowed to recede: a near-empty
 * cell should fade into the background rather than assert itself. Matrix
 * structure is carried by the cell gaps, not by the palest fill.
 */
const CELL_RAMP_LIGHT = ['#cde2fb', '#9ec5f4', '#6da7ec', '#3987e5', '#256abf', '#184f95', '#0d366b'];
const CELL_RAMP_DARK = ['#10243d', '#173a63', '#1f5390', '#2a78d6', '#5598e7', '#86b6ef', '#cde2fb'];

/**
 * Edge ramps — for stroked marks (diagram edges).
 * Floored so that even the quietest edge clears ~2:1 against the surface. An
 * edge cannot be allowed to recede the way a cell can: a near-surface stroke on
 * the graph canvas is simply an invisible connection, which would read as "no
 * traffic" rather than "little traffic".
 */
const EDGE_RAMP_LIGHT = ['#86b6ef', '#5598e7', '#256abf', '#184f95', '#0d366b'];
const EDGE_RAMP_DARK = ['#184f95', '#2a78d6', '#5598e7', '#86b6ef', '#cde2fb'];

export type VolumeColorFn = (value: number) => string;

/** The colour used for a zero/absent value, per ramp. */
function floorColor(ramp: string[]): string {
  return ramp[0];
}

/**
 * Normalises a domain to something a log scale can actually span.
 *
 * `minValue` should be the smallest *positive* value in view. Defaulting it to 1
 * would be wrong for real data: byte counts start in the hundreds, so a [1, max]
 * domain spends the bottom half of the ramp on values that never occur and
 * squeezes the real range into what is left — the same wasted-contrast problem
 * the log scale exists to avoid. Fitting the domain to the observed range keeps
 * the whole ramp meaningful.
 */
function domainOf(minValue: number, maxValue: number): [number, number] {
  const lo = Math.max(1, Math.min(minValue, maxValue));
  // A degenerate domain (single distinct value) would make the scale divide by
  // zero; widening it renders that value at the top of the ramp.
  const hi = maxValue > lo ? maxValue : lo * 2;
  return [lo, hi];
}

function makeScale(ramp: string[], minValue: number, maxValue: number): VolumeColorFn {
  const interpolator = interpolateRgbBasis(ramp);
  const scale = scaleSequentialLog(interpolator).domain(domainOf(minValue, maxValue)).clamp(true);
  // Log scales cannot span 0, so absent/zero values are pinned to the floor
  // colour rather than passed through the scale.
  return (value: number) => (value > 0 ? scale(value) : floorColor(ramp));
}

/**
 * Colour scale for filled areas (heatmap cells, cluster nodes).
 *
 * `maxValue`/`minValue` describe the current view — the scale is always relative
 * to what is on screen, so re-filtering re-normalises. Pass `minValue` as the
 * smallest positive value present to use the full ramp.
 */
export function makeVolumeColor(maxValue: number, dark: boolean, minValue = 1): VolumeColorFn {
  return makeScale(dark ? CELL_RAMP_DARK : CELL_RAMP_LIGHT, minValue, maxValue);
}

/** Colour scale for stroked marks (diagram edges) — floored to stay visible. */
export function makeVolumeEdgeColor(maxValue: number, dark: boolean, minValue = 1): VolumeColorFn {
  return makeScale(dark ? EDGE_RAMP_DARK : EDGE_RAMP_LIGHT, minValue, maxValue);
}

/**
 * Ink colour for text sitting *on top of* a volume-filled area.
 * Replaces the `ratio > 0.55 ? '#fff' : '#212529'` heuristics that were inlined
 * at each call site. `ratio` is 0–1 within the ramp, not a raw value.
 */
export function volumeTextColor(ratio: number, dark: boolean): string {
  if (dark) {
    // Dark ramp runs dark→light, so the *high* end is the pale one.
    return ratio > 0.55 ? '#0d1117' : '#e6edf3';
  }
  return ratio > 0.55 ? '#ffffff' : '#212529';
}

/**
 * Where `value` sits along the ramp, 0–1, in the same log space the colour uses.
 *
 * Callers that need to react to "how dark is this fill" — picking ink, say —
 * must use this rather than a plain `value / max`. A linear ratio disagrees with
 * a log fill everywhere except the endpoints, which is exactly how you end up
 * with dark text on a dark cell.
 */
export function volumeRatio(value: number, maxValue: number, minValue = 1): number {
  if (value <= 0) return 0;
  const [lo, hi] = domainOf(minValue, maxValue);
  const r = (Math.log(value) - Math.log(lo)) / (Math.log(hi) - Math.log(lo));
  return Math.max(0, Math.min(1, r));
}

export interface VolumeLegendStop {
  /** 0–1 position along the gradient. */
  offset: number;
  color: string;
}

/**
 * Evenly spaced gradient stops describing a scale, for rendering a legend.
 * Sampled in *log* space so the legend gradient matches what the marks actually
 * do — a linear sample would misrepresent where the mid-tones land.
 */
export function volumeLegendStops(
  maxValue: number,
  dark: boolean,
  variant: 'cell' | 'edge' = 'cell',
  minValue = 1,
  steps = 12,
): VolumeLegendStop[] {
  const color =
    variant === 'edge'
      ? makeVolumeEdgeColor(maxValue, dark, minValue)
      : makeVolumeColor(maxValue, dark, minValue);
  const [lo, hi] = domainOf(minValue, maxValue);

  return Array.from({ length: steps }, (_, i) => {
    const offset = i / (steps - 1);
    // Invert the log scale: the value sitting this fraction along the ramp.
    const value = Math.exp(Math.log(lo) + offset * (Math.log(hi) - Math.log(lo)));
    return { offset, color: color(value) };
  });
}

/** CSS `linear-gradient(...)` string for a legend bar. */
export function volumeGradientCss(
  maxValue: number,
  dark: boolean,
  variant: 'cell' | 'edge' = 'cell',
  minValue = 1,
): string {
  const stops = volumeLegendStops(maxValue, dark, variant, minValue)
    .map(s => `${s.color} ${(s.offset * 100).toFixed(1)}%`)
    .join(', ');
  return `linear-gradient(to right, ${stops})`;
}
