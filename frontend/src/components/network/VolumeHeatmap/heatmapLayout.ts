/**
 * Grid geometry for the volume heatmap.
 *
 * Split out from the component so the sizing rules can be reasoned about (and
 * exercised) on their own — the matrix is O(N²) and how a cell is sized is the
 * difference between a readable grid and an unusable one.
 */

/**
 * Sanity ceiling on axis size. Not a rendering limit — the canvas copes with far
 * more — but past this point a cell is well under a pixel and the matrix has
 * stopped conveying anything, so there is no reason to keep going.
 */
export const MAX_AXIS_HOSTS = 1000;

/** Cell size bounds, in CSS px. The grid is fitted to its container between these. */
export const MIN_CELL = 2;
export const MAX_CELL = 22;
/** Below this cell size, axis labels are unreadable and are dropped. */
export const LABEL_MIN_CELL = 9;

/** Zoom stops, in px per cell. Fine at the bottom, where 1px matters most. */
export const ZOOM_STEPS = [2, 3, 4, 6, 8, 10, 14, 18, 22];

export const LABEL_GUTTER = { x: 140, y: 96 };
export const BARE_GUTTER = { x: 8, y: 8 };

export function clamp(v: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, v));
}

export interface HeatmapLayout {
  cellSize: number;
  gutterX: number;
  gutterY: number;
  labels: boolean;
}

/**
 * Fits the grid to the available width, or honours an explicit zoom.
 *
 * Labels need a gutter, but the gutter competes with the grid for that width, so
 * the fitted path resolves the circularity by trying the labelled layout first
 * and falling back to a bare one when the resulting cells would be too small to
 * label anyway.
 */
export function computeLayout(width: number, n: number, override?: number | null): HeatmapLayout {
  // An explicit zoom wins over fitting: the user has asked for a specific cell
  // size, and the container scrolls to accommodate it.
  if (override != null) {
    const cellSize = clamp(override, MIN_CELL, MAX_CELL);
    const labels = cellSize >= LABEL_MIN_CELL;
    return {
      cellSize,
      gutterX: labels ? LABEL_GUTTER.x : BARE_GUTTER.x,
      gutterY: labels ? LABEL_GUTTER.y : BARE_GUTTER.y,
      labels,
    };
  }

  if (n === 0 || width <= 0) {
    return { cellSize: MAX_CELL, gutterX: LABEL_GUTTER.x, gutterY: LABEL_GUTTER.y, labels: true };
  }

  const labelled = clamp(Math.floor((width - LABEL_GUTTER.x - 2) / n), MIN_CELL, MAX_CELL);
  if (labelled >= LABEL_MIN_CELL) {
    return { cellSize: labelled, gutterX: LABEL_GUTTER.x, gutterY: LABEL_GUTTER.y, labels: true };
  }

  const bare = clamp(Math.floor((width - BARE_GUTTER.x - 2) / n), MIN_CELL, MAX_CELL);
  return { cellSize: bare, gutterX: BARE_GUTTER.x, gutterY: BARE_GUTTER.y, labels: false };
}
