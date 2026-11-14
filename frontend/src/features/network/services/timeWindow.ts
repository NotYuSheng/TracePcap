import type { GraphEdge } from '../types';

/** A time window on the capture, epoch ms, inclusive. */
export interface TimeWindow {
  from: number;
  to: number;
}

const startOf = (e: GraphEdge) => e.data.startTime;
const endOf = (e: GraphEdge) => e.data.endTime ?? e.data.startTime;

/** The first conversation's start and the last one's end; null when no edge has a time. */
export function timeBounds(edges: GraphEdge[]): TimeWindow | null {
  let from = Infinity;
  let to = -Infinity;
  for (const e of edges) {
    const s = startOf(e);
    const t = endOf(e);
    if (s == null || !Number.isFinite(s) || s <= 0) continue;
    from = Math.min(from, s);
    to = Math.max(to, t != null && Number.isFinite(t) ? t : s);
  }
  return Number.isFinite(from) ? { from, to: Math.max(to, from) } : null;
}

/**
 * What was active in a window: the conversations that overlap it, and the nodes at either end of
 * one. A conversation with no time counts as always active, so it never silently disappears.
 */
export function activeInWindow(edges: GraphEdge[], w: TimeWindow): { edgeIds: Set<string>; nodeIds: Set<string> } {
  const edgeIds = new Set<string>();
  const nodeIds = new Set<string>();
  for (const e of edges) {
    const s = startOf(e);
    const t = endOf(e) ?? s;
    const timeless = s == null || s <= 0;
    if (timeless || (s <= w.to && (t ?? s) >= w.from)) {
      edgeIds.add(e.id);
      nodeIds.add(e.source);
      nodeIds.add(e.target);
    }
  }
  return { edgeIds, nodeIds };
}

/**
 * Bytes per bucket across [from, to]. A conversation's bytes are spread over its duration, so a
 * long download fills every bucket it spans instead of one spike where it started.
 */
export function bytesHistogram(edges: GraphEdge[], bounds: TimeWindow, buckets: number): number[] {
  const out = new Array<number>(buckets).fill(0);
  const span = Math.max(1, bounds.to - bounds.from);
  const width = span / buckets;
  for (const e of edges) {
    const s = startOf(e);
    if (s == null || s <= 0) continue;
    const t = Math.max(s, endOf(e) ?? s);
    const bytes = e.data.totalBytes ?? 0;
    if (bytes <= 0) continue;
    const first = Math.min(buckets - 1, Math.max(0, Math.floor((s - bounds.from) / width)));
    const last = Math.min(buckets - 1, Math.max(0, Math.floor((t - bounds.from) / width)));
    if (first === last || t === s) {
      out[first] += bytes;
      continue;
    }
    const dur = t - s;
    for (let b = first; b <= last; b++) {
      const bStart = bounds.from + b * width;
      const overlap = Math.min(t, bStart + width) - Math.max(s, bStart);
      if (overlap > 0) out[b] += (bytes * overlap) / dur;
    }
  }
  return out;
}

/** A window of {@code width} starting at {@code from}, kept inside the bounds. */
export function clampWindow(from: number, width: number, bounds: TimeWindow): TimeWindow {
  const w = Math.min(width, bounds.to - bounds.from);
  const start = Math.min(Math.max(from, bounds.from), bounds.to - w);
  return { from: start, to: start + w };
}
