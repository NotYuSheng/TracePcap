import type Sigma from 'sigma';

/** How long a dot takes to cross an edge, in ms. */
const CROSS_MS = 2200;
/** At most this many edges animate at once: the busiest, so a huge graph stays smooth. */
const MAX_EDGES = 400;

interface EdgeShape {
  key: string;
  bytes: number;
  bidirectional: boolean;
  /** A stable 0–1 phase, so dots on different edges aren't in lockstep. */
  phase: number;
}

function phaseOf(key: string): number {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) | 0;
  return ((h >>> 0) % 1000) / 1000;
}

/** The edges worth animating, busiest first (recomputed when the graph changes). */
export function animatedEdges(sigma: Sigma): EdgeShape[] {
  const out: EdgeShape[] = [];
  sigma.getGraph().forEachEdge((key, attrs) => {
    out.push({
      key,
      bytes: Number(attrs['totalBytes'] ?? 0),
      bidirectional: !!attrs['bidirectional'],
      phase: phaseOf(key),
    });
  });
  out.sort((a, b) => b.bytes - a.bytes);
  return out.slice(0, MAX_EDGES);
}

/** More dots on busier edges: 1 for a trickle, up to 4 for the heaviest. */
function dotsFor(bytes: number): number {
  return 1 + Math.min(3, Math.floor(Math.log10(Math.max(1, bytes)) / 2));
}

/**
 * Draws one frame of traffic dots moving along the visible edges. Each dot follows its edge's own
 * shape: straight, or the same quadratic curve the curved-edge program draws (control point offset
 * from the midpoint by the edge's curvature times its length). Edges the reducers hide (outside the
 * time window, or not next to the hovered node) get no dots.
 */
export function drawParticles(
  ctx: CanvasRenderingContext2D,
  sigma: Sigma,
  edges: EdgeShape[],
  now: number,
): void {
  const { width, height } = ctx.canvas;
  const ratio = window.devicePixelRatio || 1;
  ctx.clearRect(0, 0, width, height);
  const graph = sigma.getGraph();
  for (const e of edges) {
    if (!graph.hasEdge(e.key)) continue;
    const display = sigma.getEdgeDisplayData(e.key);
    if (!display || display.hidden) continue;
    const [s, t] = graph.extremities(e.key);
    const sd = sigma.getNodeDisplayData(s);
    const td = sigma.getNodeDisplayData(t);
    if (!sd || !td || sd.hidden || td.hidden) continue;
    const a = sigma.framedGraphToViewport({ x: sd.x, y: sd.y });
    const b = sigma.framedGraphToViewport({ x: td.x, y: td.y });
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    if (dx * dx + dy * dy < 16) continue; // too short to see anything move
    const curvature = display.type === 'curved' ? Number((display as unknown as { curvature?: number }).curvature ?? 0) : 0;
    // The curve's control point, in screen coordinates (y down).
    const cx = (a.x + b.x) / 2 + dy * curvature;
    const cy = (a.y + b.y) / 2 - dx * curvature;
    const n = dotsFor(e.bytes);
    ctx.fillStyle = display.color || '#888';
    ctx.globalAlpha = 0.9;
    for (let i = 0; i < n; i++) {
      let p = (now / CROSS_MS + e.phase + i / n) % 1;
      // Two-way traffic: every other dot runs back.
      if (e.bidirectional && i % 2 === 1) p = 1 - p;
      const q = 1 - p;
      const x = q * q * a.x + 2 * q * p * cx + p * p * b.x;
      const y = q * q * a.y + 2 * q * p * cy + p * p * b.y;
      ctx.beginPath();
      ctx.arc(x * ratio, y * ratio, 2.6 * ratio, 0, Math.PI * 2);
      ctx.fill();
    }
  }
  ctx.globalAlpha = 1;
}
