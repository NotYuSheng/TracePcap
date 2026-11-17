import type Sigma from 'sigma';
import type { Pt } from '@/features/network/services/edgeRouting';

/**
 * Draws the network map's routed edges ("Along the gaps"): each a right-angle line along the
 * grid's gaps, with its arrowhead at the target's edge. They go on the canvas under the graph, so
 * the devices cover the ends of each route. The edge's own straight stroke is made invisible by
 * the edge reducer, which passes its colour on as `routeColor`; hover, legend focus and the time
 * window still decide whether and how each route shows.
 */
export function drawRoutes(canvas: HTMLCanvasElement, sigma: Sigma): void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const ratio = window.devicePixelRatio || 1;
  const graph = sigma.getGraph();
  ctx.save();
  ctx.scale(ratio, ratio);
  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';
  graph.forEachEdge((key, attrs, source, target) => {
    const route = attrs['route'] as Pt[] | undefined;
    if (!route || route.length < 2) return;
    const d = sigma.getEdgeDisplayData(key) as (ReturnType<Sigma['getEdgeDisplayData']> & { routeColor?: string }) | undefined;
    if (!d || d.hidden) return;
    const sd = sigma.getNodeDisplayData(source);
    const td = sigma.getNodeDisplayData(target);
    if (!sd || !td || sd.hidden || td.hidden) return;
    const pts = route.map(p => sigma.graphToViewport(p));
    const color = d.routeColor ?? '#9aa1ad';
    const width = Math.max(1, d.size ?? 1);
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.lineWidth = width;
    ctx.beginPath();
    ctx.moveTo(pts[0].x, pts[0].y);
    for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
    ctx.stroke();

    // The arrowhead, at the target's edge on the last leg.
    const end = pts[pts.length - 1];
    const prev = pts[pts.length - 2];
    const len = Math.hypot(end.x - prev.x, end.y - prev.y);
    if (len === 0) return;
    const ux = (end.x - prev.x) / len;
    const uy = (end.y - prev.y) / len;
    const r = sigma.scaleSize(td.size);
    const tipX = end.x - ux * r;
    const tipY = end.y - uy * r;
    const head = 5 + width * 2.5;
    const half = head * 0.55;
    ctx.beginPath();
    ctx.moveTo(tipX, tipY);
    ctx.lineTo(tipX - ux * head - uy * half, tipY - uy * head + ux * half);
    ctx.lineTo(tipX - ux * head + uy * half, tipY - uy * head - ux * half);
    ctx.closePath();
    ctx.fill();
  });
  ctx.restore();
}
