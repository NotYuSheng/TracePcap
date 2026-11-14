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

/** One device on two nodes (it moved to another address): a dashed line and a label between them. */
export function drawDeviceLinks(
  ctx: CanvasRenderingContext2D,
  sigma: Sigma,
  links: { from: string; to: string; label: string; hideLabel?: boolean }[],
  dark: boolean,
): void {
  if (links.length === 0) return;
  const ratio = window.devicePixelRatio || 1;
  const graph = sigma.getGraph();
  ctx.save();
  ctx.setLineDash([6 * ratio, 5 * ratio]);
  ctx.lineWidth = 1.6 * ratio;
  const stroke = dark ? '#b9a6ff' : '#5925dc';
  ctx.strokeStyle = stroke;
  ctx.font = `${11 * ratio}px Inter, system-ui, sans-serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  for (const l of links) {
    if (!graph.hasNode(l.from) || !graph.hasNode(l.to)) continue;
    const a = sigma.getNodeDisplayData(l.from);
    const b = sigma.getNodeDisplayData(l.to);
    // Not drawn while either end is hidden (not seen yet in the time window, or filtered).
    if (!a || !b || a.hidden || b.hidden) continue;
    const pa = sigma.framedGraphToViewport({ x: a.x, y: a.y });
    const pb = sigma.framedGraphToViewport({ x: b.x, y: b.y });
    ctx.globalAlpha = 0.9;
    ctx.beginPath();
    ctx.moveTo(pa.x * ratio, pa.y * ratio);
    ctx.lineTo(pb.x * ratio, pb.y * ratio);
    ctx.stroke();
    if (l.hideLabel) continue;
    // The label on a pill at the midpoint, so it reads over edges.
    const mx = ((pa.x + pb.x) / 2) * ratio;
    const my = ((pa.y + pb.y) / 2) * ratio;
    const w = ctx.measureText(l.label).width + 10 * ratio;
    const h = 16 * ratio;
    ctx.globalAlpha = 1;
    ctx.setLineDash([]);
    ctx.fillStyle = dark ? '#1e2130' : '#ffffff';
    ctx.fillRect(mx - w / 2, my - h / 2, w, h);
    ctx.strokeRect(mx - w / 2, my - h / 2, w, h);
    ctx.fillStyle = stroke;
    ctx.fillText(l.label, mx, my);
    ctx.setLineDash([6 * ratio, 5 * ratio]);
  }
  ctx.restore();
}

// ── Time-axis effects: a node appearing, a device moving ────────────────────────────────────────

/** What the time axis showed at one moment (the NetworkGraph's activeInWindow, plus the window). */
export interface WindowState {
  nodeIds: Set<string>;
  hiddenNodeIds?: Set<string>;
  faintNodeIds?: Set<string>;
  window?: { from: number; to: number };
}

export type GraphEffect =
  | { kind: 'appear'; node: string; t0: number }
  | { kind: 'move'; from: string; to: string; note: string; t0: number };

export const APPEAR_MS = 900;
export const MOVE_MS = 1400;
/** Linger after the dot lands, so the note can be read. */
const NOTE_MS = 1600;
/** A big jump would light up the whole graph; past this many, appear rings are skipped. */
const MAX_APPEAR = 30;

/** The address part of a device key: `10.0.0.73@1700000000` / `10.0.0.73~site-b` → `10.0.0.73`. */
function addressOf(nodeId: string): string {
  return nodeId.split(/[@~]/)[0];
}

/** The note shown as a device lands on its new address: where it went, and a rename if any. */
export function moveNote(to: string, label: string): string {
  const rename = /renamed (.+)$/.exec(label);
  return `moved → ${addressOf(to)}${rename ? `, renamed ${rename[1]}` : ''}`;
}

/**
 * The effects a window change sets off. Only for changes the window crossed going forward: no
 * effects when the window is cleared, first set, or moved back — a jump is not an event.
 */
export function windowEffects(
  prev: WindowState | null | undefined,
  cur: WindowState | null | undefined,
  links: { from: string; to: string; at?: number; label: string }[],
  now: number,
): GraphEffect[] {
  if (!prev?.window || !cur?.window || cur.window.to <= prev.window.to) return [];
  const out: GraphEffect[] = [];
  const prevUnseen = prev.hiddenNodeIds ?? prev.faintNodeIds;
  const curUnseen = cur.hiddenNodeIds ?? cur.faintNodeIds;
  if (prevUnseen && curUnseen) {
    const appeared: string[] = [];
    for (const n of prevUnseen) if (!curUnseen.has(n)) appeared.push(n);
    if (appeared.length <= MAX_APPEAR) {
      for (const node of appeared) out.push({ kind: 'appear', node, t0: now });
    }
  }
  const { to: prevTo } = prev.window;
  const { to: curTo } = cur.window;
  for (const l of links) {
    if (l.at != null && l.at > prevTo && l.at <= curTo) {
      out.push({ kind: 'move', from: l.from, to: l.to, note: moveNote(l.to, l.label), t0: now });
    }
  }
  return out;
}

/** True while an effect still has frames to draw. */
export function effectAlive(e: GraphEffect, now: number): boolean {
  return now - e.t0 < (e.kind === 'appear' ? APPEAR_MS : MOVE_MS + NOTE_MS);
}

function ring(ctx: CanvasRenderingContext2D, x: number, y: number, r0: number, p: number, colour: string, ratio: number) {
  ctx.globalAlpha = (1 - p) * 0.85;
  ctx.lineWidth = 2.5 * ratio;
  ctx.strokeStyle = colour;
  ctx.beginPath();
  ctx.arc(x, y, r0 + p * 26 * ratio, 0, Math.PI * 2);
  ctx.stroke();
}

/** Draws live effects over the graph; drops finished ones from `effects` in place. */
export function drawEffects(ctx: CanvasRenderingContext2D, sigma: Sigma, effects: GraphEffect[], now: number, dark: boolean): void {
  for (let i = effects.length - 1; i >= 0; i--) if (!effectAlive(effects[i], now)) effects.splice(i, 1);
  if (effects.length === 0) return;
  const ratio = window.devicePixelRatio || 1;
  const graph = sigma.getGraph();
  const accent = dark ? '#b9a6ff' : '#5925dc';
  const point = (node: string) => {
    if (!graph.hasNode(node)) return null;
    const d = sigma.getNodeDisplayData(node);
    if (!d || d.hidden) return null;
    const p = sigma.framedGraphToViewport({ x: d.x, y: d.y });
    // Node size is in viewport pixels already (sigma scales it for the camera).
    return { x: p.x * ratio, y: p.y * ratio, r: sigma.scaleSize(d.size) * ratio, color: d.color };
  };
  ctx.save();
  ctx.setLineDash([]);
  for (const e of effects) {
    const t = now - e.t0;
    if (e.kind === 'appear') {
      const p = point(e.node);
      if (p) ring(ctx, p.x, p.y, p.r, t / APPEAR_MS, accent, ratio);
      continue;
    }
    const a = point(e.from);
    const b = point(e.to);
    if (!a || !b) continue;
    if (t < MOVE_MS) {
      // Ease in-out, a glowing dot from the old address to the new one.
      const p = t / MOVE_MS;
      const k = p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2;
      const x = a.x + (b.x - a.x) * k;
      const y = a.y + (b.y - a.y) * k;
      ctx.globalAlpha = 0.25;
      ctx.fillStyle = accent;
      ctx.beginPath();
      ctx.arc(x, y, 10 * ratio, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 1;
      ctx.beginPath();
      ctx.arc(x, y, 4.5 * ratio, 0, Math.PI * 2);
      ctx.fill();
      continue;
    }
    const after = t - MOVE_MS;
    if (after < APPEAR_MS) ring(ctx, b.x, b.y, b.r, after / APPEAR_MS, accent, ratio);
    // The note above the new node: fades in fast, holds, fades out.
    const fade = Math.min(1, after / 200, (MOVE_MS + NOTE_MS - t) / 400);
    ctx.globalAlpha = Math.max(0, fade);
    ctx.font = `600 ${12 * ratio}px Inter, system-ui, sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const w = ctx.measureText(e.note).width + 14 * ratio;
    const h = 20 * ratio;
    const ny = b.y - b.r - 22 * ratio;
    ctx.fillStyle = accent;
    ctx.beginPath();
    ctx.roundRect(b.x - w / 2, ny - h / 2, w, h, 10 * ratio);
    ctx.fill();
    ctx.fillStyle = dark ? '#1a1530' : '#ffffff';
    ctx.fillText(e.note, b.x, ny);
  }
  ctx.restore();
}

// ── Packet replay: each packet flies along its edge ─────────────────────────────────────────────

export interface LiveFlight {
  from: string;
  to: string;
  color: string;
  t0: number;
  dur: number;
}

/** Draws in-flight packets (a dot with a short trail, a ring where it lands); drops finished ones in place. */
export function drawFlights(ctx: CanvasRenderingContext2D, sigma: Sigma, flights: LiveFlight[], now: number): void {
  for (let i = flights.length - 1; i >= 0; i--) if (now - flights[i].t0 > flights[i].dur * 1.5) flights.splice(i, 1);
  if (flights.length === 0) return;
  const ratio = window.devicePixelRatio || 1;
  const graph = sigma.getGraph();
  const at = (node: string) => {
    if (!graph.hasNode(node)) return null;
    const d = sigma.getNodeDisplayData(node);
    if (!d || d.hidden) return null;
    const p = sigma.framedGraphToViewport({ x: d.x, y: d.y });
    return { x: p.x * ratio, y: p.y * ratio, r: sigma.scaleSize(d.size) * ratio };
  };
  ctx.save();
  for (const f of flights) {
    const a = at(f.from);
    const b = at(f.to);
    if (!a || !b) continue;
    const p = (now - f.t0) / f.dur;
    ctx.fillStyle = f.color;
    ctx.strokeStyle = f.color;
    if (p <= 1) {
      // Ease out, so a packet visibly leaves and settles in.
      const k = 1 - Math.pow(1 - p, 2);
      const x = a.x + (b.x - a.x) * k;
      const y = a.y + (b.y - a.y) * k;
      const tk = Math.max(0, k - 0.12);
      const g = ctx.createLinearGradient(a.x + (b.x - a.x) * tk, a.y + (b.y - a.y) * tk, x, y);
      g.addColorStop(0, 'rgba(0,0,0,0)');
      g.addColorStop(1, f.color);
      ctx.globalAlpha = 0.7;
      ctx.lineWidth = 3 * ratio;
      ctx.lineCap = 'round';
      ctx.strokeStyle = g;
      ctx.beginPath();
      ctx.moveTo(a.x + (b.x - a.x) * tk, a.y + (b.y - a.y) * tk);
      ctx.lineTo(x, y);
      ctx.stroke();
      ctx.globalAlpha = 0.25;
      ctx.beginPath();
      ctx.arc(x, y, 9 * ratio, 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 1;
      ctx.beginPath();
      ctx.arc(x, y, 4.5 * ratio, 0, Math.PI * 2);
      ctx.fill();
    } else {
      // Landed: a ring opens on the receiver.
      const q = (p - 1) / 0.5;
      ctx.globalAlpha = (1 - q) * 0.8;
      ctx.lineWidth = 2 * ratio;
      ctx.strokeStyle = f.color;
      ctx.beginPath();
      ctx.arc(b.x, b.y, b.r + q * 14 * ratio, 0, Math.PI * 2);
      ctx.stroke();
    }
  }
  ctx.restore();
}
