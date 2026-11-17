import { CELL_H, CELL_W, NODE_TOP } from './networkGroups';

/**
 * Keeping the network map's edges from running through devices.
 *
 * The map packs each group's devices into a grid, so a straight edge between two devices in the
 * same row or column (or that happen to line up) runs through every device between them, and it
 * reads as traffic to that device. Two ways out, chosen in the map's settings:
 *
 * - **Bend** (`bendEdges`): an edge whose line would touch another device bends into the gentlest
 *   arc that clears it; every other edge keeps its shape.
 * - **Along the gaps** (`routeOrthogonal`): an edge that would touch a device is routed with
 *   right-angle turns through the space between devices, like a drawn diagram.
 *
 * Everything here works in layout units with y pointing down (the same way round as the screen),
 * and is pure: the graph applies the results.
 */

export interface Pt {
  x: number;
  y: number;
}

export interface EdgeEnds {
  key: string;
  source: string;
  target: string;
  /** The curvature it already has (parallel edges are fanned apart); 0 or absent for straight. */
  curvature?: number;
}

/** How close (layout units) a line may pass a device's centre: the node, its ring and a margin. */
export const CLEARANCE = 40;
/** The sharpest bend allowed; a device right next to an end would otherwise ask for a loop. */
const MAX_CURVATURE = 1.2;

/** Where along the line (0..1) the point projects, and how far it is off it (signed, + = left of s→t). */
function project(s: Pt, t: Pt, p: Pt): { u: number; d: number; len: number } {
  const dx = t.x - s.x;
  const dy = t.y - s.y;
  const len = Math.hypot(dx, dy);
  if (len === 0) return { u: 0, d: Math.hypot(p.x - s.x, p.y - s.y), len };
  const u = ((p.x - s.x) * dx + (p.y - s.y) * dy) / (len * len);
  // The curved-edge program offsets its control point by curvature × (dy, −dx): that's "+" here.
  const d = ((p.x - s.x) * dy - (p.y - s.y) * dx) / len;
  return { u, d, len };
}

/** Devices the straight line from s to t would touch (not its own ends). */
export function blockers(s: Pt, t: Pt, pos: Map<string, Pt>, ends: [string, string], clearance = CLEARANCE): string[] {
  const out: string[] = [];
  const minX = Math.min(s.x, t.x) - clearance;
  const maxX = Math.max(s.x, t.x) + clearance;
  const minY = Math.min(s.y, t.y) - clearance;
  const maxY = Math.max(s.y, t.y) + clearance;
  pos.forEach((p, id) => {
    if (id === ends[0] || id === ends[1]) return;
    if (p.x < minX || p.x > maxX || p.y < minY || p.y > maxY) return;
    const { u, d } = project(s, t, p);
    if (u > 0 && u < 1 && Math.abs(d) < clearance) out.push(id);
  });
  return out;
}

/** A point on the quadratic curve the curved-edge program draws (control = midpoint + c·(dy, −dx)). */
export function curvePoint(s: Pt, t: Pt, curvature: number, u: number): Pt {
  const cx = (s.x + t.x) / 2 + (t.y - s.y) * curvature;
  const cy = (s.y + t.y) / 2 - (t.x - s.x) * curvature;
  const q = 1 - u;
  return { x: q * q * s.x + 2 * q * u * cx + u * u * t.x, y: q * q * s.y + 2 * q * u * cy + u * u * t.y };
}

/** How many devices (other than its ends) the curve passes too close to. */
export function hitsOfCurve(s: Pt, t: Pt, c: number, pos: Map<string, Pt>, ends: [string, string], clearance = CLEARANCE): number {
  const samples: Pt[] = [];
  for (let i = 1; i < 32; i++) samples.push(curvePoint(s, t, c, i / 32));
  const minX = Math.min(...samples.map(q => q.x)) - clearance;
  const maxX = Math.max(...samples.map(q => q.x)) + clearance;
  const minY = Math.min(...samples.map(q => q.y)) - clearance;
  const maxY = Math.max(...samples.map(q => q.y)) + clearance;
  let hits = 0;
  pos.forEach((p, id) => {
    if (id === ends[0] || id === ends[1]) return;
    if (p.x < minX || p.x > maxX || p.y < minY || p.y > maxY) return;
    if (samples.some(q => Math.hypot(q.x - p.x, q.y - p.y) < clearance * 0.9)) hits++;
  });
  return hits;
}

/**
 * The gentlest curvature that takes the edge clear of the devices in its way, bowing away from
 * them; null when nothing is in the way. Tries both sides and keeps the one that clips the fewest
 * devices, then the gentler.
 */
export function bendFor(s: Pt, t: Pt, pos: Map<string, Pt>, ends: [string, string], clearance = CLEARANCE): number | null {
  const inWay = blockers(s, t, pos, ends, clearance);
  if (inWay.length === 0) return null;
  const options = [1, -1].map(side => {
    let need = 0;
    for (const id of inWay) {
      const { u, d, len } = project(s, t, pos.get(id)!);
      // The curve's offset from the line at u is 2u(1−u)·c·len, on the side of c's sign.
      const away = side * d < 0 || d === 0;
      const offset = away ? clearance - Math.abs(d) : Math.abs(d) + clearance;
      need = Math.max(need, offset / (2 * u * (1 - u) * len));
    }
    const c = side * Math.min(MAX_CURVATURE, need * 1.05);
    return { c, hits: hitsOfCurve(s, t, c, pos, ends, clearance) };
  });
  options.sort((a, b) => a.hits - b.hits || Math.abs(a.c) - Math.abs(b.c));
  return options[0].c;
}

/**
 * Bend: the new curvature for each edge that would run through a device. A straight edge gets the
 * gentlest arc that clears; a fanned-out parallel keeps its place in the fan, around the bent path
 * of the pair, when that clips fewer devices than its own curve does.
 */
export function bendEdges(edges: EdgeEnds[], pos: Map<string, Pt>, clearance = CLEARANCE): Map<string, number> {
  const out = new Map<string, number>();
  const pairBend = new Map<string, number | null>();
  for (const e of edges) {
    const s = pos.get(e.source);
    const t = pos.get(e.target);
    if (!s || !t || e.source === e.target) continue;
    const ends: [string, string] = [e.source, e.target];
    // Worked out once per pair of devices, from the lower id to the higher, so a pair's edges
    // (both directions, fanned apart) bend to the same side together.
    const forward = e.source < e.target;
    const pair = forward ? `${e.source}|${e.target}` : `${e.target}|${e.source}`;
    if (!pairBend.has(pair)) {
      pairBend.set(pair, forward ? bendFor(s, t, pos, ends, clearance) : bendFor(t, s, pos, [e.target, e.source], clearance));
    }
    const base = pairBend.get(pair);
    if (base === null || base === undefined) continue;
    // Curvature is relative to the edge's own direction: the reverse edge flips it to bow the same way.
    const bend = forward ? base : -base;
    const own = e.curvature ?? 0;
    if (own === 0) {
      out.set(e.key, bend);
      continue;
    }
    const before = hitsOfCurve(s, t, own, pos, ends, clearance);
    if (before === 0) continue;
    // Keep its place in the fan around the bent path; a fan member on the near side may need a
    // stronger bend to clear too.
    let best = { c: own, hits: before };
    for (const f of [1, 1.5, 2, 3]) {
      const c = Math.max(-MAX_CURVATURE, Math.min(MAX_CURVATURE, bend * f + own));
      const hits = hitsOfCurve(s, t, c, pos, ends, clearance);
      if (hits < best.hits) best = { c, hits };
      if (hits === 0) break;
    }
    if (best.c !== own) out.set(e.key, best.c);
  }
  return out;
}

// ── Along the gaps: right-angle routes ─────────────────────────────────────────────────────────

/** Grid step for routing (layout units): fine enough to find the gaps between labels. */
const STEP = 10;
/** A device's centre: no route within this (its node and ring). */
const NODE_RADIUS = 36;
const TURN_COST = 12;
const LABEL_COST = 12;
/** Per earlier route through a grid point: later ones spread out instead of stacking. */
const BUSY_COST = 2;
/** Give up on a route (and bend that edge) after this many grid points. */
const MAX_EXPANSIONS = 30_000;

/** A binary min-heap of (key, priority) in typed arrays: the router pushes millions of these. */
class Heap {
  private keys = new Int32Array(1024);
  private pri = new Float64Array(1024);
  size = 0;
  push(k: number, f: number) {
    if (this.size === this.keys.length) {
      const keys = new Int32Array(this.size * 2);
      keys.set(this.keys);
      this.keys = keys;
      const pri = new Float64Array(this.size * 2);
      pri.set(this.pri);
      this.pri = pri;
    }
    let i = this.size++;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (this.pri[p] <= f) break;
      this.keys[i] = this.keys[p];
      this.pri[i] = this.pri[p];
      i = p;
    }
    this.keys[i] = k;
    this.pri[i] = f;
  }
  pop(): number {
    const top = this.keys[0];
    const n = --this.size;
    const k = this.keys[n];
    const f = this.pri[n];
    let i = 0;
    for (;;) {
      const l = 2 * i + 1;
      if (l >= n) break;
      const r = l + 1;
      const m = r < n && this.pri[r] < this.pri[l] ? r : l;
      if (this.pri[m] >= f) break;
      this.keys[i] = this.keys[m];
      this.pri[i] = this.pri[m];
      i = m;
    }
    this.keys[i] = k;
    this.pri[i] = f;
    return top;
  }
}

/** Devices bucketed by area, to find the ones near a point quickly. */
function bucketed(pos: Map<string, Pt>, size: number) {
  const buckets = new Map<string, { id: string; p: Pt }[]>();
  pos.forEach((p, id) => {
    const k = `${Math.floor(p.x / size)},${Math.floor(p.y / size)}`;
    (buckets.get(k) ?? buckets.set(k, []).get(k)!).push({ id, p });
  });
  return (x: number, y: number) => {
    const bx = Math.floor(x / size);
    const by = Math.floor(y / size);
    const out: { id: string; p: Pt }[] = [];
    for (let i = -1; i <= 1; i++) for (let j = -1; j <= 1; j++) out.push(...(buckets.get(`${bx + i},${by + j}`) ?? []));
    return out;
  };
}

/**
 * Along the gaps: a right-angle route for each edge whose straight line would touch a device,
 * found by a shortest-path search on a fine grid. Devices are walls; their labels (under them)
 * cost extra to cross; every turn costs extra, so routes are a few long legs; and points earlier
 * routes used cost a little more, so routes sharing a corridor sit side by side.
 * A route runs from the source's centre to the target's (the devices cover the ends). Edges with
 * no route found within a bound are left out (bend those).
 */
export function routeOrthogonal(
  edges: EdgeEnds[],
  pos: Map<string, Pt>,
  clearance = CLEARANCE,
  /** Routing stops after this long; edges left over are bent instead. */
  budgetMs = 1500,
): Map<string, Pt[]> {
  const out = new Map<string, Pt[]>();
  const near = bucketed(pos, CELL_W);
  const busy = new Map<string, number>();
  // A label sits under its device: about a cell wide, from just under the node to the cell's end.
  const labelW = CELL_W / 2 - 14;
  const labelTop = NODE_RADIUS - 4;
  const labelBottom = CELL_H - NODE_TOP - 16;

  const started = Date.now();
  // Shortest first: cheapest to route, and the most local, so the budget covers the most edges.
  const length = (e: EdgeEnds) => {
    const a = pos.get(e.source);
    const b = pos.get(e.target);
    return a && b ? Math.abs(a.x - b.x) + Math.abs(a.y - b.y) : Infinity;
  };
  const ordered = [...edges].sort((a, b) => length(a) - length(b));
  for (const e of ordered) {
    // A busy map can have hundreds of edges to route: past the budget, the rest are bent instead.
    if (Date.now() - started > budgetMs) break;
    const s = pos.get(e.source);
    const t = pos.get(e.target);
    if (!s || !t || e.source === e.target) continue;
    if (blockers(s, t, pos, [e.source, e.target], clearance).length === 0) continue;

    // The grid is anchored on the source, so the route leaves it on a grid line.
    const toX = (i: number) => s.x + i * STEP;
    const toY = (j: number) => s.y + j * STEP;
    const ti = Math.round((t.x - s.x) / STEP);
    const tj = Math.round((t.y - s.y) / STEP);
    const margin = Math.ceil(CELL_W / STEP);
    const minI = Math.min(0, ti) - margin;
    const maxI = Math.max(0, ti) + margin;
    const minJ = Math.min(0, tj) - margin;
    const maxJ = Math.max(0, tj) + margin;
    const W = maxI - minI + 1;
    const H = maxJ - minJ + 1;
    const key = (i: number, j: number, d: number) => (((j - minJ) * W + (i - minI)) << 2) | d;

    // Each grid point's cost, worked out when first reached (NaN: not yet).
    const cellCost = new Float64Array(W * H).fill(NaN);
    const costAt = (i: number, j: number): number => {
      const ck = (j - minJ) * W + (i - minI);
      const cached = cellCost[ck];
      if (!Number.isNaN(cached)) return cached;
      const x = toX(i);
      const y = toY(j);
      let c = 1;
      for (const n of near(x, y)) {
        const own = n.id === e.source || n.id === e.target;
        const dx = x - n.p.x;
        const dy = y - n.p.y;
        if (!own && dx * dx + dy * dy < NODE_RADIUS * NODE_RADIUS) {
          c = Infinity;
          break;
        }
        if (!own && Math.abs(dx) < labelW && dy > labelTop && dy < labelBottom) c += LABEL_COST;
      }
      if (c !== Infinity) c += (busy.get(`${Math.round(x)},${Math.round(y)}`) ?? 0) * BUSY_COST;
      cellCost[ck] = c;
      return c;
    };

    const DIRS = [[1, 0], [0, 1], [-1, 0], [0, -1]];
    const g = new Float64Array(W * H * 4).fill(Infinity);
    const from = new Int32Array(W * H * 4).fill(-1);
    const heap = new Heap();
    const h = (i: number, j: number) => Math.abs(ti - i) + Math.abs(tj - j);
    for (let d = 0; d < 4; d++) {
      const k = key(0, 0, d);
      g[k] = 0;
      heap.push(k, h(0, 0));
    }
    let found = -1;
    let expansions = 0;
    while (heap.size > 0 && expansions < MAX_EXPANSIONS) {
      const k = heap.pop();
      const d = k & 3;
      const cell = k >> 2;
      const i = (cell % W) + minI;
      const j = Math.floor(cell / W) + minJ;
      if (i === ti && j === tj) {
        found = k;
        break;
      }
      expansions++;
      const base = g[k];
      for (let nd = 0; nd < 4; nd++) {
        if ((nd + 2) % 4 === d && !(i === 0 && j === 0)) continue; // no turning back
        const ni = i + DIRS[nd][0];
        const nj = j + DIRS[nd][1];
        if (ni < minI || ni > maxI || nj < minJ || nj > maxJ) continue;
        const step = costAt(ni, nj);
        if (step === Infinity) continue;
        const cost = base + step + (nd !== d && !(i === 0 && j === 0) ? TURN_COST : 0);
        const nk = key(ni, nj, nd);
        if (cost < g[nk]) {
          g[nk] = cost;
          from[nk] = k;
          heap.push(nk, cost + h(ni, nj));
        }
      }
    }
    if (found < 0) continue;

    // Walk back, keeping only the corners.
    const cells: Pt[] = [];
    for (let k = found; k >= 0; k = from[k]) {
      const cell = k >> 2;
      cells.push({ x: toX((cell % W) + minI), y: toY(Math.floor(cell / W) + minJ) });
    }
    cells.reverse();
    const route: Pt[] = [cells[0]];
    for (let n = 1; n < cells.length - 1; n++) {
      const a = route[route.length - 1];
      const c = cells[n + 1];
      if (!(a.x === c.x || a.y === c.y)) route.push(cells[n]);
    }
    route.push(cells[cells.length - 1]);
    // The target sits up to half a step off the grid: move the last leg onto it.
    const last = route.length - 1;
    if (route.length >= 3) {
      const before = route[last - 1];
      if (before.x === route[last].x) before.x = t.x;
      else before.y = t.y;
    }
    route[last] = { x: t.x, y: t.y };
    out.set(e.key, route);
    for (const p of cells) {
      const bk = `${Math.round(p.x)},${Math.round(p.y)}`;
      busy.set(bk, (busy.get(bk) ?? 0) + 1);
    }
  }
  return out;
}

/** The point a fraction `u` (0..1) of the way along a route, by length. */
export function pointAlong(route: Pt[], u: number): Pt {
  const lens: number[] = [];
  let total = 0;
  for (let i = 1; i < route.length; i++) {
    const l = Math.hypot(route[i].x - route[i - 1].x, route[i].y - route[i - 1].y);
    lens.push(l);
    total += l;
  }
  if (total === 0) return route[0];
  let left = Math.max(0, Math.min(1, u)) * total;
  for (let i = 0; i < lens.length; i++) {
    if (left <= lens[i] || i === lens.length - 1) {
      const f = lens[i] === 0 ? 0 : left / lens[i];
      return {
        x: route[i].x + (route[i + 1].x - route[i].x) * f,
        y: route[i].y + (route[i + 1].y - route[i].y) * f,
      };
    }
    left -= lens[i];
  }
  return route[route.length - 1];
}
