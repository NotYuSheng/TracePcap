/**
 * Pure layouts for the Overview's "where the traffic goes" cards: a squarified treemap and a
 * two-column flow (Sankey) diagram. Kept apart from the components so they can be tested on numbers.
 */

export interface Tile<T> {
  x: number;
  y: number;
  w: number;
  h: number;
  value: number;
  item: T;
}

/**
 * Squarified treemap (Bruls, Huizing, van Wijk): lays out `items` (largest first works best) in
 * the w×h box, filling rows along the short side while that keeps the tiles closer to square.
 */
export function squarify<T>(items: { value: number; item: T }[], w: number, h: number): Tile<T>[] {
  const out: Tile<T>[] = [];
  let rest = items.filter(i => i.value > 0);
  let x = 0;
  let y = 0;
  while (rest.length > 0 && w > 0 && h > 0) {
    const total = rest.reduce((s, i) => s + i.value, 0);
    const side = Math.min(w, h);
    let row: typeof rest = [];
    let best = Infinity;
    for (const it of rest) {
      const trial = [...row, it];
      const areas = trial.map(t => (t.value / total) * w * h);
      const sum = areas.reduce((s, a) => s + a, 0);
      const len = sum / side;
      const worst = Math.max(...areas.map(a => Math.max((len * len) / a, a / (len * len))));
      if (worst > best) break;
      row = trial;
      best = worst;
    }
    const areas = row.map(t => (t.value / total) * w * h);
    const sum = areas.reduce((s, a) => s + a, 0);
    if (w >= h) {
      const cw = sum / h;
      let cy = y;
      row.forEach((t, i) => {
        const ch = areas[i] / cw;
        out.push({ x, y: cy, w: cw, h: ch, value: t.value, item: t.item });
        cy += ch;
      });
      x += cw;
      w -= cw;
    } else {
      const rh = sum / w;
      let cx = x;
      row.forEach((t, i) => {
        const cw = areas[i] / rh;
        out.push({ x: cx, y, w: cw, h: rh, value: t.value, item: t.item });
        cx += cw;
      });
      y += rh;
      h -= rh;
    }
    rest = rest.slice(row.length);
  }
  return out;
}

export interface FlowIn {
  from: string;
  to: string;
  value: number;
}

export interface FlowNode {
  id: string;
  y: number;
  h: number;
  value: number;
}

export interface FlowBand extends FlowIn {
  /** Top of the band at its source, and at its target. */
  y0: number;
  y1: number;
  /** Its thickness at the source and at the target (the columns scale separately). */
  h0: number;
  h1: number;
}

/**
 * A two-column flow layout: senders on the left, receivers on the right, each stacked by total,
 * biggest at the top, and every band as thick as its share of the column. A group can appear in
 * both columns (it sends and receives).
 */
export function flowLayout(flows: FlowIn[], height: number, gap = 8, top = 0) {
  const sum = (m: Map<string, number>, k: string, v: number) => m.set(k, (m.get(k) ?? 0) + v);
  const out = new Map<string, number>();
  const inn = new Map<string, number>();
  for (const f of flows) {
    sum(out, f.from, f.value);
    sum(inn, f.to, f.value);
  }
  const total = flows.reduce((s, f) => s + f.value, 0);
  const column = (m: Map<string, number>) => {
    const ids = [...m.keys()].sort((a, b) => (m.get(b) ?? 0) - (m.get(a) ?? 0));
    const scale = total > 0 ? Math.max(0, height - gap * (ids.length - 1)) / total : 0;
    const nodes: FlowNode[] = [];
    let y = top;
    for (const id of ids) {
      const h = (m.get(id) ?? 0) * scale;
      nodes.push({ id, y, h, value: m.get(id) ?? 0 });
      y += h + gap;
    }
    return { nodes, scale };
  };
  const left = column(out);
  const right = column(inn);
  const cursorL = new Map(left.nodes.map(n => [n.id, n.y]));
  const cursorR = new Map(right.nodes.map(n => [n.id, n.y]));
  const bands: FlowBand[] = [...flows]
    .sort((a, b) => b.value - a.value)
    .map(f => {
      const h0 = f.value * left.scale;
      const h1 = f.value * right.scale;
      const y0 = cursorL.get(f.from) ?? top;
      const y1 = cursorR.get(f.to) ?? top;
      cursorL.set(f.from, y0 + h0);
      cursorR.set(f.to, y1 + h1);
      return { ...f, y0, y1, h0, h1 };
    });
  return { left: left.nodes, right: right.nodes, bands };
}

/** "Deutsche Telekom AG (AS3320)" → "Deutsche Telekom AG", "Germany (DE)" → "Germany". */
export function groupName(label: string): string {
  return label.replace(/\s*\(AS\d+\)$/, '').replace(/\s*\([A-Z]{2}\)$/, '');
}

/**
 * Display names for a set of groups: the short name, except where two groups would share it
 * (Microsoft has more than one ASN), which keep their full label so they can be told apart.
 */
export function groupNames(groups: { id: string; label: string }[]): Map<string, string> {
  const count = new Map<string, number>();
  for (const g of groups) count.set(groupName(g.label), (count.get(groupName(g.label)) ?? 0) + 1);
  return new Map(groups.map(g => [g.id, (count.get(groupName(g.label)) ?? 0) > 1 ? g.label : groupName(g.label)]));
}

/** "1 host", "2 hosts". */
export function hosts(n: number): string {
  return `${n.toLocaleString()} ${n === 1 ? 'host' : 'hosts'}`;
}
