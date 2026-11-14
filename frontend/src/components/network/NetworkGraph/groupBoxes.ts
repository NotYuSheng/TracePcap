import type Sigma from 'sigma';
import type { GroupBox } from '@/features/network/services/networkGroups';

/** One colour per network, told apart by lightness as well as hue. */
export const TONES_LIGHT = ['#6d4fd8', '#c2410c', '#0f766e', '#1d4ed8', '#be185d', '#4d7c0f'];
const TONES_DARK = ['#a993ff', '#fb923c', '#2dd4bf', '#7aa2ff', '#f472b6', '#a3e635'];

interface Style {
  fill: string;
  stroke: string;
  dash?: number[];
  text: string;
  muted: string;
}

function hexA(hex: string, a: number): string {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}

function styleFor(b: GroupBox, dark: boolean): Style {
  const text = dark ? '#e2e8f0' : '#1f2937';
  const muted = dark ? '#a3adbf' : '#4b5563';
  const tones = dark ? TONES_DARK : TONES_LIGHT;
  const tone = tones[(b.tone ?? 0) % tones.length];
  switch (b.kind) {
    case 'local':
      return { fill: dark ? '#1b1f2c' : '#eceef3', stroke: dark ? '#2e3349' : '#c9ced8', text, muted };
    case 'internet':
      return { fill: dark ? '#17233b' : '#e8f0fe', stroke: dark ? '#2b4470' : '#b7cdf5', text: dark ? '#bcd3ff' : '#1e3a8a', muted };
    case 'special':
      return { fill: dark ? '#1d1f26' : '#f1f2f4', stroke: dark ? '#353a46' : '#d4d7dd', text, muted };
    case 'network':
      return { fill: hexA(tone, dark ? 0.1 : 0.06), stroke: tone, dash: [7, 5], text: tone, muted };
    case 'subnet':
      return { fill: dark ? 'rgba(15, 18, 28, 0.55)' : 'rgba(255, 255, 255, 0.78)', stroke: hexA(tone, 0.45), text, muted };
    case 'domain':
      return { fill: dark ? 'rgba(15, 18, 28, 0.55)' : '#ffffff', stroke: dark ? '#2b4470' : '#b7cdf5', text: dark ? '#bcd3ff' : '#1e3a8a', muted };
    default:
      return { fill: dark ? 'rgba(255, 255, 255, 0.03)' : '#f7f8fb', stroke: dark ? '#2a2f40' : '#e3e6ec', text: muted, muted };
  }
}

function fitText(ctx: CanvasRenderingContext2D, text: string, max: number): string {
  if (ctx.measureText(text).width <= max) return text;
  let t = text;
  while (t.length > 1 && ctx.measureText(t + '…').width > max) t = t.slice(0, -1);
  return t + '…';
}

/**
 * Draws the "Network map" layout's group boxes, under the graph. Boxes are in layout units with y
 * down; the nodes were placed at (x, −y), so each corner goes through the same transform.
 * `active` (the time axis's window) turns each count into "n of m active".
 */
export function drawGroupBoxes(
  canvas: HTMLCanvasElement,
  sigma: Sigma,
  boxes: GroupBox[],
  headerFor: (level: number) => number,
  dark: boolean,
  active?: Set<string> | null,
): void {
  const ratio = window.devicePixelRatio || 1;
  const w = Math.round(canvas.clientWidth * ratio);
  const h = Math.round(canvas.clientHeight * ratio);
  if (canvas.width !== w || canvas.height !== h) {
    canvas.width = w;
    canvas.height = h;
  }
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  ctx.clearRect(0, 0, w, h);
  if (boxes.length === 0) return;

  ctx.save();
  ctx.scale(ratio, ratio);
  for (const b of boxes) {
    const a = sigma.graphToViewport({ x: b.x, y: -b.y });
    const c = sigma.graphToViewport({ x: b.x + b.w, y: -(b.y + b.h) });
    const left = Math.min(a.x, c.x);
    const top = Math.min(a.y, c.y);
    const bw = Math.abs(c.x - a.x);
    const bh = Math.abs(c.y - a.y);
    if (left > canvas.clientWidth || top > canvas.clientHeight || left + bw < 0 || top + bh < 0) continue;
    const scale = bw / b.w;
    const s = styleFor(b, dark);

    ctx.beginPath();
    ctx.roundRect(left, top, bw, bh, Math.max(3, Math.min(16, 14 * scale * 2)));
    ctx.fillStyle = s.fill;
    ctx.fill();
    ctx.setLineDash(s.dash ?? []);
    ctx.lineWidth = b.kind === 'network' ? 1.5 : 1;
    ctx.strokeStyle = s.stroke;
    ctx.stroke();
    ctx.setLineDash([]);

    // The name, in the header band the layout left for it; shrinks with zoom, gone when unreadable.
    const band = headerFor(b.level) * scale;
    const max = b.level === 1 ? 16 : b.level === 2 ? 15 : 13;
    const size = Math.min(max, band * 0.42);
    if (size < 7) continue;
    const padX = Math.max(6, 18 * scale);
    const room = bw - padX * 2;
    if (room < 30) continue;
    const n = active ? b.memberIds.filter(id => active.has(id)).length : b.count;
    const count = active
      ? `${n} of ${b.count} active`
      : `${b.count} ${b.count === 1 ? 'device' : 'devices'}`;
    const lineY = top + Math.min(band * 0.5, size * 1.4);
    ctx.textBaseline = 'middle';
    ctx.font = `600 ${size}px Inter, system-ui, sans-serif`;
    ctx.fillStyle = s.text;
    const name = fitText(ctx, b.label, room * 0.7);
    ctx.fillText(name, left + padX, lineY);
    const nameW = ctx.measureText(name).width;
    ctx.font = `400 ${size}px Inter, system-ui, sans-serif`;
    ctx.fillStyle = s.muted;
    ctx.fillText(fitText(ctx, ` · ${count}`, room - nameW), left + padX + nameW, lineY);
    if (b.detail && band > size * 2.6) {
      ctx.font = `400 ${size * 0.82}px Inter, system-ui, sans-serif`;
      ctx.fillText(fitText(ctx, b.detail, room), left + padX, lineY + size * 1.25);
    }
  }
  ctx.restore();
}
