import type { GraphEdge, GraphNode } from '@/features/network/types';
import { familyOf, type GroupBox, type GroupedLayout } from '@/features/network/services/networkGroups';
import { getProtocolColor } from '@/features/network/constants';
import { TONES_LIGHT } from './groupBoxes';

/**
 * The network map as a draw.io diagram (an uncompressed .drawio file), for an analyst to finish in
 * draw.io. Every group is a container shape nested in its parent's, so moving a box in draw.io
 * carries what's in it; every device is one of draw.io's network shapes (server, router, laptop…)
 * labelled as on screen; conversations are one line per device pair, in the protocol's colour.
 * Coordinates are the map's own, so the diagram opens laid out the way TracePcap drew it.
 */

/** draw.io's built-in network shapes, by device family. */
const SHAPES: Record<string, string> = {
  Servers: 'mxgraph.networks.server',
  Routers: 'mxgraph.networks.router',
  'Laptops and desktops': 'mxgraph.networks.laptop',
  'Phones and tablets': 'mxgraph.networks.mobile',
  'Layer-2 devices': 'mxgraph.networks.switch',
  'IoT devices': 'mxgraph.networks.pc',
};
const DEVICE_W = 44;
const DEVICE_H = 36;

function xml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** An html=1 label: lines joined by <br>, each line's own markup escaped first. */
function label(lines: string[]): string {
  return xml(lines.map(l => xml(l)).join('<br>'));
}

function boxStyle(b: GroupBox): string {
  const tone = TONES_LIGHT[(b.tone ?? 0) % TONES_LIGHT.length];
  const base = 'rounded=1;arcSize=3;whiteSpace=wrap;html=1;container=1;collapsible=0;recursiveResize=0;verticalAlign=top;align=left;spacingLeft=10;spacingTop=2;';
  const size = b.level === 1 ? 16 : b.level === 2 ? 14 : 12;
  const look: Record<string, string> = {
    local: 'fillColor=#ECEEF3;strokeColor=#C9CED8;fontColor=#1F2937;',
    internet: 'fillColor=#E8F0FE;strokeColor=#B7CDF5;fontColor=#1E3A8A;',
    special: 'fillColor=#F1F2F4;strokeColor=#D4D7DD;fontColor=#1F2937;',
    network: `fillColor=${tone};fillOpacity=8;strokeColor=${tone};dashed=1;fontColor=${tone};`,
    subnet: 'fillColor=#FFFFFF;strokeColor=#D3D7E0;fontColor=#1F2937;',
    domain: 'fillColor=#FFFFFF;strokeColor=#B7CDF5;fontColor=#1E3A8A;',
    type: 'fillColor=#F7F8FB;strokeColor=#E3E6EC;fontColor=#4B5563;',
  };
  return `${base}${look[b.kind] ?? look.type}fontSize=${size};fontStyle=1;`;
}

/** Each box's parent: the smallest box one level up that holds it. */
function parentsOf(boxes: GroupBox[]): Map<string, GroupBox | undefined> {
  const m = new Map<string, GroupBox | undefined>();
  for (const b of boxes) {
    const holders = boxes.filter(
      p => p.level === b.level - 1 && p.x <= b.x && p.y <= b.y && p.x + p.w >= b.x + b.w && p.y + p.h >= b.y + b.h,
    );
    m.set(b.id, holders.sort((a, c) => a.w * a.h - c.w * c.h)[0]);
  }
  return m;
}

export function toDrawio(
  layout: GroupedLayout,
  nodes: GraphNode[],
  edges: GraphEdge[],
  linesOf: (n: GraphNode) => string[],
  title = 'Network map',
): string {
  const cells: string[] = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>'];
  const parents = parentsOf(layout.boxes);
  const cellId = new Map<string, string>();
  layout.boxes.forEach((b, i) => cellId.set(b.id, `g${i}`));

  // Containers first, parents before children (boxes come out of the layout in that order).
  for (const b of layout.boxes) {
    const p = parents.get(b.id);
    const x = p ? b.x - p.x : b.x;
    const y = p ? b.y - p.y : b.y;
    const name = `${b.label} · ${b.count} ${b.count === 1 ? 'device' : 'devices'}`;
    const value = label([name, b.detail, b.note].filter((x): x is string => !!x));
    cells.push(
      `<mxCell id="${cellId.get(b.id)}" value="${value}" style="${boxStyle(b)}" vertex="1" parent="${p ? cellId.get(p.id) : '1'}">` +
        `<mxGeometry x="${Math.round(x)}" y="${Math.round(y)}" width="${Math.round(b.w)}" height="${Math.round(b.h)}" as="geometry"/></mxCell>`,
    );
  }

  // Devices, inside their innermost box.
  const byId = new Map(nodes.map(n => [n.id, n]));
  const deviceId = new Map<string, string>();
  let d = 0;
  for (const [id, pos] of layout.positions) {
    const n = byId.get(id);
    if (!n) continue;
    const inner = layout.boxes.filter(b => b.memberIds.includes(id)).sort((a, b) => b.level - a.level)[0];
    const x = pos.x - DEVICE_W / 2 - (inner?.x ?? 0);
    const y = pos.y - DEVICE_H / 2 - (inner?.y ?? 0);
    const shape = SHAPES[familyOf(n)];
    const style = shape
      ? `shape=${shape};html=1;whiteSpace=wrap;fillColor=#FFFFFF;strokeColor=#4B5563;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;fontSize=10;`
      : 'ellipse;html=1;whiteSpace=wrap;fillColor=#FFFFFF;strokeColor=#6B7280;labelPosition=center;verticalLabelPosition=bottom;align=center;verticalAlign=top;fontSize=10;';
    const cid = `d${d++}`;
    deviceId.set(id, cid);
    cells.push(
      `<mxCell id="${cid}" value="${label(linesOf(n))}" style="${style}" vertex="1" parent="${inner ? cellId.get(inner.id) : '1'}">` +
        `<mxGeometry x="${Math.round(x)}" y="${Math.round(y)}" width="${DEVICE_W}" height="${DEVICE_H}" as="geometry"/></mxCell>`,
    );
  }

  // One line per device pair, in the colour of its first protocol.
  const seen = new Set<string>();
  let e = 0;
  for (const edge of edges) {
    const a = deviceId.get(edge.source);
    const b = deviceId.get(edge.target);
    if (!a || !b || a === b) continue;
    const key = a < b ? `${a}|${b}` : `${b}|${a}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const color = getProtocolColor(edge.data.protocol ?? '');
    cells.push(
      `<mxCell id="e${e++}" style="endArrow=none;html=1;strokeColor=${color};opacity=60;" edge="1" parent="1" source="${a}" target="${b}">` +
        `<mxGeometry relative="1" as="geometry"/></mxCell>`,
    );
  }

  return (
    `<mxfile host="TracePcap"><diagram id="network-map" name="${xml(title)}">` +
    `<mxGraphModel grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="0" pageScale="1" math="0" shadow="0">` +
    `<root>${cells.join('')}</root></mxGraphModel></diagram></mxfile>`
  );
}

/** Saves the diagram as `<name>.drawio`. */
export function downloadDrawio(xmlText: string, fileName: string): void {
  const url = URL.createObjectURL(new Blob([xmlText], { type: 'application/xml' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName.endsWith('.drawio') ? fileName : `${fileName}.drawio`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
