/**
 * Renders both ELK network diagram layouts (force-directed + hierarchical) to
 * base64-encoded PNG strings suitable for embedding in a PDF report.
 *
 * Uses the exact same ELK options, colour logic, and data pipeline as
 * NetworkGraph.tsx — no html2canvas, no browser screenshot, no timing hacks.
 */

import ELK from 'elkjs';
import type { Node, Edge } from '@xyflow/react';
import { conversationService } from '@/features/conversation/services/conversationService';
import { networkService } from '@/features/network/services/networkService';
import { getProtocolColor } from '@/features/network/constants';
import { NODE_TYPE_COLORS } from '@/features/network/constants';
import { deviceTypeColor } from '@/utils/deviceType';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import type { AnalysisSummary } from '@/types';

// ── constants matching NetworkGraph.tsx ──────────────────────────────────────

const NODE_W = 56;
const NODE_H = 56;
const MAX_CONVERSATIONS = 500;

const ELK_OPTIONS: Record<string, Record<string, string>> = {
  hierarchicalTd: {
    'elk.algorithm': 'layered',
    'elk.direction': 'DOWN',
    'elk.separateConnectedComponents': 'true',
    'elk.spacing.componentComponent': '80',
    'elk.layered.spacing.nodeNodeBetweenLayers': '80',
    'elk.spacing.nodeNode': '40',
    'elk.edgeRouting': 'SPLINES',
  },
  forceDirected2d: {
    'elk.algorithm': 'org.eclipse.elk.force',
    'elk.separateConnectedComponents': 'true',
    'elk.spacing.nodeNode': '80',
    'elk.force.iterations': '500',
    'elk.force.repulsion': '5.0',
  },
};

const SPECIFIC_NODE_TYPES = new Set([
  'dns-server', 'web-server', 'ssh-server', 'ftp-server',
  'mail-server', 'dhcp-server', 'ntp-server', 'database-server', 'router',
]);

const elk = new ELK();

// ── colour helpers (mirrors NetworkGraph.tsx) ────────────────────────────────

function getNodeColor(nodeData: {
  role: string;
  isAnomaly: boolean;
  nodeType?: string;
  deviceType?: string;
}): string {
  if (nodeData.isAnomaly) return NODE_TYPE_COLORS['anomaly'];
  if (nodeData.nodeType && SPECIFIC_NODE_TYPES.has(nodeData.nodeType))
    return NODE_TYPE_COLORS[nodeData.nodeType];
  if (nodeData.deviceType && nodeData.deviceType !== 'UNKNOWN')
    return deviceTypeColor(nodeData.deviceType);
  if (nodeData.nodeType && NODE_TYPE_COLORS[nodeData.nodeType])
    return NODE_TYPE_COLORS[nodeData.nodeType];
  switch (nodeData.role) {
    case 'server': return '#2ecc71';
    case 'both':   return '#9b59b6';
    default:       return '#95a5a6';
  }
}

// ── dedup + offset (mirrors NetworkGraph.tsx) ─────────────────────────────────

function deduplicateEdges(edges: GraphEdge[]): GraphEdge[] {
  const groups = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    const appOrProto = (e.data.appName ?? e.data.protocol).toLowerCase();
    const key = `${e.source}\0${e.target}\0${appOrProto}`;
    const g = groups.get(key) ?? [];
    g.push(e);
    groups.set(key, g);
  }
  const result: GraphEdge[] = [];
  for (const group of groups.values()) {
    if (group.length === 1) { result.push(group[0]); continue; }
    const dominant = group.reduce((best, e) =>
      e.data.packetCount > best.data.packetCount ? e : best);
    const totalPackets = group.reduce((s, e) => s + e.data.packetCount, 0);
    const totalBytes   = group.reduce((s, e) => s + e.data.totalBytes,  0);
    const raw = dominant.data.appName ?? dominant.data.protocol;
    const displayName = raw.charAt(0).toUpperCase() + raw.slice(1);
    result.push({
      ...dominant,
      id: group.map(e => e.id).join('|'),
      label: `${displayName} (${totalPackets})`,
      data: { ...dominant.data, packetCount: totalPackets, totalBytes },
    });
  }
  return result;
}

function assignEdgeOffsets(edges: GraphEdge[]): Map<string, number> {
  const groups = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    const key = [e.source, e.target].sort().join('\0');
    const g = groups.get(key) ?? [];
    g.push(e);
    groups.set(key, g);
  }
  const offsetMap = new Map<string, number>();
  for (const group of groups.values()) {
    if (group.length === 1) { offsetMap.set(group[0].id, 0); continue; }
    const step = 20;
    const mid  = (group.length - 1) / 2;
    group.forEach((e, i) => offsetMap.set(e.id, (i - mid) * step));
  }
  return offsetMap;
}

// ── ELK layout (mirrors computeLayout in NetworkGraph.tsx) ───────────────────

interface LayoutResult {
  rfNodes: Node[];
  rfEdges: Edge[];
}

async function computeLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  layoutType: 'forceDirected2d' | 'hierarchicalTd',
): Promise<LayoutResult> {
  // For hierarchical, drop unconnected nodes (same as NetworkGraph.tsx)
  let visibleNodes = nodes;
  if (layoutType === 'hierarchicalTd') {
    const connected = new Set(edges.flatMap(e => [e.source, e.target]));
    visibleNodes = nodes.filter(n => connected.has(n.id));
  }

  const dedupedEdges = deduplicateEdges(edges);
  const offsetMap    = assignEdgeOffsets(dedupedEdges);

  const graph = await elk.layout({
    id: 'root',
    layoutOptions: ELK_OPTIONS[layoutType],
    children: visibleNodes.map(n => ({ id: n.id, width: NODE_W, height: NODE_H })),
    edges: dedupedEdges.map(e => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  });

  const posMap = new Map(
    (graph.children ?? []).map(n => [n.id, { x: n.x ?? 0, y: n.y ?? 0 }]),
  );

  const rfNodes: Node[] = visibleNodes.map(n => ({
    id: n.id,
    type: 'networkNode',
    position: posMap.get(n.id) ?? { x: 0, y: 0 },
    data: {
      label: n.label,
      color: getNodeColor(n.data),
    },
    width: NODE_W,
    height: NODE_H,
  }));

  const rfEdges: Edge[] = dedupedEdges.map(e => ({
    id: e.id,
    source: e.source,
    target: e.target,
    data: { label: e.label ?? '', offset: offsetMap.get(e.id) ?? 0 },
    style: { stroke: getProtocolColor(e.data.protocol), strokeWidth: 1.5 },
  }));

  return { rfNodes, rfEdges };
}

// ── SVG renderer ──────────────────────────────────────────────────────────────

const SVG_W = 1400;
const SVG_H = 860;
const TITLE_H = 36;
const PADDING = 55;

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function layoutToSvg(
  { rfNodes, rfEdges }: LayoutResult,
  title: string,
): string {
  if (rfNodes.length === 0) {
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${SVG_W}" height="${SVG_H}">
      <rect width="${SVG_W}" height="${SVG_H}" fill="#f8fafc"/>
      <rect width="${SVG_W}" height="${TITLE_H}" fill="#1e40af"/>
      <text x="14" y="24" font-size="15" font-weight="bold" fill="white"
            font-family="Arial,Helvetica,sans-serif">${esc(title)}</text>
      <text x="${SVG_W / 2}" y="${SVG_H / 2}" text-anchor="middle"
            font-size="16" fill="#94a3b8" font-family="Arial,Helvetica,sans-serif">
        No network data available
      </text>
    </svg>`;
  }

  // Bounding box
  const xs = rfNodes.map(n => n.position.x);
  const ys = rfNodes.map(n => n.position.y);
  const minX = Math.min(...xs);
  const minY = Math.min(...ys);
  const maxX = Math.max(...xs) + NODE_W;
  const maxY = Math.max(...ys) + NODE_H;
  const contentW = maxX - minX || 1;
  const contentH = maxY - minY || 1;

  const availW = SVG_W - 2 * PADDING;
  const availH = SVG_H - TITLE_H - 2 * PADDING;
  const scale = Math.min(availW / contentW, availH / contentH);

  const tx = (x: number) => PADDING + (x - minX) * scale;
  const ty = (y: number) => TITLE_H + PADDING + (y - minY) * scale;
  const cx = (x: number) => tx(x) + (NODE_W * scale) / 2;
  const cy = (y: number) => ty(y) + (NODE_H * scale) / 2;

  const nodePos = new Map(rfNodes.map(n => [n.id, n.position]));

  const parts: string[] = [];

  parts.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${SVG_W}" height="${SVG_H}">`);
  parts.push(`<rect width="${SVG_W}" height="${SVG_H}" fill="#f8fafc"/>`);

  // Subtle dot grid
  parts.push(`<pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
    <circle cx="10" cy="10" r="0.8" fill="#cbd5e1"/>
  </pattern>
  <rect x="0" y="${TITLE_H}" width="${SVG_W}" height="${SVG_H - TITLE_H}" fill="url(#grid)"/>`);

  // ── Edges ────────────────────────────────────────────────────────────────
  for (const edge of rfEdges) {
    const sp = nodePos.get(edge.source);
    const tp = nodePos.get(edge.target);
    if (!sp || !tp) continue;

    const sx = cx(sp.x);
    const sy = cy(sp.y);
    const ex = cx(tp.x);
    const ey = cy(tp.y);
    const offset = (edge.data as { offset?: number }).offset ?? 0;
    const color  = (edge.style?.stroke as string) ?? '#95a5a6';
    const label  = (edge.data as { label?: string }).label ?? '';

    // Perpendicular offset (same math as NetworkEdge component)
    const canonicalDir = sx < ex || (sx === ex && sy <= ey);
    const cdx = canonicalDir ? ex - sx : sx - ex;
    const cdy = canonicalDir ? ey - sy : sy - ey;
    const len = Math.sqrt(cdx * cdx + cdy * cdy) || 1;
    const px = (-cdy / len) * offset;
    const py = ( cdx / len) * offset;

    const x1 = sx + px; const y1 = sy + py;
    const x2 = ex + px; const y2 = ey + py;

    // Line
    parts.push(`<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}"
      x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}"
      stroke="${esc(color)}" stroke-width="1.5" opacity="0.75"/>`);

    // Arrowhead at midpoint
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const angle = Math.atan2(y2 - y1, x2 - x1) * 180 / Math.PI;
    parts.push(`<polygon points="-5,-3 5,0 -5,3"
      transform="translate(${mx.toFixed(1)},${my.toFixed(1)}) rotate(${angle.toFixed(1)})"
      fill="${esc(color)}" opacity="0.85"/>`);

    // Label (only if non-trivial)
    if (label && label.length < 40) {
      const lx = x1 + (x2 - x1) * 0.3;
      const ly = y1 + (y2 - y1) * 0.3 - 4;
      const tw = Math.min(label.length * 5.5, 100);
      parts.push(
        `<rect x="${(lx - tw / 2).toFixed(1)}" y="${(ly - 9).toFixed(1)}"
          width="${tw.toFixed(1)}" height="12" rx="2"
          fill="white" fill-opacity="0.85"/>`,
        `<text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}"
          text-anchor="middle" font-size="7.5" fill="#444"
          font-family="Arial,Helvetica,sans-serif">${esc(label)}</text>`,
      );
    }
  }

  // ── Nodes ────────────────────────────────────────────────────────────────
  const nodeR = Math.max(18, Math.min(28, (NODE_W * scale) / 2 - 2));

  for (const node of rfNodes) {
    const color = (node.data as { color?: string }).color ?? '#95a5a6';
    const label = (node.data as { label?: string }).label ?? node.id;
    const ncx   = cx(node.position.x);
    const ncy   = cy(node.position.y);

    // Outer circle with device-type colour
    parts.push(`<circle cx="${ncx.toFixed(1)}" cy="${ncy.toFixed(1)}"
      r="${nodeR}"
      fill="${esc(color)}" fill-opacity="0.15"
      stroke="${esc(color)}" stroke-width="2.5"/>`);

    // Label lines (split at '\n' if present, or truncate)
    const labelLines = label.includes('\n')
      ? label.split('\n')
      : [label];
    const firstLine = labelLines[0] ?? '';
    const secondLine = labelLines[1] ?? '';

    const fontSize = Math.max(6, Math.min(9, (nodeR * 0.55)));

    // Primary label inside circle
    parts.push(`<text x="${ncx.toFixed(1)}" y="${(ncy + fontSize * 0.35).toFixed(1)}"
      text-anchor="middle" font-size="${fontSize.toFixed(1)}"
      fill="${esc(color)}" font-weight="bold"
      font-family="'Courier New',monospace">${esc(firstLine)}</text>`);

    // Secondary line below circle
    if (secondLine) {
      parts.push(`<text x="${ncx.toFixed(1)}" y="${(ncy + nodeR + 12).toFixed(1)}"
        text-anchor="middle" font-size="7.5" fill="#64748b"
        font-family="Arial,Helvetica,sans-serif">${esc(secondLine)}</text>`);
    } else {
      // Show node.id (IP) if label doesn't already include it
      const ip = node.id;
      if (ip !== label) {
        parts.push(`<text x="${ncx.toFixed(1)}" y="${(ncy + nodeR + 12).toFixed(1)}"
          text-anchor="middle" font-size="7.5" fill="#64748b"
          font-family="'Courier New',monospace">${esc(ip)}</text>`);
      }
    }
  }

  // ── Title bar ────────────────────────────────────────────────────────────
  parts.push(`<rect width="${SVG_W}" height="${TITLE_H}" fill="#1e40af"/>`);
  parts.push(`<text x="14" y="24" font-size="14" font-weight="bold" fill="white"
    font-family="Arial,Helvetica,sans-serif">${esc(title)}</text>`);
  parts.push(`<text x="${SVG_W - 14}" y="24" font-size="11" fill="#93c5fd"
    text-anchor="end" font-family="Arial,Helvetica,sans-serif">
    ${rfNodes.length} nodes · ${rfEdges.length} connections
  </text>`);

  parts.push('</svg>');
  return parts.join('\n');
}

// ── SVG → base64 PNG via Canvas ───────────────────────────────────────────────

function svgToBase64Png(svgStr: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const img  = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width  = SVG_W;
      canvas.height = SVG_H;
      const ctx = canvas.getContext('2d')!;
      ctx.fillStyle = '#f8fafc';
      ctx.fillRect(0, 0, SVG_W, SVG_H);
      ctx.drawImage(img, 0, 0, SVG_W, SVG_H);
      URL.revokeObjectURL(url);
      resolve(canvas.toDataURL('image/png').split(',')[1]);
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('SVG→PNG failed')); };
    img.src = url;
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface DiagramImages {
  forceDirected: string; // base64 PNG
  hierarchical: string;  // base64 PNG
}

export async function captureNetworkDiagrams(
  fileId: string,
  analysisSummary?: AnalysisSummary,
): Promise<DiagramImages> {
  // 1. Fetch conversation + host data (same as useNetworkData)
  const response = await conversationService.getConversations(fileId, {
    ip: '', port: '', payloadContains: '',
    protocols: [], l7Protocols: [], apps: [], categories: [],
    hasRisks: false, fileTypes: [], riskTypes: [], customSignatures: [],
    deviceTypes: [], countries: [],
    sortBy: '', sortDir: 'asc',
    page: 1, pageSize: 10000,
  });

  let hostClassifications;
  try {
    hostClassifications = await conversationService.getHostClassifications(fileId);
  } catch { /* optional — best effort */ }

  // 2. Build graph (same as useNetworkData)
  const graphData = networkService.buildNetworkGraph(
    response.data, analysisSummary, MAX_CONVERSATIONS, hostClassifications,
  );

  const { nodes, edges } = graphData;

  // 3. Run both ELK layouts
  const [fdLayout, hierLayout] = await Promise.all([
    computeLayout(nodes, edges, 'forceDirected2d'),
    computeLayout(nodes, edges, 'hierarchicalTd'),
  ]);

  // 4. Render SVG → PNG
  const fdSvg   = layoutToSvg(fdLayout,   'Force-Directed Layout');
  const hierSvg = layoutToSvg(hierLayout, 'Hierarchical Layout (Top-Down)');

  const [forceDirected, hierarchical] = await Promise.all([
    svgToBase64Png(fdSvg),
    svgToBase64Png(hierSvg),
  ]);

  return { forceDirected, hierarchical };
}
