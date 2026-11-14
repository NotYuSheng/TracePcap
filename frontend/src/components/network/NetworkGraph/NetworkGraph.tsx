import { Spinner } from '@components/common/Spinner/Spinner';
import { useEffect, useRef, useState, useCallback, useMemo, memo } from 'react';
import ELK from 'elkjs';
const ELK_WORKER_URL = `${import.meta.env.BASE_URL}elk-worker.min.js`;
import Graph from 'graphology';
import Sigma from 'sigma';
import { EdgeArrowProgram } from 'sigma/rendering';
import { EdgeCurvedArrowProgram, indexParallelEdgesIndex } from '@sigma/edge-curve';
import { animatedEdges, drawDeviceLinks, drawEffects, drawFlights, drawParticles, windowEffects, type GraphEffect, type LiveFlight } from './trafficParticles';

const EMPTY_LINKS: { from: string; to: string; label: string }[] = [];
import circular from 'graphology-layout/circular';
import noverlap from 'graphology-layout-noverlap';
import type { GraphNode, GraphEdge, GraphLayoutType } from '@/features/network/types';
import { buildGroupTree, layoutGroups, CELL_H, CELL_W, NODE_TOP, type GroupedLayout } from '@/features/network/services/networkGroups';
import type { NetworkSegment } from '@/features/networkSegments/networkSegmentService';
import type { CustomPrivateRange } from '@/features/cluster/types/customPrivateRange.types';
import { drawGroupBoxes } from './groupBoxes';
import { getProtocolColor, NODE_TYPE_CONFIG, buildProtocolLegend, buildAppLegend, DEFAULT_EDGE_COLOR } from '@/features/network/constants';
import { getAppColor } from '@/utils/appColors';
import { makeVolumeEdgeColor } from '@/utils/volumeColor';
import { deviceTypeIcon, deviceTypeLabel, DEVICE_TYPES } from '@/utils/deviceType';
import { useStore } from '@/store';
import { GENERIC_NODE_TYPES, getNodeIcon } from './nodeIcons';
import { buildNodeLines } from './nodeLines';
import './NetworkGraph.css';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface NodeHighlight {
  color: string;
  label: string;
  description?: string;
}

export type EdgeColorMode = 'transport' | 'application' | 'volume';

interface NetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (node: GraphNode) => void;
  onClusterClick?: (clusterId: string) => void;
  layoutType?: GraphLayoutType;
  onLayoutChange?: (layout: GraphLayoutType) => void;
  onLayoutComplete?: () => void;
  primarySource?: string;
  hiddenNodesList?: GraphNode[];
  crossEdges?: GraphEdge[];
  onFilterClick?: () => void;
  activeFilterCount?: number;
  /** Monitor mode: map of node label (IP/MAC) → highlight colour + badge text */
  highlightedNodes?: Map<string, NodeHighlight>;
  /**
   * The time axis's window: what was active in it. Nodes outside it are dimmed and edges outside it
   * hidden, by redrawing only, so the layout never moves while the window plays. Null shows all.
   */
  activeInWindow?: { nodeIds: Set<string>; edgeIds: Set<string>; hiddenNodeIds?: Set<string>; faintNodeIds?: Set<string>; window?: { from: number; to: number } } | null;
  /**
   * Called when Fit view is pressed again with the graph already fitted: nothing visibly happens, so
   * the user is probably after the header's fullscreen button (the two used to share an icon).
   */
  onFitViewRepeated?: () => void;
  /** Networks found from DHCP/VLANs (#462): the network map layout's second level. */
  networkSegments?: NetworkSegment[];
  /** The user's private-range overrides: what counts as "Your networks" in the network map. */
  customPrivateRanges?: CustomPrivateRange[];
  /** Address → the name clients looked it up by: the network map's domain for unnamed hosts. */
  dnsNames?: Map<string, string>;
  /**
   * Packet replay's current moment: its packets fly along their edges. A new `key` launches them;
   * null when the replay is off.
   */
  packetFlights?: { key: number; flights: { from: string; to: string; color: string }[]; durationMs: number } | null;
  /** A bar along the bottom of the graph (the time axis); the legend and controls move up for it. */
  bottomBar?: import('react').ReactNode;
  /** Dots moving along the visible edges, in the edge's colour; more on busier conversations. */
  animateTraffic?: boolean;
  /** One device on two nodes (it moved to another address): drawn as dashed links. */
  deviceLinks?: { from: string; to: string; at?: number; label: string; hideLabel?: boolean }[];
  /**
   * What edge colour encodes. Protocol (the default) uses `getProtocolColor`;
   * volume shades each edge by `totalBytes` on the shared volume scale — the same
   * ramp the node-to-node heatmap uses. Note an edge is one protocol/app between a
   * pair (see `deduplicateEdges`), while a heatmap cell is the pair's total across
   * all protocols, so the two agree exactly only for single-protocol pairs.
   *
   * <p>These are mutually exclusive by design: colour is one channel, and showing
   * two meanings at once would make neither legible. Whichever is active needs a
   * legend rendered by the caller.
   */
  edgeColorMode?: EdgeColorMode;
  /**
   * Render light regardless of the user's theme — for PDF capture, which always wants white
   * diagrams (see captureNetworkDiagrams.ts).
   *
   * <p>A prop rather than a CSS override because this component picks its colours in JavaScript,
   * from the theme store and matchMedia. No amount of CSS on an ancestor reaches them: the capture
   * used to set data-theme="light" on <html> and it never worked — it only made the page strobe.
   */
  forceLight?: boolean;
}

// ---------------------------------------------------------------------------
// Node visual helpers
// ---------------------------------------------------------------------------

const DARK_BG = '#0f1117';
/** Dashed ring for contested identities (#512 slice 5b) — amber, matches NodeDetails' bg-warning badge. */
const CONTESTED_COLOR = '#f59e0b';
const DARK_SURFACE = '#1e2130';
const LIGHT_BG = '#f6f8fa';

/**
 * Sidecar maps: label → nodeType and label → deviceType.
 * Sigma strips custom graph attributes before calling defaultDrawNodeLabel —
 * only standard NodeDisplayData fields survive (x, y, size, color, label…).
 * We key by label (the node's IP / hostname) which is unique per graph.
 * Stored as refs so they are instance-local and never shared across remounts.
 */

/**
 * Draws the full node appearance on the 2D canvas layer.
 *
 * Strategy: node `color` in NodeDisplayData IS the accent color (so Sigma's
 * WebGL circle draws the accent color underneath). This function overdraws:
 *   1. White filled circle (covers the WebGL accent circle)
 *   2. Accent-colored border ring
 *   3. Accent-colored Bootstrap Icon centered inside
 *   4. Text label below
 */

function drawNodeLabel(
  ctx: CanvasRenderingContext2D,
  data: { key?: string; x: number; y: number; size: number; label: string | null; color: string },
  labelColor: string,
  nodeFill: string,
  ntMap: Map<string, string>,
  dtMap: Map<string, string>,
  linesMap: Map<string, string[]>,
  hlMap?: Map<string, NodeHighlight>,
  contestedMap?: Map<string, boolean>,
  fit?: { w: number; below: number } | null,
): void {
  const { x, y, size, label, color: accentColor } = data;
  // The per-node sidecars are keyed by node id: two nodes can share a label (one device that moved
  // to another address, or two devices that shared one, both named by the same hostname).
  const id = data.key ?? label ?? '';
  const nodeType = ntMap.get(id) ?? 'unknown';
  const deviceType = dtMap.get(id) ?? '';
  // Change highlights (Monitor) name nodes by their label (IP or MAC).
  const highlight = label ? hlMap?.get(label) : undefined;
  const contested = contestedMap?.get(id) ?? false;

  // Outer glow ring for highlighted (changed) nodes
  if (highlight) {
    ctx.beginPath();
    ctx.arc(x, y, size + size * 0.45, 0, Math.PI * 2);
    ctx.strokeStyle = highlight.color;
    ctx.lineWidth = size * 0.22;
    ctx.globalAlpha = 0.55;
    ctx.stroke();
    ctx.globalAlpha = 1;
  }

  // Fill — covers the WebGL accent circle underneath
  ctx.beginPath();
  ctx.arc(x, y, size, 0, Math.PI * 2);
  ctx.fillStyle = nodeFill;
  ctx.fill();

  // Accent border ring
  ctx.beginPath();
  ctx.arc(x, y, size, 0, Math.PI * 2);
  ctx.strokeStyle = highlight ? highlight.color : accentColor;
  ctx.lineWidth = highlight ? Math.max(2, size * 0.12) : Math.max(1, size * 0.07);
  ctx.stroke();

  // Contested-identity ring (#512 slice 5b, #498): dashed amber outside the accent ring —
  // the adjudicator found competing answers, so the node must read as a question, not a fact.
  if (contested) {
    ctx.beginPath();
    ctx.setLineDash([size * 0.35, size * 0.25]);
    ctx.arc(x, y, size + size * 0.3, 0, Math.PI * 2);
    ctx.strokeStyle = CONTESTED_COLOR;
    ctx.lineWidth = Math.max(1.5, size * 0.1);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // Bootstrap Icon — reflects the same logic as getNodeColor/getNodeIcon
  const cp = getNodeIcon(nodeType, deviceType);
  ctx.font = `${size * 0.9}px "bootstrap-icons"`;
  ctx.fillStyle = accentColor;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(cp, x, y);

  // Text label(s) below — one line per configured field.
  // An empty label means the node is dimmed (hover) and should draw no text.
  let lines = label ? linesMap.get(id) ?? linesMap.get(label) ?? [label] : [];
  if (fit && lines.length > 0) {
    // A cell of the network map: as many lines as fit under the node, each cut to the cell's width,
    // so neighbours never overlap; zooming in shows the rest.
    const room = Math.floor((fit.below - size - 8) / 13);
    lines = lines.slice(0, Math.max(0, room));
    ctx.font = `500 11px Inter, system-ui, sans-serif`;
    const maxW = fit.w - 10;
    lines = lines.map(l => {
      if (ctx.measureText(l).width <= maxW) return l;
      let t = l;
      while (t.length > 1 && ctx.measureText(t + '…').width > maxW) t = t.slice(0, -1);
      return t.length > 1 ? t + '…' : '';
    }).filter(Boolean);
  }
  if (lines.length > 0) {
    ctx.font = `500 11px Inter, system-ui, sans-serif`;
    ctx.fillStyle = labelColor;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    let lineY = y + size + 3;
    for (const line of lines) {
      ctx.fillText(line, x, lineY);
      lineY += 13;
    }
  }
}

/**
 * The node's colour, from its adjudicated nodeType.
 *
 * <p>This used to adjudicate: nodeType-wins-else-deviceType-else-fallback, resolving two competing
 * classifications by display precedence — in the browser, with no confidence and no contested
 * state (#521, #499). But nodeType is now a projection of the backend's host-identity adjudication
 * (see networkService's applyIdentities), so it already *is* the one answer. There is nothing left
 * to resolve; the colour just follows it.
 */
function getNodeColor(node: GraphNode): string {
  const { nodeType } = node.data;
  return NODE_TYPE_CONFIG[nodeType as keyof typeof NODE_TYPE_CONFIG]?.color ?? '#95a5a6';
}

// ---------------------------------------------------------------------------
// Deduplicate & normalise edges (ported from old NetworkGraph)
// ---------------------------------------------------------------------------

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
    const dominant = group.reduce((b, e) => e.data.packetCount > b.data.packetCount ? e : b);
    const totalPackets = group.reduce((s, e) => s + e.data.packetCount, 0);
    const totalBytes = group.reduce((s, e) => s + e.data.totalBytes, 0);
    const raw = dominant.data.appName ?? dominant.data.protocol;
    const display = raw.charAt(0).toUpperCase() + raw.slice(1);
    result.push({
      ...dominant,
      id: group.map(e => e.id).join('|'),
      label: `${display} (${totalPackets})`,
      data: { ...dominant.data, packetCount: totalPackets, totalBytes },
    });
  }
  return result;
}


/**
 * Range of positive edge volumes, used to fit the volume colour scale.
 * Exported so a caller rendering the legend derives the exact same domain the
 * edges are painted with — a legend fitted to a different range would lie.
 */
export function edgeBytesRange(edges: GraphEdge[]): { min: number; max: number } {
  let max = 0;
  let min = Infinity;
  for (const e of edges) {
    const b = e.data.totalBytes ?? 0;
    if (b <= 0) continue;
    if (b > max) max = b;
    if (b < min) min = b;
  }
  return { min: Number.isFinite(min) ? min : 1, max };
}

// ---------------------------------------------------------------------------
// Parallel-edge curvature
// ---------------------------------------------------------------------------

/**
 * Curvature for the edge at `index` within a parallel group of `maxIndex + 1` edges. Zero-index
 * edges stay flat; the rest fan out symmetrically. `amplitude` keeps big groups from curving so hard
 * they cross each other. Mirrors the reference implementation from `@sigma/edge-curve`.
 */
function getCurvature(index: number, maxIndex: number): number {
  // `!maxIndex` also rejects undefined/null/NaN (a missing parallel-index attribute) — those would
  // otherwise sail past `<= 0` and produce NaN curvature.
  if (!maxIndex || maxIndex <= 0) return 0;
  if (index < 0) return -getCurvature(-index, maxIndex);
  const amplitude = 3.5;
  const maxCurvature = (amplitude * (1 - Math.exp(-maxIndex / amplitude))) / maxIndex;
  return (maxCurvature * index) / maxIndex;
}

/**
 * When two nodes are joined by more than one edge — a different protocol/app per edge, or one in
 * each direction — straight strokes would draw on top of each other and hide all but one colour
 * (#497). Curve the parallels apart so every edge (and its protocol colour) is visible; edges with a
 * single connection between their endpoints stay straight. Reads the parallel-group indices that
 * `indexParallelEdgesIndex` writes and sets each edge's render `type` + `curvature` accordingly.
 */
function applyParallelEdgeCurvature(graph: Graph): void {
  indexParallelEdgesIndex(graph, {
    edgeIndexAttribute: 'parallelIndex',
    edgeMinIndexAttribute: 'parallelMinIndex',
    edgeMaxIndexAttribute: 'parallelMaxIndex',
  });
  graph.forEachEdge((edge, attrs) => {
    const parallelIndex = attrs.parallelIndex as number | null | undefined;
    const parallelMinIndex = attrs.parallelMinIndex as number | null | undefined;
    const parallelMaxIndex = attrs.parallelMaxIndex as number | null | undefined;

    if (typeof parallelMinIndex === 'number') {
      // Group spans both directions: the middle edge stays straight, the rest curve.
      graph.mergeEdgeAttributes(edge, {
        type: parallelIndex ? 'curved' : 'arrow',
        curvature: getCurvature(parallelIndex as number, parallelMaxIndex as number),
      });
    } else if (typeof parallelIndex === 'number') {
      // Same-direction parallels: curve them all (index 0 gets 0 curvature → renders straight).
      graph.mergeEdgeAttributes(edge, {
        type: 'curved',
        curvature: getCurvature(parallelIndex, parallelMaxIndex as number),
      });
    } else {
      // The only edge between its endpoints — keep it a straight arrow.
      graph.setEdgeAttribute(edge, 'type', 'arrow');
    }
  });
}

// ---------------------------------------------------------------------------
// Build a graphology graph from GraphNode[] / GraphEdge[]
// ---------------------------------------------------------------------------

function buildGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  primarySource?: string,
  edgeColorMode: EdgeColorMode = 'transport',
  darkMode = false,
): Graph {
  const graph = new Graph({ multi: true, type: 'directed' });

  const nodeIdSet = new Set(nodes.map(n => n.id));
  const validEdges = deduplicateEdges(
    edges.filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target))
  );

  for (const n of nodes) {
    const color = getNodeColor(n);
    const size = n.data.isCluster ? 18 : 12;

    const isSecondaryOnly =
      n.data.sources?.length === 1 &&
      primarySource !== undefined &&
      n.data.sources[0] !== primarySource;

    const nodeType = n.data.isCluster ? 'cluster' : (n.data.nodeType ?? 'unknown');
    graph.addNode(n.id, {
      x: Math.random() * 1000,
      y: Math.random() * 1000,
      size,
      color,
      label: n.label,
      nodeType,
      deviceType: n.data.deviceType ?? '',
      identityContested: !!n.data.identityContested,
      isCluster: !!n.data.isCluster,
      clusterId: n.data.clusterId,
      memberCount: n.data.memberCount ?? 0,
      isSecondaryOnly,
      hidden: false,
    });
  }

  // Fitting the scale to the current view's range means it re-fits whenever
  // filters change, so contrast is never wasted on values nothing reaches.
  const { min: minEdgeBytes, max: maxEdgeBytes } = edgeBytesRange(validEdges);
  const volumeColor = makeVolumeEdgeColor(maxEdgeBytes, darkMode, minEdgeBytes);

  for (const e of validEdges) {
    const isSecondaryOnly =
      e.data.sources?.length === 1 &&
      primarySource !== undefined &&
      e.data.sources[0] !== primarySource;

    const appName = e.data.appName ?? '';
    graph.addEdgeWithKey(e.id, e.source, e.target, {
      color:
        edgeColorMode === 'volume'
          ? volumeColor(e.data.totalBytes ?? 0)
          : edgeColorMode === 'application'
            ? (appName ? getAppColor(appName) : DEFAULT_EDGE_COLOR)
            : getProtocolColor(e.data.protocol),
      size: 1.2,
      label: e.label,
      type: 'arrow',
      isSecondaryOnly,
      packetCount: e.data.packetCount,
      // Kept on the edge so the colour mode can be switched by repainting in
      // place, without rebuilding the graph and throwing away the layout.
      totalBytes: e.data.totalBytes ?? 0,
      bidirectional: !!e.data.bidirectional,
      protocol: e.data.protocol,
      appName,
    });
  }

  // Curve edges that share a node pair so overlapping strokes don't hide each other's colour.
  applyParallelEdgeCurvature(graph);

  return graph;
}

// ---------------------------------------------------------------------------
// Hierarchical layout — ELK layered algorithm (Sugiyama-style)
// ---------------------------------------------------------------------------

const NODE_SIZE = 36; // bounding box for ELK spacing; actual rendered node diameter is 24–36px

async function applyHierarchicalLayout(graph: Graph, elk: InstanceType<typeof ELK>): Promise<void> {
  const nodes: { id: string }[] = [];
  graph.forEachNode(n => nodes.push({ id: n }));

  const edges: { id: string; sources: string[]; targets: string[] }[] = [];
  graph.forEachEdge((key, _attrs, src, tgt) => {
    edges.push({ id: key, sources: [src], targets: [tgt] });
  });

  const elkGraph = await elk.layout({
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'DOWN',
      'elk.separateConnectedComponents': 'true',
      'elk.spacing.componentComponent': '80',
      'elk.layered.spacing.nodeNodeBetweenLayers': '80',
      'elk.spacing.nodeNode': '40',
    },
    children: nodes.map(n => ({ id: n.id, width: NODE_SIZE, height: NODE_SIZE })),
    edges,
  });

  for (const child of elkGraph.children ?? []) {
    if (child.x !== undefined && child.y !== undefined) {
      graph.setNodeAttribute(child.id, 'x', child.x);
      graph.setNodeAttribute(child.id, 'y', child.y);
    }
  }
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

const EMPTY_SEGMENTS: NetworkSegment[] = [];
const EMPTY_RANGES: CustomPrivateRange[] = [];

export const NetworkGraph = memo(function NetworkGraph({
  nodes,
  edges,
  onNodeClick,
  onClusterClick,
  layoutType = 'circular',
  onLayoutChange,
  onLayoutComplete,
  primarySource,
  hiddenNodesList = [],
  crossEdges = [],
  onFilterClick,
  activeFilterCount = 0,
  highlightedNodes,
  activeInWindow = null,
  animateTraffic = false,
  bottomBar,
  deviceLinks = EMPTY_LINKS,
  onFitViewRepeated,
  packetFlights = null,
  networkSegments = EMPTY_SEGMENTS,
  customPrivateRanges = EMPTY_RANGES,
  dnsNames,
  edgeColorMode = 'transport',
  forceLight = false,
}: NetworkGraphProps) {
  const themeMode = useStore(s => s.themeMode);
  const [sysDark, setSysDark] = useState(
    () => window.matchMedia('(prefers-color-scheme: dark)').matches
  );
  useEffect(() => {
    if (themeMode !== 'system') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => setSysDark(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [themeMode]);
  const darkMode =
    !forceLight && (themeMode === 'dark' || (themeMode === 'system' && sysDark));

  const containerRef = useRef<HTMLDivElement>(null);
  const [containerReady, setContainerReady] = useState(false);

  // Watch for the container getting actual width (e.g. modal finishes opening)
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    if (el.offsetWidth > 0) { setContainerReady(true); return; }
    const ro = new ResizeObserver(() => {
      if (el.offsetWidth > 0) { setContainerReady(true); ro.disconnect(); }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const sigmaRef = useRef<Sigma | null>(null);
  // Sigma only re-measures on window resizes; a CSS fullscreen or a resized card would leave its
  // canvases stretched (and the network map's boxes, drawn at the real size, out of line).
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const sigma = sigmaRef.current;
      if (!sigma) return;
      sigma.resize();
      sigma.refresh();
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const graphRef = useRef<Graph | null>(null);
  const nodeTypeByLabel = useRef<Map<string, string>>(new Map());
  const deviceTypeByLabel = useRef<Map<string, string>>(new Map());
  const contestedByLabel = useRef<Map<string, boolean>>(new Map());
  // Per-node text lines (keyed by the node's label), derived from the user's label config.
  const nodeLinesByLabel = useRef<Map<string, string[]>>(new Map());
  const nodeLabelConfig = useStore(s => s.nodeLabelConfig);
  const elkRef = useRef<InstanceType<typeof ELK> | null>(null);
  if (!elkRef.current) {
    elkRef.current = new ELK({
      workerFactory: () => new Worker(ELK_WORKER_URL, { type: 'classic' }),
    });
  }

  const [layouting, setLayouting] = useState(false);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);

  const onLayoutCompleteRef = useRef(onLayoutComplete);
  useEffect(() => { onLayoutCompleteRef.current = onLayoutComplete; });

  const nodesRef = useRef(nodes);
  useEffect(() => { nodesRef.current = nodes; });

  const highlightedNodesRef = useRef(highlightedNodes);
  useEffect(() => {
    highlightedNodesRef.current = highlightedNodes;
    sigmaRef.current?.refresh();
  }, [highlightedNodes]);

  // Traffic dots: an overlay canvas over Sigma's, redrawn every frame while on (and the tab shows).
  const particlesRef = useRef<HTMLCanvasElement>(null);
  // The network map layout: its group boxes, drawn on a canvas under the graph.
  const groupsCanvasRef = useRef<HTMLCanvasElement>(null);
  const groupLayoutRef = useRef<GroupedLayout | null>(null);
  // Dragged nodes keep their place until the layout runs again; this puts them back.
  const [nodesMoved, setNodesMoved] = useState(false);
  const resetLayoutRef = useRef<(() => void) | null>(null);
  // The network map's cell size on screen, refreshed each render: labels are fitted to it.
  const labelFitRef = useRef<{ w: number; below: number } | null>(null);
  // Legend highlight: click a node type or an edge colour to pick out its nodes and edges.
  const [legendFocus, setLegendFocus] = useState<LegendFocus | null>(null);
  const legendMatchRef = useRef<{ nodes: Set<string>; edges: Set<string> } | null>(null);
  const groupingRef = useRef({ segments: networkSegments, customRanges: customPrivateRanges, dnsNames });
  groupingRef.current = { segments: networkSegments, customRanges: customPrivateRanges, dnsNames };
  const deviceLinksRef = useRef(deviceLinks);
  deviceLinksRef.current = deviceLinks;
  const darkRef = useRef(darkMode);
  darkRef.current = darkMode;
  const hasLinks = deviceLinks.length > 0;
  const hasWindow = activeInWindow != null;
  const hasFlights = packetFlights != null;
  // Packet replay: the moment's packets, launched when its key changes.
  const flightsRef = useRef<LiveFlight[]>([]);
  const flightKey = packetFlights?.key;
  useEffect(() => {
    if (!packetFlights) {
      flightsRef.current.length = 0;
      return;
    }
    const now = performance.now();
    for (const f of packetFlights.flights) flightsRef.current.push({ ...f, t0: now, dur: packetFlights.durationMs });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flightKey]);
  // Appear rings and device-move animations, set off as the time window crosses them.
  const effectsRef = useRef<GraphEffect[]>([]);
  useEffect(() => {
    if (!animateTraffic && !hasLinks && !hasWindow && !hasFlights) {
      const c = particlesRef.current;
      c?.getContext('2d')?.clearRect(0, 0, c.width, c.height);
      return;
    }
    let raf = 0;
    let lastSigma: unknown = null;
    let lastSize = -1;
    let edges: ReturnType<typeof animatedEdges> = [];
    const frame = (now: number) => {
      raf = requestAnimationFrame(frame);
      const sigma = sigmaRef.current;
      const canvas = particlesRef.current;
      if (!sigma || !canvas || document.hidden) return;
      // Match the canvas to its box (and the screen's pixel ratio).
      const ratio = window.devicePixelRatio || 1;
      const w = Math.round(canvas.clientWidth * ratio);
      const h = Math.round(canvas.clientHeight * ratio);
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
      }
      const size = sigma.getGraph().size;
      if (sigma !== lastSigma || size !== lastSize) {
        edges = animatedEdges(sigma);
        lastSigma = sigma;
        lastSize = size;
      }
      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      if (animateTraffic) drawParticles(ctx, sigma, edges, now);
      else ctx.clearRect(0, 0, canvas.width, canvas.height);
      drawDeviceLinks(ctx, sigma, deviceLinksRef.current, darkRef.current);
      drawEffects(ctx, sigma, effectsRef.current, now, darkRef.current);
      drawFlights(ctx, sigma, flightsRef.current, now);
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [animateTraffic, hasLinks, hasWindow, hasFlights]);

  const activeInWindowRef = useRef(activeInWindow);
  useEffect(() => {
    const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
    if (!reduced) {
      const fresh = windowEffects(activeInWindowRef.current, activeInWindow, deviceLinksRef.current, performance.now());
      if (fresh.length) effectsRef.current.push(...fresh);
    }
    if (!activeInWindow) effectsRef.current.length = 0;
    activeInWindowRef.current = activeInWindow;
    sigmaRef.current?.refresh();
  }, [activeInWindow]);

  // The network map's grouping can arrive after the graph (segments load separately): regroup.
  useEffect(() => {
    const sigma = sigmaRef.current;
    if (layoutType !== 'grouped' || !sigma) return;
    applyGroupedLayout(sigma, nodesRef.current, groupingRef.current, groupLayoutRef);
    sigma.refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [networkSegments, customPrivateRanges, dnsNames]);

  // Work out what the legend highlight picks out, whenever it or the graph changes. A frame
  // later, so a graph rebuilt or repainted by the effects below is the one matched.
  useEffect(() => {
    const raf = requestAnimationFrame(() => {
      const sigma = sigmaRef.current;
      if (!sigma) return;
      if (!legendFocus) {
        legendMatchRef.current = null;
        sigma.refresh();
        return;
      }
      const graph = sigma.getGraph();
      const matchNodes = new Set<string>();
      const matchEdges = new Set<string>();
      if (legendFocus.kind === 'node') {
        graph.forEachNode((id, a) => {
          if (legendNodeMatches(legendFocus.key, a['nodeType'] as string | undefined, a['deviceType'] as string | undefined)) matchNodes.add(id);
        });
        graph.forEachEdge((id, _a, src, tgt) => {
          if (matchNodes.has(src) || matchNodes.has(tgt)) matchEdges.add(id);
        });
      } else {
        graph.forEachEdge((id, a, src, tgt) => {
          if (a['color'] === legendFocus.color) {
            matchEdges.add(id);
            matchNodes.add(src);
            matchNodes.add(tgt);
          }
        });
      }
      // The picked type is gone from the graph (filtered away): drop the highlight.
      if (matchNodes.size === 0) {
        setLegendFocus(null);
        return;
      }
      legendMatchRef.current = { nodes: matchNodes, edges: matchEdges };
      sigma.refresh();
    });
    return () => cancelAnimationFrame(raf);
  }, [legendFocus, nodes, edges, edgeColorMode, layoutType]);

  // Recompute node text lines when the label config changes, then redraw (no relayout).
  useEffect(() => {
    const lines = new Map<string, string[]>();
    for (const n of nodesRef.current) lines.set(n.id, buildNodeLines(n, nodeLabelConfig));
    nodeLinesByLabel.current = lines;
    sigmaRef.current?.refresh();
  }, [nodeLabelConfig]);

  // Hidden neighbor lookup
  const hiddenNodeMap = useMemo(
    () => new Map(hiddenNodesList.map(n => [n.id, n])),
    [hiddenNodesList]
  );

  // Edge-colour legend entries for the current colour mode. Volume mode encodes
  // byte counts, not categories, so it has no swatch legend. Transport lists the
  // base protocols (TCP/UDP/ICMP…); Application lists the nDPI applications
  // (WhatsApp, YouTube…) the same way the strokes are coloured, via getAppColor.
  const protocolLegend = useMemo(() => {
    if (edgeColorMode === 'volume') return { entries: [], hasUnmapped: false };
    if (edgeColorMode === 'application') return buildAppLegend(edges.map(e => e.data.appName));
    return buildProtocolLegend(edges.map(e => e.data.protocol));
  }, [edges, edgeColorMode]);

  const hiddenNeighbors = useMemo<GraphNode[]>(() => {
    if (!hoveredNode || crossEdges.length === 0) return [];
    const neighborIds = new Set<string>();
    for (const e of crossEdges) {
      if (e.source === hoveredNode) neighborIds.add(e.target);
      else if (e.target === hoveredNode) neighborIds.add(e.source);
    }
    return [...neighborIds]
      .map(id => hiddenNodeMap.get(id))
      .filter((n): n is GraphNode => n !== undefined);
  }, [hoveredNode, crossEdges, hiddenNodeMap]);

  // ---------------------------------------------------------------------------
  // Build & render Sigma instance
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (!containerRef.current) return;
    if (nodes.length === 0) return;
    if (!containerReady) return;

    // Hide canvas immediately so the layout flash (random → laid-out positions) is invisible.
    // revealCanvas() is called once the first correct frame is ready.
    const canvasEl = containerRef.current;
    canvasEl.style.opacity = '0';
    canvasEl.style.transition = '';
    const revealCanvas = () => {
      canvasEl.style.transition = 'opacity 0.15s';
      canvasEl.style.opacity = '1';
    };

    // Tear down previous instance
    sigmaRef.current?.kill();
    sigmaRef.current = null;

    const graph = buildGraph(nodes, edges, primarySource, edgeColorMode, darkMode);
    graphRef.current = graph;

    // Seed the per-node text lines before the first paint. Read config fresh so a
    // config change alone doesn't force a full graph rebuild + relayout (handled below).
    const initialCfg = useStore.getState().nodeLabelConfig;
    const initialLines = new Map<string, string[]>();
    for (const n of nodes) initialLines.set(n.id, buildNodeLines(n, initialCfg));
    nodeLinesByLabel.current = initialLines;

    const bgColor = darkMode ? DARK_BG : LIGHT_BG;
    const nodeFill = darkMode ? DARK_SURFACE : '#ffffff';
    const labelColor = darkMode ? '#c9d1d9' : '#212529';

    const sigma = new Sigma(graph, containerRef.current, {
      allowInvalidContainer: true,
      renderLabels: true,
      renderEdgeLabels: false,
      defaultEdgeType: 'arrow',
      // 'arrow' = straight (single edge between a pair); 'curved' = fanned-out parallels, set per
      // edge by applyParallelEdgeCurvature so overlapping protocol colours stay distinguishable.
      edgeProgramClasses: {
        arrow: EdgeArrowProgram,
        curved: EdgeCurvedArrowProgram,
      },
      labelDensity: 1,
      labelGridCellSize: 60,
      labelRenderedSizeThreshold: -Infinity, // always call drawNodeLabel at every zoom level
      minEdgeThickness: 0.5,
      zIndex: true,
      defaultDrawNodeLabel: (ctx, data) => {
        const faint = activeInWindowRef.current?.faintNodeIds?.has(data.key) ?? false;
        ctx.save();
        if (faint) ctx.globalAlpha = 0.3;
        drawNodeLabel(ctx, data, labelColor, nodeFill, nodeTypeByLabel.current, deviceTypeByLabel.current, nodeLinesByLabel.current, highlightedNodesRef.current, contestedByLabel.current, labelFitRef.current);
        ctx.restore();
      },
      defaultDrawNodeHover: (ctx, data) => {
        const faint = activeInWindowRef.current?.faintNodeIds?.has(data.key) ?? false;
        ctx.save();
        if (faint) ctx.globalAlpha = 0.3;
        drawNodeLabel(ctx, data, labelColor, nodeFill, nodeTypeByLabel.current, deviceTypeByLabel.current, nodeLinesByLabel.current, highlightedNodesRef.current, contestedByLabel.current);
        ctx.restore();
      },
      nodeReducer: (node, data) => {
        const res = { ...data };
        const hovNode = sigmaRef.current?.['hoveredNode'] as string | undefined;
        const isHovered = !!hovNode && node === hovNode;
        const neighbors = hovNode && graph.hasNode(hovNode)
          ? new Set(graph.neighbors(hovNode))
          : new Set<string>();

        const dimColor = darkMode ? '#3a3f4b' : '#c8cdd6';

        // Hover dimming
        if (hovNode && !isHovered && !neighbors.has(node)) {
          res['color'] = dimColor;
          res['label'] = '';
        }

        // Legend highlight: everything but the picked type (or the ends of the picked edges) fades.
        const lm = legendMatchRef.current;
        if (lm && !lm.nodes.has(node)) {
          res['color'] = dimColor;
          res['label'] = '';
          res['zIndex'] = 0;
        } else if (lm) {
          // Drawn in full (icon and label) even where the label grid would skip it.
          res['forceLabel'] = true;
          res['zIndex'] = 2;
        }

        // Time axis: quiet in the window → dimmed, label kept so the node is still findable.
        const win = activeInWindowRef.current;
        if (win?.hiddenNodeIds?.has(node)) {
          // Not seen yet (the "appear when first seen" option): not drawn at all.
          res['hidden'] = true;
        } else if (win?.faintNodeIds?.has(node)) {
          // Not seen yet, shown faint: a ghost of the node, its label drawn at low alpha too.
          res['color'] = blendColor(String(res['color'] ?? dimColor), bgColor, 0.82);
          res['zIndex'] = 0;
        } else if (win && !win.nodeIds.has(node)) {
          res['color'] = dimColor;
          res['zIndex'] = 0;
        }

        // Compare-mode secondary
        if (data['isSecondaryOnly']) {
          res['color'] = blendColor(data['color'] as string, bgColor, 0.4);
        }

        return res;
      },
      edgeReducer: (edge, data) => {
        const res = { ...data };
        const hovNode = sigmaRef.current?.['hoveredNode'];
        if (hovNode) {
          const [src, tgt] = graph.extremities(edge);
          if (src !== hovNode && tgt !== hovNode) {
            res['hidden'] = true;
          }
        }
        if (data['isSecondaryOnly']) {
          res['color'] = blendColor(data['color'] as string, bgColor, 0.5);
        }
        const lmEdges = legendMatchRef.current?.edges;
        if (lmEdges && !lmEdges.has(edge)) {
          res['color'] = blendColor(data['color'] as string, bgColor, 0.12);
          res['zIndex'] = 0;
        }
        // Time axis: a conversation outside the window isn't drawn. An edge standing for several
        // conversations between the same pair (deduplicateEdges joins their ids with '|') is
        // drawn when any of them is in the window.
        const win = activeInWindowRef.current;
        if (win && !win.edgeIds.has(edge) && !edge.split('|').some(id => win.edgeIds.has(id))) {
          res['hidden'] = true;
        }
        return res;
      },
    });

    sigmaRef.current = sigma;
    groupLayoutRef.current = null;
    sigma.on('afterRender', () => {
      const canvas = groupsCanvasRef.current;
      const layout = groupLayoutRef.current;
      if (!canvas) return;
      drawGroupBoxes(
        canvas,
        sigma,
        layout?.boxes ?? [],
        layout?.headerFor ?? (() => 0),
        darkMode,
        activeInWindowRef.current?.nodeIds ?? null,
      );
    });

    // Test seam for the README demo recording (frontend/e2e/demo.spec.ts).
    //
    // The graph is WebGL, so a node has no DOM element and no addressable pixel:
    // there is nothing for a test to hover or click by selector, and Sigma does
    // its hit-testing internally. Exposing the instance lets the recording ask
    // where a node actually is on screen (viewportForNode) and click that point,
    // instead of guessing coordinates and silently filming a miss.
    (window as unknown as { __sigma?: Sigma }).__sigma = sigma;

    // ── Edge overdraw for PDF capture ─────────────────────────────────────────
    //
    // Sigma draws edges on a WebGL canvas, and a WebGL canvas cannot be read back from
    // JavaScript — toDataURL and gl.readPixels both return empty while the edges are plainly
    // visible on screen, because the pixels only ever exist inside the compositor. So every
    // capture library produces the same edgeless diagram; this is not an html-to-image problem
    // and no amount of swapping libraries fixes it (#526).
    //
    // The 2D `labels` layer IS readable — it is the only reason nodes and text reach the PDF at
    // all (they come from drawNodeLabel's overdraw, not from Sigma's WebGL node layer). So for
    // capture we redraw the edges onto that same 2D layer, underneath the labels.
    //
    // Capture-only, deliberately: the interactive renderer keeps its WebGL edges, which is what
    // makes a 700-edge graph pan smoothly. Doing this always would put every edge through the 2D
    // context on every frame.
    if (forceLight) {
      const labelCanvas = sigma.getCanvases()['labels'];
      const labelCtx = labelCanvas?.getContext('2d');
      if (labelCtx) {
        sigma.on('afterRender', () => {
          labelCtx.save();
          // Sigma sizes its canvases for the device pixel ratio; graphToViewport returns CSS
          // pixels, so match that transform or the lines land in the wrong place on HiDPI.
          //
          // Guard clientWidth rather than trusting `|| 1`: that catches 0/0 (NaN, falsy) but NOT
          // n/0, which is Infinity — truthy, so it sails past the fallback and setTransform then
          // silently draws nothing. A zero-width layout pass is reachable here, since the capture
          // container is mounted and measured before the graph has laid out.
          const dpr = labelCanvas.clientWidth > 0 ? labelCanvas.width / labelCanvas.clientWidth : 1;
          labelCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
          labelCtx.globalCompositeOperation = 'destination-over'; // behind the labels already drawn
          graph.forEachEdge((_edge, attrs, source, target) => {
            if (attrs['hidden']) return;
            const s = sigma.graphToViewport(graph.getNodeAttributes(source) as { x: number; y: number });
            const t = sigma.graphToViewport(graph.getNodeAttributes(target) as { x: number; y: number });
            labelCtx.beginPath();
            labelCtx.moveTo(s.x, s.y);
            // Curved parallels must bow the same way here as Sigma draws them on screen, or the PDF
            // would show overlapping straight lines again. Same control point Sigma uses: the
            // midpoint offset perpendicular to the edge by `curvature` (#497).
            const curvature = (attrs['curvature'] as number) ?? 0;
            // Number.isFinite guards against a NaN curvature (missing/malformed index) reaching
            // quadraticCurveTo, which would silently drop the stroke.
            if (attrs['type'] === 'curved' && Number.isFinite(curvature) && curvature !== 0) {
              const cx = (s.x + t.x) / 2 + (t.y - s.y) * curvature;
              const cy = (s.y + t.y) / 2 - (t.x - s.x) * curvature;
              labelCtx.quadraticCurveTo(cx, cy, t.x, t.y);
            } else {
              labelCtx.lineTo(t.x, t.y);
            }
            labelCtx.strokeStyle = (attrs['color'] as string) ?? '#999';
            labelCtx.lineWidth = Math.max(0.6, (attrs['size'] as number) ?? 1);
            labelCtx.globalAlpha = 0.75;
            labelCtx.stroke();
          });
          labelCtx.restore();
        });
      }
    }

    // ── Node dragging ──────────────────────────────────────────────────────────
    // Track which node is being dragged. These are plain vars (not refs) because
    // they're local to this effect closure and reset on every rebuild.
    const DRAG_THRESHOLD_PX = 5;
    let dragNode: string | null = null;
    let dragMoved = false;
    let suppressNextClick = false;
    let dragStartX = 0;
    let dragStartY = 0;

    // sigma.getCamera().disable() is a valid Sigma v3 API that prevents the camera
    // from processing pan/zoom interactions while preserving hover/click event dispatch.
    sigma.on('downNode', ({ node, event }) => {
      dragNode = node;
      dragMoved = false;
      dragStartX = event.x;
      dragStartY = event.y;
      sigma.getCamera().disable();
      canvasEl.style.cursor = 'grabbing';
    });

    const onDragMove = (e: MouseEvent) => {
      if (!dragNode) return;
      const rect = canvasEl.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      // Only commit to a drag once the pointer has moved beyond the threshold;
      // this prevents micro-movements from suppressing a legitimate click.
      if (!dragMoved) {
        const dx = x - dragStartX;
        const dy = y - dragStartY;
        if (dx * dx + dy * dy < DRAG_THRESHOLD_PX * DRAG_THRESHOLD_PX) return;
        dragMoved = true;
      }
      const pos = sigma.viewportToGraph({ x, y });
      graph.setNodeAttribute(dragNode, 'x', pos.x);
      graph.setNodeAttribute(dragNode, 'y', pos.y);
      sigma.refresh();
    };

    const onDragEnd = () => {
      if (!dragNode) return;
      suppressNextClick = dragMoved;
      if (dragMoved) setNodesMoved(true);
      dragNode = null;
      dragMoved = false;
      sigma.getCamera().enable();
      canvasEl.style.cursor = '';
    };

    document.addEventListener('mousemove', onDragMove);
    document.addEventListener('mouseup', onDragEnd);

    // Before each render, rebuild the label→nodeType/deviceType sidecar maps.
    // Keyed by label (IP/hostname) which is unique per node in this graph.
    sigma.on('beforeRender', () => {
      if (groupLayoutRef.current) {
        const o = sigma.graphToViewport({ x: 0, y: 0 });
        const c = sigma.graphToViewport({ x: CELL_W, y: -(CELL_H - NODE_TOP) });
        labelFitRef.current = { w: Math.abs(c.x - o.x), below: Math.abs(c.y - o.y) };
      } else {
        labelFitRef.current = null;
      }
      nodeTypeByLabel.current.clear();
      deviceTypeByLabel.current.clear();
      contestedByLabel.current.clear();
      graph.forEachNode((node, attrs) => {
        nodeTypeByLabel.current.set(node, attrs['nodeType'] as string ?? 'unknown');
        deviceTypeByLabel.current.set(node, attrs['deviceType'] as string ?? '');
        if (attrs['identityContested']) contestedByLabel.current.set(node, true);
      });
    });

    // After each render, clear the separate hoverNodes WebGL layer that Sigma
    // uses to draw a solid-colored circle over the hovered node. This removes
    // the built-in hover highlight while keeping our canvas overdraw intact.
    sigma.on('afterRender', () => {
      const gl = (sigma as unknown as { webGLContexts: { hoverNodes: WebGLRenderingContext } }).webGLContexts?.hoverNodes;
      if (gl) gl.clear(gl.COLOR_BUFFER_BIT);
    });


    // Override background color via the canvas element behind WebGL
    const canvas = containerRef.current.querySelector('canvas');
    // In the network map the group boxes sit under the graph, so its canvas stays clear (the
    // wrapper behind it carries the same background colour).
    if (canvas) (canvas as HTMLCanvasElement).style.background = layoutType === 'grouped' ? 'transparent' : bgColor;

    // ── Events ────────────────────────────────────────────────────────────────

    sigma.on('enterNode', ({ node }) => {
      setHoveredNode(node);
      sigma.refresh();
    });

    sigma.on('leaveNode', () => {
      setHoveredNode(null);
      sigma.refresh();
    });

    sigma.on('clickNode', ({ node, event }) => {
      // Suppress click when the mousedown was part of a drag gesture
      if (suppressNextClick) { suppressNextClick = false; return; }

      const original = nodesRef.current.find(n => n.id === node);
      if (!original) return;

      if (original.data.isCluster) {
        const clusterId = graph.getNodeAttribute(node, 'clusterId') as string;
        onClusterClick?.(clusterId);
        return;
      }

      // Show tooltip pos from mouse event (guard against TouchEvent)
      const orig = event.original;
      if (containerRef.current && orig instanceof MouseEvent) {
        const rect = containerRef.current.getBoundingClientRect();
        setTooltipPos({ x: orig.clientX - rect.left + 12, y: orig.clientY - rect.top + 12 });
      }

      onNodeClick?.(original);
    });

    // Double-click to zoom into node
    sigma.on('doubleClickNode', ({ node }) => {
      const cam = sigma.getCamera();
      const { x, y } = sigma.getNodeDisplayData(node) ?? { x: 0.5, y: 0.5 };
      cam.animate({ x, y, ratio: cam.ratio / 2 }, { duration: 300 });
    });

    // ── Layout ────────────────────────────────────────────────────────────────

    let cancelled = false;

    if (!elkRef.current) {
      elkRef.current = new ELK({
        workerFactory: () => new Worker(ELK_WORKER_URL, { type: 'classic' }),
      });
    }

    setNodesMoved(false);
    resetLayoutRef.current = () => {
      setNodesMoved(false);
      if (layoutType === 'grouped') {
        applyGroupedLayout(sigma, nodesRef.current, groupingRef.current, groupLayoutRef);
        sigma.refresh();
      } else if (layoutType === 'hierarchicalTd') {
        applyHierarchicalLayout(graph, elkRef.current!).then(() => !cancelled && sigma.refresh());
      } else {
        circular.assign(graph, { scale: 1 });
        noverlap.assign(graph, { maxIterations: 50, settings: { margin: 6 } });
        sigma.refresh();
      }
    };

    if (layoutType === 'grouped') {
      applyGroupedLayout(sigma, nodes, groupingRef.current, groupLayoutRef);
      sigma.refresh();
      requestAnimationFrame(() => {
        revealCanvas();
        onLayoutCompleteRef.current?.();
      });
    } else if (layoutType === 'hierarchicalTd') {
      setLayouting(true);
      applyHierarchicalLayout(graph, elkRef.current!).then(() => {
        if (cancelled) return;
        sigma.refresh();
        sigma.getCamera().animate({ ratio: 1 }, { duration: 400 });
        setLayouting(false);
        revealCanvas();
        requestAnimationFrame(() => onLayoutCompleteRef.current?.());
      }).catch(err => {
        if (cancelled) return;
        console.error('[NetworkGraph] ELK hierarchical layout failed:', err);
        setLayouting(false);
      });
    } else {
      // Circular layout — synchronous, applied before first render so there
      // is no visible jump from random positions to laid-out positions.
      circular.assign(graph, { scale: 1 });
      noverlap.assign(graph, { maxIterations: 50, settings: { margin: 6 } });
      sigma.refresh();
      requestAnimationFrame(() => {
        revealCanvas();
        onLayoutCompleteRef.current?.();
      });
    }

    return () => {
      cancelled = true;
      document.removeEventListener('mousemove', onDragMove);
      document.removeEventListener('mouseup', onDragEnd);
      sigmaRef.current?.kill();
      sigmaRef.current = null;
      delete (window as unknown as { __sigma?: Sigma }).__sigma;
      elkRef.current?.terminateWorker();
      elkRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, layoutType, primarySource, darkMode, containerReady]);

  // Re-render sigma when hover changes (reducer reads this)
  useEffect(() => {
    sigmaRef.current?.refresh();
  }, [hoveredNode]);

  // Repaint edges when the colour encoding changes.
  //
  // Deliberately not a dependency of the graph-building effect above: switching
  // Protocol↔Volume must not rebuild the graph, because that would re-run the
  // layout and scramble positions the user has been reading. Everything needed
  // (protocol, totalBytes) is already on each edge, so this is a pure repaint.
  //
  // darkMode is absent from the deps for the opposite reason — a theme change
  // *does* rebuild via the effect above, which repaints with the correct ramp.
  useEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;

    let maxEdgeBytes = 0;
    let minEdgeBytes = Infinity;
    graph.forEachEdge((_key, attrs) => {
      const b = (attrs.totalBytes as number) ?? 0;
      if (b <= 0) return;
      if (b > maxEdgeBytes) maxEdgeBytes = b;
      if (b < minEdgeBytes) minEdgeBytes = b;
    });
    const volumeColor = makeVolumeEdgeColor(
      maxEdgeBytes,
      darkMode,
      Number.isFinite(minEdgeBytes) ? minEdgeBytes : 1
    );

    graph.forEachEdge((key, attrs) => {
      graph.setEdgeAttribute(
        key,
        'color',
        edgeColorMode === 'volume'
          ? volumeColor((attrs.totalBytes as number) ?? 0)
          : edgeColorMode === 'application'
            ? ((attrs.appName as string)
                ? getAppColor(attrs.appName as string)
                : DEFAULT_EDGE_COLOR)
            : getProtocolColor((attrs.protocol as string) ?? '')
      );
    });
    sigmaRef.current?.refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edgeColorMode]);

  // Fit view
  const onFitViewRepeatedRef = useRef(onFitViewRepeated);
  onFitViewRepeatedRef.current = onFitViewRepeated;
  const noopFits = useRef<number[]>([]);
  const handleFitView = useCallback(() => {
    const camera = sigmaRef.current?.getCamera();
    if (!camera) return;
    const { x, y, ratio } = camera.getState();
    const fitted = Math.abs(x - 0.5) < 1e-3 && Math.abs(y - 0.5) < 1e-3 && Math.abs(ratio - 1) < 1e-3;
    if (fitted) {
      // Two presses that changed nothing, close together: point the user at fullscreen.
      const now = Date.now();
      noopFits.current = [...noopFits.current.filter(t => now - t < 5000), now];
      if (noopFits.current.length >= 2) {
        noopFits.current = [];
        onFitViewRepeatedRef.current?.();
      }
      return;
    }
    noopFits.current = [];
    camera.animate({ x: 0.5, y: 0.5, ratio: 1 }, { duration: 300 });
  }, []);

  return (
    <div
      className="network-graph-wrapper"
      /*
       * Publishes the graph's own resolved theme for its CSS children (the legend, tooltips).
       * They cannot read `darkMode` — it is JS state — and they must not read the page's theme
       * either: under forceLight the page stays dark while this canvas renders light for the PDF.
       * The canvas is the thing they sit on, so the canvas is what they follow.
       */
      data-graph-theme={darkMode ? 'dark' : 'light'}
      data-has-bottom-bar={bottomBar ? 'true' : undefined}
      style={{ background: darkMode ? DARK_BG : LIGHT_BG }}
    >
      {/* Sigma canvas — always mounted so Sigma's DOM is never torn out by React */}
      {/* Network map group boxes, under the graph. */}
      <canvas
        ref={groupsCanvasRef}
        className="network-graph-groups"
        aria-hidden="true"
        style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none' }}
      />
      <div className="network-graph-canvas" ref={containerRef} />
      {/* Traffic dots, drawn over the graph; clicks go through to it. */}
      <canvas
        ref={particlesRef}
        className="network-graph-particles"
        aria-hidden="true"
        style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none' }}
      />

      {/* Empty-state overlay — sits on top when there is nothing to show */}
      {nodes.length === 0 && (
        <div className="network-graph-empty" style={{ position: 'absolute', inset: 0 }}>
          <i className="bi bi-diagram-3" style={{ fontSize: '4rem', opacity: 0.3 }} />
          <h5 className="mt-3 text-muted">No Network Data Available</h5>
          <p className="text-muted">
            {activeFilterCount > 0
              ? 'No nodes match the current filters.'
              : 'Upload a pcap file to visualize network topology'}
          </p>
        </div>
      )}

      {bottomBar}

      {/* ── Bottom-right controls ────────────────────────────────────────── */}
      <div className="ng-overlay-controls">
        {nodesMoved && (
          <button
            className="ng-ctrl-btn"
            title="Reset positions"
            aria-label="Reset positions: put dragged nodes back"
            onClick={() => resetLayoutRef.current?.()}
          >
            <i className="bi bi-arrow-counterclockwise" aria-hidden="true" />
          </button>
        )}
        <button className="ng-ctrl-btn" title="Fit view" aria-label="Fit view" onClick={handleFitView}>
          <i className="bi bi-bounding-box-circles" aria-hidden="true" />
        </button>
        {onLayoutChange && (
          <>
            <button
              className={`ng-ctrl-btn${layoutType === 'circular' ? ' active' : ''}`}
              title="Circular layout: devices around a ring, spread out so none overlap"
              aria-label="Circular layout: devices around a ring, spread out so none overlap"
              onClick={() => onLayoutChange('circular')}
            >
              <i className="bi bi-diagram-2" aria-hidden="true" />
            </button>
            <button
              className={`ng-ctrl-btn${layoutType === 'hierarchicalTd' ? ' active' : ''}`}
              title="Hierarchical layout: layered top to bottom by who talks to whom"
              aria-label="Hierarchical layout: layered top to bottom by who talks to whom"
              onClick={() => onLayoutChange('hierarchicalTd')}
            >
              <i className="bi bi-diagram-3" aria-hidden="true" />
            </button>
            <button
              className={`ng-ctrl-btn${layoutType === 'grouped' ? ' active' : ''}`}
              title="Network map: grouped by network"
              aria-label="Network map: grouped by network"
              onClick={() => onLayoutChange('grouped')}
            >
              <i className="bi bi-grid-1x2" aria-hidden="true" />
            </button>
          </>
        )}
        {onFilterClick && (
          <button
            className={`ng-ctrl-btn${activeFilterCount > 0 ? ' active' : ''}`}
            title="Filters"
            onClick={onFilterClick}
          >
            <i className="bi bi-funnel" />
            {activeFilterCount > 0 && (
              <span className="ng-filter-badge">{activeFilterCount}</span>
            )}
          </button>
        )}
      </div>

      {/* ── Layout spinner ───────────────────────────────────────────────── */}
      {layouting && (
        <div className="ng-layouting">
          <Spinner animation="border" size="sm" className="text-secondary me-2" />
          Computing layout…
        </div>
      )}

      {/* ── Hidden neighbor tooltip ──────────────────────────────────────── */}
      {tooltipPos && hiddenNeighbors.length > 0 && (
        <div className="nf-hidden-tooltip" style={{ left: tooltipPos.x, top: tooltipPos.y }}>
          <div className="nf-hidden-tooltip-title">Hidden neighbors ({hiddenNeighbors.length})</div>
          <ul className="nf-hidden-tooltip-list">
            {hiddenNeighbors.slice(0, 10).map(n => (
              <li key={n.id}>
                {n.data.ip}{n.data.hostname ? ` (${n.data.hostname})` : ''}
              </li>
            ))}
            {hiddenNeighbors.length > 10 && (
              <li className="nf-hidden-tooltip-more">+{hiddenNeighbors.length - 10} more</li>
            )}
          </ul>
        </div>
      )}

      {/* ── Node-type legend — data-driven, matches getNodeColor/getNodeIcon ── */}
      {/* Scrollable on-screen so a long protocol list can't overflow the canvas; the PDF-capture
          render (forceLight) keeps the full height so nothing is clipped in the export. */}
      <div
        className={`ng-legend${forceLight ? '' : ' ng-legend--scroll'}${legendFocus ? ' ng-legend--focused' : ''}`}
        role="group"
        aria-label="Legend: click an entry to highlight it"
      >
        {/* Specific service nodeTypes present in this graph */}
        {Object.entries(NODE_TYPE_CONFIG)
          .filter(([type]) => !GENERIC_NODE_TYPES.has(type) && type !== 'cluster' &&
            nodes.some(n => !n.data.isCluster && (n.data.nodeType ?? 'unknown') === type))
          .map(([type, cfg]) => (
            <LegendButton key={type} focus={legendFocus} value={{ kind: 'node', key: `type:${type}` }} onPick={setLegendFocus}>
              <i className={`bi ${cfg.icon} ng-legend-icon`} style={{ color: cfg.color }} aria-hidden="true" />
              <span className="ng-legend-label">{cfg.label}</span>
            </LegendButton>
          ))}
        {/* Device types present among generic (client/unknown) nodes */}
        {DEVICE_TYPES
          .filter(dt => dt !== 'UNKNOWN' &&
            nodes.some(n => GENERIC_NODE_TYPES.has(n.data.nodeType ?? 'unknown') && n.data.deviceType === dt))
          .map(dt => (
            <LegendButton key={dt} focus={legendFocus} value={{ kind: 'node', key: `device:${dt}` }} onPick={setLegendFocus}>
              {/*
                Swatch matches what the node actually renders. Generic nodes (client/unknown) now
                take their colour from NODE_TYPE_CONFIG[nodeType], not from deviceTypeColor — so
                using the device colour here would advertise a colour no node shows (#521 review).
                The device icon still distinguishes IoT from Mobile; the colour follows the node.
              */}
              <i
                className={`bi ${deviceTypeIcon(dt)} ng-legend-icon`}
                style={{ color: NODE_TYPE_CONFIG['client'].color }}
                aria-hidden="true"
              />
              <span className="ng-legend-label">{deviceTypeLabel(dt)}</span>
            </LegendButton>
          ))}
        {/* Fallback: show Unknown only if generic nodes exist with no specific deviceType */}
        {nodes.some(n => GENERIC_NODE_TYPES.has(n.data.nodeType ?? 'unknown') && (!n.data.deviceType || n.data.deviceType === 'UNKNOWN')) && (
          <LegendButton focus={legendFocus} value={{ kind: 'node', key: 'unknown' }} onPick={setLegendFocus}>
            <i className="bi bi-question-circle ng-legend-icon" style={{ color: NODE_TYPE_CONFIG['unknown'].color }} aria-hidden="true" />
            <span className="ng-legend-label">Unknown</span>
          </LegendButton>
        )}

        {/* ── Edge-protocol colours — line swatches, driven by PROTOCOL_COLORS ── */}
        {(protocolLegend.entries.length > 0 || protocolLegend.hasUnmapped) && (
          <>
            <div className="ng-legend-divider" />
            <div className="ng-legend-heading">Edges</div>
            {protocolLegend.entries.map(({ color, label }) => (
              <LegendButton key={color} focus={legendFocus} value={{ kind: 'edge', color }} onPick={setLegendFocus}>
                <span className="ng-legend-line" style={{ background: color }} aria-hidden="true" />
                <span className="ng-legend-label">{label}</span>
              </LegendButton>
            ))}
            {protocolLegend.hasUnmapped && (
              <LegendButton focus={legendFocus} value={{ kind: 'edge', color: DEFAULT_EDGE_COLOR }} onPick={setLegendFocus}>
                <span className="ng-legend-line" style={{ background: DEFAULT_EDGE_COLOR }} aria-hidden="true" />
                <span className="ng-legend-label">Other</span>
              </LegendButton>
            )}
          </>
        )}
      </div>
    </div>
  );
});

// ---------------------------------------------------------------------------
// Utility: blend two hex colours
// ---------------------------------------------------------------------------

function blendColor(hex: string, bg: string, alpha: number): string {
  const parse = (h: string) => {
    let c = h.replace('#', '');
    if (c.length === 3) c = c[0]+c[0]+c[1]+c[1]+c[2]+c[2]; // expand shorthand
    return [parseInt(c.slice(0, 2), 16), parseInt(c.slice(2, 4), 16), parseInt(c.slice(4, 6), 16)];
  };
  const [r1, g1, b1] = parse(hex);
  const [r2, g2, b2] = parse(bg);
  const r = Math.round(r1 * alpha + r2 * (1 - alpha));
  const g = Math.round(g1 * alpha + g2 * (1 - alpha));
  const b = Math.round(b1 * alpha + b2 * (1 - alpha));
  return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
}

/**
 * The network map layout: nested group boxes (networks, subnets, device types), each device in a
 * grid cell of its innermost group. Boxes are kept for the under-graph canvas to draw.
 */
function applyGroupedLayout(
  sigma: Sigma,
  nodes: GraphNode[],
  grouping: { segments: NetworkSegment[]; customRanges: CustomPrivateRange[]; dnsNames?: Map<string, string> },
  out: { current: GroupedLayout | null },
): void {
  const graph = sigma.getGraph();
  const present = nodes.filter(n => graph.hasNode(n.id));
  const layout = layoutGroups(buildGroupTree(present, grouping));
  layout.positions.forEach((p, id) => {
    if (!graph.hasNode(id)) return;
    graph.setNodeAttribute(id, 'x', p.x);
    graph.setNodeAttribute(id, 'y', -p.y);
  });
  out.current = layout;
  // Frame the boxes, not just the nodes: the camera fits the bounding box, and the outer boxes and
  // their names reach past the outermost devices.
  if (layout.boxes.length) {
    const xs = layout.boxes.flatMap(b => [b.x, b.x + b.w]);
    const ys = layout.boxes.flatMap(b => [-b.y, -(b.y + b.h)]);
    const [top, bottom] = [Math.max(...ys), Math.min(...ys)];
    // Extra room at the bottom, where the time axis bar sits over the graph.
    const below = (top - bottom) * 0.08;
    sigma.setCustomBBox({ x: [Math.min(...xs), Math.max(...xs)], y: [bottom - below, top] });
  }
}

/** What a legend click picks out: a node type (`type:<nodeType>`, `device:<deviceType>`, `unknown`) or an edge colour. */
type LegendFocus = { kind: 'node'; key: string } | { kind: 'edge'; color: string };

/** Mirrors how the legend lists node types: specific service types, else generic nodes by device type. */
function legendNodeMatches(key: string, nodeType: string | undefined, deviceType: string | undefined): boolean {
  const nt = nodeType ?? 'unknown';
  if (key.startsWith('type:')) return nt === key.slice(5);
  const generic = GENERIC_NODE_TYPES.has(nt);
  if (key.startsWith('device:')) return generic && deviceType === key.slice(7);
  return generic && (!deviceType || deviceType === 'UNKNOWN');
}

function sameFocus(a: LegendFocus | null, b: LegendFocus): boolean {
  if (!a || a.kind !== b.kind) return false;
  return a.kind === 'node' ? a.key === (b as { key: string }).key : a.color === (b as { color: string }).color;
}

/** A legend entry: a toggle that highlights its nodes or edges; pressing it again clears. */
function LegendButton({
  focus,
  value,
  onPick,
  children,
}: {
  focus: LegendFocus | null;
  value: LegendFocus;
  onPick: (f: LegendFocus | null) => void;
  children: import('react').ReactNode;
}) {
  const on = sameFocus(focus, value);
  return (
    <button type="button" className="ng-legend-item ng-legend-btn" aria-pressed={on} onClick={() => onPick(on ? null : value)}>
      {children}
    </button>
  );
}
