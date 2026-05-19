import { Spinner } from '@components/common/Spinner/Spinner';
import { useEffect, useRef, useState, useCallback, useMemo, memo } from 'react';
import ELK from 'elkjs';
const ELK_WORKER_URL = `${import.meta.env.BASE_URL}elk-worker.min.js`;
import Graph from 'graphology';
import Sigma from 'sigma';
import FA2Layout from 'graphology-layout-forceatlas2/worker';
import { inferSettings } from 'graphology-layout-forceatlas2';
import noverlap from 'graphology-layout-noverlap';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import { getProtocolColor, NODE_TYPE_CONFIG } from '@/features/network/constants';
import { deviceTypeColor, deviceTypeIcon, deviceTypeLabel, DEVICE_TYPES } from '@/utils/deviceType';
import { useStore } from '@/store';
import './NetworkGraph.css';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface NodeHighlight {
  color: string;
  label: string;
  description?: string;
}

interface NetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (node: GraphNode) => void;
  onClusterClick?: (clusterId: string) => void;
  layoutType?: 'forceDirected2d' | 'hierarchicalTd';
  onLayoutChange?: (layout: 'forceDirected2d' | 'hierarchicalTd') => void;
  onLayoutComplete?: () => void;
  primarySource?: string;
  hiddenNodesList?: GraphNode[];
  crossEdges?: GraphEdge[];
  onFilterClick?: () => void;
  activeFilterCount?: number;
  /** Monitor mode: map of node label (IP/MAC) → highlight colour + badge text */
  highlightedNodes?: Map<string, NodeHighlight>;
}

// ---------------------------------------------------------------------------
// Node visual helpers
// ---------------------------------------------------------------------------

const DARK_BG = '#0f1117';
const DARK_SURFACE = '#1e2130';
const LIGHT_BG = '#f6f8fa';

// ---------------------------------------------------------------------------
// Bootstrap Icons — unicode codepoints for each node type
// Pre-rendered to data URLs so Sigma's WebGL renderer can display them.
// ---------------------------------------------------------------------------

// Icons for specific service nodeTypes
const NODE_TYPE_ICONS: Record<string, string> = {
  'dns-server':      '\uf3ef', // bi-globe2
  'web-server':      '\uf52c', // bi-server
  'ssh-server':      '\uf5c3', // bi-terminal
  'ftp-server':      '\uf3d5', // bi-folder-symlink
  'mail-server':     '\uf32f', // bi-envelope
  'dhcp-server':     '\uf1d6', // bi-broadcast
  'ntp-server':      '\uf293', // bi-clock
  'database-server': '\uf8c4', // bi-database
  router:            '\uf6ec', // bi-router
  'l2-device':       '\uf6d5', // bi-ethernet
  cluster:           '\uf2ee', // bi-diagram-3
};

// Icons for device types — used on generic (client/unknown) nodes
const DEVICE_TYPE_ICONS: Record<string, string> = {
  ROUTER:         '\uf6ec', // bi-router
  MOBILE:         '\uf4b9', // bi-phone
  LAPTOP_DESKTOP: '\uf456', // bi-laptop
  SERVER:         '\uf52c', // bi-server
  IOT:            '\uf46b', // bi-cpu
};

const FALLBACK_ICON = '\uf505'; // bi-question-circle

function getNodeIcon(nodeType: string, deviceType: string): string {
  if (!GENERIC_NODE_TYPES.has(nodeType)) {
    return NODE_TYPE_ICONS[nodeType] ?? FALLBACK_ICON;
  }
  return DEVICE_TYPE_ICONS[deviceType] ?? FALLBACK_ICON;
}

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
  data: { x: number; y: number; size: number; label: string | null; color: string },
  labelColor: string,
  nodeFill: string,
  ntMap: Map<string, string>,
  dtMap: Map<string, string>,
  hlMap?: Map<string, NodeHighlight>,
): void {
  const { x, y, size, label, color: accentColor } = data;
  const nodeType = ntMap.get(label ?? '') ?? 'unknown';
  const deviceType = dtMap.get(label ?? '') ?? '';
  const highlight = label ? hlMap?.get(label) : undefined;

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

  // Bootstrap Icon — reflects the same logic as getNodeColor/getNodeIcon
  const cp = getNodeIcon(nodeType, deviceType);
  ctx.font = `${size * 0.9}px "bootstrap-icons"`;
  ctx.fillStyle = accentColor;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(cp, x, y);

  // Text label below
  if (label) {
    ctx.font = `500 11px Inter, system-ui, sans-serif`;
    ctx.fillStyle = labelColor;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(label, x, y + size + 3);
  }
}

// Generic nodeTypes that carry no specific service information.
// For these, deviceType provides a more meaningful colour signal.
const GENERIC_NODE_TYPES = new Set(['client', 'unknown']);

function getNodeColor(node: GraphNode): string {
  const { nodeType, deviceType } = node.data;
  // Specific service nodeTypes always take priority (DNS server, web server, etc.)
  if (!GENERIC_NODE_TYPES.has(nodeType) && NODE_TYPE_CONFIG[nodeType as keyof typeof NODE_TYPE_CONFIG]) {
    return NODE_TYPE_CONFIG[nodeType as keyof typeof NODE_TYPE_CONFIG].color;
  }
  // For generic types (client / unknown), prefer the hardware device classification
  if (deviceType && deviceType !== 'UNKNOWN') return deviceTypeColor(deviceType);
  // Fall back to the nodeType color (client=blue, unknown=grey)
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

// ---------------------------------------------------------------------------
// Build a graphology graph from GraphNode[] / GraphEdge[]
// ---------------------------------------------------------------------------

function buildGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  primarySource?: string,
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
      isCluster: !!n.data.isCluster,
      clusterId: n.data.clusterId,
      memberCount: n.data.memberCount ?? 0,
      isSecondaryOnly,
      hidden: false,
    });
  }

  for (const e of validEdges) {
    const color = getProtocolColor(e.data.protocol);
    const isSecondaryOnly =
      e.data.sources?.length === 1 &&
      primarySource !== undefined &&
      e.data.sources[0] !== primarySource;

    graph.addEdgeWithKey(e.id, e.source, e.target, {
      color,
      size: 1.2,
      label: e.label,
      type: 'arrow',
      isSecondaryOnly,
      packetCount: e.data.packetCount,
    });
  }

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

export const NetworkGraph = memo(function NetworkGraph({
  nodes,
  edges,
  onNodeClick,
  onClusterClick,
  layoutType = 'forceDirected2d',
  onLayoutChange,
  onLayoutComplete,
  primarySource,
  hiddenNodesList = [],
  crossEdges = [],
  onFilterClick,
  activeFilterCount = 0,
  highlightedNodes,
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
  const darkMode = themeMode === 'dark' || (themeMode === 'system' && sysDark);

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
  const fa2Ref = useRef<InstanceType<typeof FA2Layout> | null>(null);
  const graphRef = useRef<Graph | null>(null);
  const nodeTypeByLabel = useRef<Map<string, string>>(new Map());
  const deviceTypeByLabel = useRef<Map<string, string>>(new Map());
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

  // Hidden neighbor lookup
  const hiddenNodeMap = useMemo(
    () => new Map(hiddenNodesList.map(n => [n.id, n])),
    [hiddenNodesList]
  );

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

    // Tear down previous instance
    fa2Ref.current?.kill();
    fa2Ref.current = null;
    sigmaRef.current?.kill();
    sigmaRef.current = null;

    const graph = buildGraph(nodes, edges, primarySource);
    graphRef.current = graph;

    const bgColor = darkMode ? DARK_BG : LIGHT_BG;
    const nodeFill = darkMode ? DARK_SURFACE : '#ffffff';
    const labelColor = darkMode ? '#c9d1d9' : '#212529';

    const sigma = new Sigma(graph, containerRef.current, {
      allowInvalidContainer: true,
      renderLabels: true,
      renderEdgeLabels: false,
      defaultEdgeType: 'arrow',
      labelDensity: 1,
      labelGridCellSize: 60,
      labelRenderedSizeThreshold: -Infinity, // always call drawNodeLabel at every zoom level
      minEdgeThickness: 0.5,
      zIndex: true,
      defaultDrawNodeLabel: (ctx, data) => {
        drawNodeLabel(ctx, data, labelColor, nodeFill, nodeTypeByLabel.current, deviceTypeByLabel.current, highlightedNodesRef.current);
      },
      defaultDrawNodeHover: (ctx, data) => {
        drawNodeLabel(ctx, data, labelColor, nodeFill, nodeTypeByLabel.current, deviceTypeByLabel.current, highlightedNodesRef.current);
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
        return res;
      },
    });

    sigmaRef.current = sigma;

    // Before each render, rebuild the label→nodeType/deviceType sidecar maps.
    // Keyed by label (IP/hostname) which is unique per node in this graph.
    sigma.on('beforeRender', () => {
      nodeTypeByLabel.current.clear();
      deviceTypeByLabel.current.clear();
      graph.forEachNode((_node, attrs) => {
        const label = attrs['label'] as string ?? '';
        if (!label) return;
        nodeTypeByLabel.current.set(label, attrs['nodeType'] as string ?? 'unknown');
        deviceTypeByLabel.current.set(label, attrs['deviceType'] as string ?? '');
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
    if (canvas) (canvas as HTMLCanvasElement).style.background = bgColor;

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

    if (layoutType === 'hierarchicalTd') {
      setLayouting(true);
      applyHierarchicalLayout(graph, elkRef.current!).then(() => {
        sigma.refresh();
        sigma.getCamera().animate({ ratio: 1 }, { duration: 400 });
        setLayouting(false);
        requestAnimationFrame(() => onLayoutCompleteRef.current?.());
      }).catch(err => {
        console.error('[NetworkGraph] ELK hierarchical layout failed:', err);
        setLayouting(false);
      });
    } else {
      // ForceAtlas2 in a web worker
      setLayouting(true);
      const fa2Settings = inferSettings(graph);
      const fa2 = new FA2Layout(graph, {
        settings: {
          ...fa2Settings,
          gravity: 1,
          scalingRatio: 2,
          slowDown: 10,
          barnesHutOptimize: graph.order > 200,
        },
      });
      fa2Ref.current = fa2;
      fa2.start();

      // Run for a fixed time then stop and de-overlap
      const runMs = Math.min(3000, 800 + graph.order * 4);
      const timer = setTimeout(() => {
        fa2.stop();
        fa2.kill();
        fa2Ref.current = null;
        noverlap.assign(graph, { maxIterations: 50, settings: { margin: 4 } });
        sigma.refresh();
        setLayouting(false);
        requestAnimationFrame(() => onLayoutCompleteRef.current?.());
      }, runMs);

      return () => {
        clearTimeout(timer);
        fa2?.stop();
        fa2?.kill();
      };
    }

    return () => {
      fa2Ref.current?.kill();
      fa2Ref.current = null;
      sigmaRef.current?.kill();
      sigmaRef.current = null;
      elkRef.current?.terminateWorker();
      elkRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, layoutType, primarySource, darkMode, containerReady]);

  // Re-render sigma when hover changes (reducer reads this)
  useEffect(() => {
    sigmaRef.current?.refresh();
  }, [hoveredNode]);

  // Fit view
  const handleFitView = useCallback(() => {
    sigmaRef.current?.getCamera().animate({ x: 0.5, y: 0.5, ratio: 1 }, { duration: 300 });
  }, []);

  if (nodes.length === 0) {
    return (
      <div className="network-graph-empty">
        <i className="bi bi-diagram-3" style={{ fontSize: '4rem', opacity: 0.3 }} />
        <h5 className="mt-3 text-muted">No Network Data Available</h5>
        <p className="text-muted">Upload a pcap file to visualize network topology</p>
      </div>
    );
  }

  return (
    <div className="network-graph-wrapper" style={{ background: darkMode ? DARK_BG : LIGHT_BG }}>
      {/* Sigma canvas mount point */}
      <div className="network-graph-canvas" ref={containerRef} />

      {/* ── Bottom-right controls ────────────────────────────────────────── */}
      <div className="ng-overlay-controls">
        <button className="ng-ctrl-btn" title="Fit view" onClick={handleFitView}>
          <i className="bi bi-fullscreen" />
        </button>
        {onLayoutChange && (
          <>
            <button
              className={`ng-ctrl-btn${layoutType === 'forceDirected2d' ? ' active' : ''}`}
              title="Force Directed layout"
              onClick={() => onLayoutChange('forceDirected2d')}
            >
              <i className="bi bi-diagram-2" />
            </button>
            <button
              className={`ng-ctrl-btn${layoutType === 'hierarchicalTd' ? ' active' : ''}`}
              title="Hierarchical layout"
              onClick={() => onLayoutChange('hierarchicalTd')}
            >
              <i className="bi bi-diagram-3" />
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
      <div className="ng-legend">
        {/* Specific service nodeTypes present in this graph */}
        {Object.entries(NODE_TYPE_CONFIG)
          .filter(([type]) => !GENERIC_NODE_TYPES.has(type) && type !== 'cluster' &&
            nodes.some(n => !n.data.isCluster && (n.data.nodeType ?? 'unknown') === type))
          .map(([type, cfg]) => (
            <div key={type} className="ng-legend-item">
              <i className={`bi ${cfg.icon} ng-legend-icon`} style={{ color: cfg.color }} />
              <span className="ng-legend-label">{cfg.label}</span>
            </div>
          ))}
        {/* Device types present among generic (client/unknown) nodes */}
        {DEVICE_TYPES
          .filter(dt => dt !== 'UNKNOWN' &&
            nodes.some(n => GENERIC_NODE_TYPES.has(n.data.nodeType ?? 'unknown') && n.data.deviceType === dt))
          .map(dt => (
            <div key={dt} className="ng-legend-item">
              <i className={`bi ${deviceTypeIcon(dt)} ng-legend-icon`} style={{ color: deviceTypeColor(dt) }} />
              <span className="ng-legend-label">{deviceTypeLabel(dt)}</span>
            </div>
          ))}
        {/* Fallback: show Unknown only if generic nodes exist with no specific deviceType */}
        {nodes.some(n => GENERIC_NODE_TYPES.has(n.data.nodeType ?? 'unknown') && (!n.data.deviceType || n.data.deviceType === 'UNKNOWN')) && (
          <div className="ng-legend-item">
            <i className="bi bi-question-circle ng-legend-icon" style={{ color: NODE_TYPE_CONFIG['unknown'].color }} />
            <span className="ng-legend-label">Unknown</span>
          </div>
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
