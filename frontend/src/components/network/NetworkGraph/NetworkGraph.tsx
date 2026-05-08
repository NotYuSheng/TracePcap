import { useState, useEffect, useRef, useCallback, useMemo, memo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Panel,
  ReactFlowProvider,
  useNodesState,
  useEdgesState,
  useReactFlow,
  Handle,
  Position,
  MarkerType,
  type Node,
  type Edge,
  type NodeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import Graph from 'graphology';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import { getProtocolColor, NODE_TYPE_COLORS } from '@/features/network/constants';
import { deviceTypeColor } from '@/utils/deviceType';
import { useStore } from '@/store';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import './NetworkGraph.css';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
  captureMode?: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NODE_SIZE_MIN = 8;
const NODE_SIZE_MAX = 32;
const CLUSTER_COLOR      = '#bdc3c7';
const CLUSTER_RISK_COLOR = '#e74c3c';

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------

const SPECIFIC_NODE_TYPES = new Set([
  'dns-server', 'web-server', 'ssh-server', 'ftp-server',
  'mail-server', 'dhcp-server', 'ntp-server', 'database-server', 'router',
]);

function getNodeColor(nodeData: { role: string; nodeType?: string; deviceType?: string }): string {
  if (nodeData.nodeType && SPECIFIC_NODE_TYPES.has(nodeData.nodeType))
    return NODE_TYPE_COLORS[nodeData.nodeType] ?? '#95a5a6';
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

function mixWithWhite(hex: string, amount: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  const mix = (c: number) => Math.round(c + (255 - c) * amount);
  return `#${mix(r).toString(16).padStart(2, '0')}${mix(g).toString(16).padStart(2, '0')}${mix(b).toString(16).padStart(2, '0')}`;
}

function mixWithGray(hex: string, amount: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  const gray = 0x88;
  const mix = (c: number) => Math.round(c + (gray - c) * amount);
  return `#${mix(r).toString(16).padStart(2, '0')}${mix(g).toString(16).padStart(2, '0')}${mix(b).toString(16).padStart(2, '0')}`;
}

function getClusterColor(data: { riskCount?: number; dominantProtocols?: string[] }): string {
  if ((data.riskCount ?? 0) > 0) return CLUSTER_RISK_COLOR;
  const proto = data.dominantProtocols?.[0];
  if (proto) return mixWithWhite(getProtocolColor(proto), 0.45);
  return CLUSTER_COLOR;
}

function computeNodeSize(totalBytes: number, maxBytes: number): number {
  if (maxBytes === 0 || totalBytes === 0) return NODE_SIZE_MIN;
  return NODE_SIZE_MIN + (NODE_SIZE_MAX - NODE_SIZE_MIN) * Math.sqrt(totalBytes / maxBytes);
}

// ---------------------------------------------------------------------------
// Edge deduplication
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
    const dominant = group.reduce((best, e) =>
      e.data.packetCount > best.data.packetCount ? e : best);
    const totalPackets = group.reduce((s, e) => s + e.data.packetCount, 0);
    const totalBytes   = group.reduce((s, e) => s + e.data.totalBytes, 0);
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

// ---------------------------------------------------------------------------
// Layout computation (same FA2 + ELK logic as before, returns positions Map)
// ---------------------------------------------------------------------------

const NODE_W = 56, NODE_H = 56, CLUSTER_W = 140, CLUSTER_H = 90;

async function computeLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  layoutType: 'forceDirected2d' | 'hierarchicalTd',
): Promise<{ positions: Map<string, { x: number; y: number }>; dedupedEdges: GraphEdge[] }> {
  const nodeIdSet = new Set(nodes.map(n => n.id));
  const validEdges = edges.filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target));
  const dedupedEdges = deduplicateEdges(validEdges);

  if (layoutType === 'forceDirected2d') {
    // Subnet-seeded initial positions for better convergence
    const subnetMap = new Map<string, GraphNode[]>();
    for (const n of nodes) {
      const ip = n.data.ip ?? '';
      const parts = ip.split('.');
      const subnet = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}` : '__other__';
      const bucket = subnetMap.get(subnet) ?? [];
      bucket.push(n);
      subnetMap.set(subnet, bucket);
    }

    const subnets = Array.from(subnetMap.keys());
    const OUTER_RADIUS = 800;
    const INNER_RADIUS = 120;
    const seedPositions = new Map<string, { x: number; y: number }>();
    subnets.forEach((subnet, si) => {
      const angle = (2 * Math.PI * si) / subnets.length;
      const cx = OUTER_RADIUS * Math.cos(angle);
      const cy = OUTER_RADIUS * Math.sin(angle);
      const members = subnetMap.get(subnet)!;
      members.forEach((n, ni) => {
        const innerAngle = (2 * Math.PI * ni) / members.length;
        const jitter = () => (Math.random() - 0.5) * 5;
        seedPositions.set(n.id, {
          x: cx + INNER_RADIUS * Math.cos(innerAngle) + jitter(),
          y: cy + INNER_RADIUS * Math.sin(innerAngle) + jitter(),
        });
      });
    });

    const layoutGraph = new Graph({ multi: false });
    for (const n of nodes) {
      const pos = seedPositions.get(n.id) ?? { x: Math.random() * 100, y: Math.random() * 100 };
      layoutGraph.addNode(n.id, { x: pos.x, y: pos.y });
    }
    const nodeSet = new Set(layoutGraph.nodes());
    for (const e of dedupedEdges) {
      if (!nodeSet.has(e.source) || !nodeSet.has(e.target)) continue;
      if (!layoutGraph.hasEdge(e.source, e.target) && !layoutGraph.hasEdge(e.target, e.source)) {
        layoutGraph.addEdge(e.source, e.target, {
          weight: Math.log10(e.data.packetCount + 1),
        });
      }
    }

    const n = nodes.length;
    const iterations = n > 5000 ? 100 : n > 2000 ? 150 : n > 500 ? 250 : 500;
    forceAtlas2.assign(layoutGraph, {
      iterations,
      settings: {
        ...forceAtlas2.inferSettings(layoutGraph),
        linLogMode: true,
        strongGravityMode: true,
        gravity: 0.1,
        scalingRatio: 2.0,
        edgeWeightInfluence: 1,
        barnesHutOptimize: n > 150,
        adjustSizes: n <= 200,
      },
    });

    const positions = new Map<string, { x: number; y: number }>();
    layoutGraph.forEachNode((id, attrs) => positions.set(id, { x: attrs.x, y: attrs.y }));
    return { positions, dedupedEdges };
  }

  // Hierarchical: server-side ELK layered
  const response = await apiClient.post<{
    positions: Array<{ id: string; x: number; y: number }>;
  }>(API_ENDPOINTS.GRAPH_LAYOUT, {
    layoutType,
    nodes: nodes.map(n => ({
      id: n.id,
      width:  n.data.isCluster ? CLUSTER_W : NODE_W,
      height: n.data.isCluster ? CLUSTER_H : NODE_H,
    })),
    edges: dedupedEdges.map(e => ({ id: e.id, source: e.source, target: e.target })),
  });
  const positions = new Map(response.data.positions.map(p => [p.id, { x: p.x, y: p.y }]));
  return { positions, dedupedEdges };
}

// ---------------------------------------------------------------------------
// Custom node types (defined outside component for stable reference)
// ---------------------------------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function HostNode({ data }: { data: any }) {
  const size = data.size ?? NODE_SIZE_MIN;
  return (
    <div
      className="ng-host-node"
      style={{ width: size, height: size, background: data.color }}
      title={data.label}
    >
      <Handle type="source" position={Position.Right} className="ng-handle" />
      <Handle type="target" position={Position.Left}  className="ng-handle" />
      <div className="ng-host-label">{data.label}</div>
      {data.hiddenNeighbors?.length > 0 && (
        <div className="ng-hidden-tip">
          <div className="ng-hidden-tip-title">Hidden neighbors ({data.hiddenNeighbors.length})</div>
          <ul className="ng-hidden-tip-list">
            {data.hiddenNeighbors.slice(0, 8).map((n: GraphNode) => (
              <li key={n.id}>{n.data.ip}{n.data.hostname ? ` (${n.data.hostname})` : ''}</li>
            ))}
            {data.hiddenNeighbors.length > 8 && (
              <li className="ng-hidden-tip-more">+{data.hiddenNeighbors.length - 8} more</li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function ClusterNodeComp({ data }: { data: any }) {
  return (
    <div
      className="ng-cluster-node"
      style={{ borderColor: data.color, '--ng-cluster-accent': data.color } as React.CSSProperties}
    >
      <Handle type="source" position={Position.Right} className="ng-handle" />
      <Handle type="target" position={Position.Left}  className="ng-handle" />

      <div className="ng-cluster-header">
        <span className="ng-cluster-label">{data.label}</span>
        {(data.riskCount ?? 0) > 0 && (
          <span className="ng-risk-badge">⚠ {data.riskCount}</span>
        )}
      </div>

      <div className="ng-cluster-meta">{data.memberCount} hosts</div>

      {data.dominantProtocols?.length > 0 && (
        <div className="ng-proto-tags">
          {(data.dominantProtocols as string[]).slice(0, 2).map(p => (
            <span key={p} className="ng-proto-tag" style={{ background: mixWithWhite(getProtocolColor(p), 0.3) }}>
              {p}
            </span>
          ))}
        </div>
      )}

      {data.roleBreakdown && (
        <ClusterRoleBar total={data.memberCount || 1} breakdown={data.roleBreakdown} />
      )}

      {data.onExpand && (
        <button
          className="ng-expand-btn"
          onClick={e => { e.stopPropagation(); data.onExpand(); }}
        >
          <i className="bi bi-arrows-angle-expand me-1" />Expand
        </button>
      )}
    </div>
  );
}

const nodeTypes: NodeTypes = {
  host:    HostNode,
  cluster: ClusterNodeComp,
};

// ---------------------------------------------------------------------------
// Cluster role bar
// ---------------------------------------------------------------------------

function ClusterRoleBar({
  total,
  breakdown,
}: {
  total: number;
  breakdown: { client: number; server: number; both: number; unknown: number };
}) {
  const clientPct  = (breakdown.client  / total) * 100;
  const serverPct  = (breakdown.server  / total) * 100;
  const bothPct    = (breakdown.both    / total) * 100;
  const unknownPct = Math.max(0, 100 - clientPct - serverPct - bothPct);
  return (
    <div className="ng-rolebar" title="Role breakdown: client / server / both / unknown">
      {clientPct  > 0 && <div style={{ width: `${clientPct}%`,  background: '#3498db' }} />}
      {serverPct  > 0 && <div style={{ width: `${serverPct}%`,  background: '#2ecc71' }} />}
      {bothPct    > 0 && <div style={{ width: `${bothPct}%`,    background: '#9b59b6' }} />}
      {unknownPct > 0 && <div style={{ width: `${unknownPct}%`, background: '#95a5a6' }} />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main export — wraps inner component in ReactFlowProvider
// ---------------------------------------------------------------------------

export const NetworkGraph = memo(function NetworkGraph(props: NetworkGraphProps) {
  return (
    <ReactFlowProvider>
      <NetworkGraphContent {...props} />
    </ReactFlowProvider>
  );
});

// ---------------------------------------------------------------------------
// Inner component — uses React Flow hooks
// ---------------------------------------------------------------------------

function NetworkGraphContent({
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
  captureMode = false,
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

  const [rfNodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [rfEdges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const { fitView } = useReactFlow();

  const [layouting, setLayouting] = useState(false);
  const [shouldFit, setShouldFit]  = useState(false);
  const [hoveredId, setHoveredId]  = useState<string | null>(null);

  const onLayoutCompleteRef = useRef(onLayoutComplete);
  useEffect(() => { onLayoutCompleteRef.current = onLayoutComplete; });

  // Pre-compute hidden-neighbor map (nodeId → hidden GraphNodes)
  const hiddenNodeMap = useMemo(
    () => new Map(hiddenNodesList.map(n => [n.id, n])),
    [hiddenNodesList]
  );
  const hiddenNeighborMap = useMemo(() => {
    const map = new Map<string, GraphNode[]>();
    for (const ce of crossEdges) {
      const srcHidden = hiddenNodeMap.has(ce.source);
      const tgtHidden = hiddenNodeMap.has(ce.target);
      if (srcHidden && !tgtHidden) {
        const list = map.get(ce.target) ?? [];
        list.push(hiddenNodeMap.get(ce.source)!);
        map.set(ce.target, list);
      } else if (tgtHidden && !srcHidden) {
        const list = map.get(ce.source) ?? [];
        list.push(hiddenNodeMap.get(ce.target)!);
        map.set(ce.source, list);
      }
    }
    return map;
  }, [crossEdges, hiddenNodeMap]);

  // Neighbor set for hover dimming
  const neighborSet = useMemo(() => {
    if (!hoveredId) return new Set<string>();
    const set = new Set<string>();
    for (const e of edges) {
      if (e.source === hoveredId) set.add(e.target);
      if (e.target === hoveredId) set.add(e.source);
    }
    return set;
  }, [hoveredId, edges]);

  // Main layout effect: recompute whenever nodes/edges/layout/source change
  useEffect(() => {
    if (nodes.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    let active = true;
    setLayouting(true);
    setHoveredId(null);

    const visibleNodes =
      layoutType === 'hierarchicalTd'
        ? (() => {
            const connected = new Set(edges.flatMap(e => [e.source, e.target]));
            return nodes.filter(n => connected.has(n.id));
          })()
        : nodes;

    computeLayout(visibleNodes, edges, layoutType)
      .then(({ positions, dedupedEdges }) => {
        if (!active) return;

        const maxBytes = Math.max(...visibleNodes.map(n => n.data.totalBytes || 0), 1);
        const nodeIdSet = new Set(visibleNodes.map(n => n.id));

        const newNodes: Node[] = visibleNodes.map(n => {
          const pos = positions.get(n.id) ?? { x: 0, y: 0 };
          const isSecondary =
            n.data.sources?.length === 1 &&
            primarySource !== undefined &&
            n.data.sources[0] !== primarySource;

          return {
            id: n.id,
            type: n.data.isCluster ? 'cluster' : 'host',
            position: pos,
            // Cluster nodes need explicit dimensions for RF to handle edges correctly
            style: n.data.isCluster
              ? { width: 160, opacity: isSecondary ? 0.45 : 1 }
              : { opacity: isSecondary ? 0.45 : 1 },
            data: {
              ...n.data,
              label: n.label,
              color: n.data.isCluster ? getClusterColor(n.data) : getNodeColor(n.data),
              size: computeNodeSize(n.data.totalBytes, maxBytes),
              hiddenNeighbors: hiddenNeighborMap.get(n.id) ?? [],
              onExpand: n.data.isCluster && onClusterClick
                ? () => onClusterClick(n.data.clusterId!)
                : undefined,
            },
          };
        });

        const newEdges: Edge[] = dedupedEdges
          .filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target))
          .map(e => {
            const isSecondary =
              e.data.sources?.length === 1 &&
              primarySource !== undefined &&
              e.data.sources[0] !== primarySource;
            const baseColor = getProtocolColor(e.data.protocol);
            const color = isSecondary ? mixWithGray(baseColor, 0.5) : baseColor;
            const strokeWidth = Math.max(1, Math.log10(e.data.packetCount + 1) * 1.5);

            return {
              id: e.id,
              source: e.source,
              target: e.target,
              label: e.label,
              type: 'smoothstep',
              style: { stroke: color, strokeWidth },
              labelStyle: { fontSize: 9, fill: darkMode ? '#ccc' : '#555', fontFamily: 'inherit' },
              labelBgStyle: {
                fill: darkMode ? '#1e1e2e' : '#fff',
                fillOpacity: 0.85,
                rx: 2,
              },
              markerEnd: {
                type: MarkerType.ArrowClosed,
                color,
                width: 12,
                height: 12,
              },
              data: e.data as unknown as Record<string, unknown>,
            };
          });

        setNodes(newNodes);
        setEdges(newEdges);
        setShouldFit(true);
      })
      .catch(err => {
        if (!active) return;
        console.error('[NetworkGraph] Layout error:', err);
        setLayouting(false);
      });

    return () => { active = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, layoutType, primarySource, captureMode]);

  // Fit view once nodes have been rendered
  useEffect(() => {
    if (!shouldFit || rfNodes.length === 0) return;
    const frame = requestAnimationFrame(() => {
      fitView({ padding: 0.12, duration: captureMode ? 0 : 400 });
      setShouldFit(false);
      const delay = captureMode ? 200 : 500;
      setTimeout(() => {
        setLayouting(false);
        onLayoutCompleteRef.current?.();
      }, delay);
    });
    return () => cancelAnimationFrame(frame);
  }, [shouldFit, rfNodes.length, fitView, captureMode]);

  // Hover dim — overlay opacity on non-neighbors
  const displayNodes = useMemo<Node[]>(() => {
    if (!hoveredId) return rfNodes;
    return rfNodes.map(n => ({
      ...n,
      style: {
        ...n.style,
        opacity:
          n.id === hoveredId || neighborSet.has(n.id)
            ? (n.style?.opacity ?? 1)
            : 0.12,
        transition: 'opacity 0.15s',
      },
    }));
  }, [rfNodes, hoveredId, neighborSet]);

  const displayEdges = useMemo<Edge[]>(() => {
    if (!hoveredId) return rfEdges;
    return rfEdges.map(e => ({
      ...e,
      style: {
        ...e.style,
        opacity:
          e.source === hoveredId || e.target === hoveredId ? 1 : 0.05,
        transition: 'opacity 0.15s',
      },
    }));
  }, [rfEdges, hoveredId]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      if (node.data.isCluster) return; // handled inside ClusterNodeComp
      const original = nodes.find(n => n.id === node.id);
      if (original) onNodeClick?.(original);
    },
    [nodes, onNodeClick]
  );

  const handleNodeMouseEnter = useCallback((_: React.MouseEvent, node: Node) => {
    setHoveredId(node.id);
  }, []);

  const handleNodeMouseLeave = useCallback(() => {
    setHoveredId(null);
  }, []);

  // Empty state
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
    <div className="network-graph-wrapper">
      {layouting && (
        <div className="network-graph-layouting">
          <div className="spinner-border spinner-border-sm text-secondary me-2" role="status" />
          Computing layout…
        </div>
      )}

      <ReactFlow
        nodes={displayNodes}
        edges={displayEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        onNodeClick={handleNodeClick}
        onNodeMouseEnter={handleNodeMouseEnter}
        onNodeMouseLeave={handleNodeMouseLeave}
        nodesDraggable
        nodesConnectable={false}
        elementsSelectable
        minZoom={0.02}
        maxZoom={4}
        colorMode={darkMode ? 'dark' : 'light'}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={24} size={1} color={darkMode ? '#333' : '#e0e0e0'} />

        {!captureMode && (
          <Controls showInteractive={false} />
        )}

        {!captureMode && (
          <MiniMap
            nodeColor={n => (n.data as { color?: string }).color ?? '#95a5a6'}
            zoomable
            pannable
            style={{ opacity: 0.85 }}
          />
        )}

        {onLayoutChange && (
          <Panel position="bottom-right">
            <div className="ng-layout-controls">
              <button
                className={layoutType === 'forceDirected2d' ? 'active' : ''}
                onClick={() => onLayoutChange('forceDirected2d')}
                title="Force-directed layout"
              >
                <i className="bi bi-diagram-2" />
              </button>
              <button
                className={layoutType === 'hierarchicalTd' ? 'active' : ''}
                onClick={() => onLayoutChange('hierarchicalTd')}
                title="Hierarchical layout"
              >
                <i className="bi bi-diagram-3" />
              </button>
            </div>
          </Panel>
        )}
      </ReactFlow>
    </div>
  );
}
