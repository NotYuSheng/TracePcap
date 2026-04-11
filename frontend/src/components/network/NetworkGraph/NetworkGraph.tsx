import { useState, useCallback, useEffect, useMemo, useRef, memo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Panel,
  Handle,
  Position,
  BaseEdge,
  EdgeLabelRenderer,
  applyNodeChanges,
  applyEdgeChanges,
  type Node,
  type Edge,
  type NodeChange,
  type EdgeChange,
  type NodeTypes,
  type EdgeTypes,
  type NodeProps,
  type EdgeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import ELK from 'elkjs';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import { ClusterNode, type ClusterFlowNodeData } from './ClusterNode';
import { getProtocolColor, NODE_TYPE_COLORS } from '@/features/network/constants';
import { deviceTypeColor } from '@/utils/deviceType';
import { useStore } from '@/store';
import './NetworkGraph.css';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface NetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (node: GraphNode) => void;
  /** Called when the user clicks the expand button on a cluster node. */
  onClusterClick?: (clusterId: string) => void;
  layoutType?: 'forceDirected2d' | 'hierarchicalTd';
  onLayoutChange?: (layout: 'forceDirected2d' | 'hierarchicalTd') => void;
  /** Called once after ELK layout completes and ReactFlow has painted. */
  onLayoutComplete?: () => void;
  /**
   * In compare mode, the label of the "primary" (File A) source.
   * Nodes/edges exclusive to the secondary source (File B) are rendered with
   * a dashed style to visually distinguish them.
   */
  primarySource?: string;
}

interface FlowNodeData extends Record<string, unknown> {
  label: string;
  color: string;
  icon: string;
  /** Which file(s) this node appears in — set only in compare mode. */
  sources?: string[];
  /** Label of the primary (File A) source — used to determine dashed styling. */
  primarySource?: string;
}

interface FlowEdgeData extends Record<string, unknown> {
  label: string;
  offset: number; // perpendicular pixel offset for parallel edges
  /** Which file(s) this edge appears in — set only in compare mode. */
  sources?: string[];
  /** Label of the primary (File A) source — used to determine dashed styling. */
  primarySource?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NODE_WIDTH = 56;
const NODE_HEIGHT = 56;
const CLUSTER_WIDTH = 140;
const CLUSTER_HEIGHT = 90;

const elk = new ELK();

// ---------------------------------------------------------------------------
// Node helpers
// ---------------------------------------------------------------------------

const SPECIFIC_NODE_TYPES = new Set([
  'dns-server',
  'web-server',
  'ssh-server',
  'ftp-server',
  'mail-server',
  'dhcp-server',
  'ntp-server',
  'database-server',
  'router',
]);

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
    case 'server':
      return '#2ecc71';
    case 'both':
      return '#9b59b6';
    default:
      return '#95a5a6';
  }
}

const NODE_ICONS: Record<string, string> = {
  router: 'bi-router',
  'web-server': 'bi-globe',
  'dns-server': 'bi-search',
  'ssh-server': 'bi-terminal',
  'ftp-server': 'bi-hdd-network',
  'mail-server': 'bi-envelope',
  'dhcp-server': 'bi-broadcast',
  'ntp-server': 'bi-clock',
  'database-server': 'bi-database',
  client: 'bi-laptop',
  anomaly: 'bi-exclamation-triangle-fill',
};

function getNodeIcon(nodeData: { nodeType?: string; isAnomaly: boolean }): string {
  if (nodeData.isAnomaly) return NODE_ICONS['anomaly'];
  return NODE_ICONS[nodeData.nodeType ?? ''] ?? 'bi-pc-display';
}

// ---------------------------------------------------------------------------
// Deduplicate same-protocol edges between the same node pair
// Handles backend inconsistencies where the same app protocol arrives with
// different casing (e.g. "telegram" vs "Telegram") across conversations.
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
    if (group.length === 1) {
      result.push(group[0]);
      continue;
    }
    const dominant = group.reduce((best, e) =>
      e.data.packetCount > best.data.packetCount ? e : best
    );
    const totalPackets = group.reduce((s, e) => s + e.data.packetCount, 0);
    const totalBytes = group.reduce((s, e) => s + e.data.totalBytes, 0);
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
// Parallel edge handling — perpendicular pixel offset
// All edges between the same node pair are fanned out as parallel straight
// lines. Each keeps its own protocol colour, label, and direction arrow.
// ---------------------------------------------------------------------------

function assignEdgeOffsets(edges: GraphEdge[]): Map<string, number> {
  // Group by unordered pair so A→B and B→A are fanned together
  const groups = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    const key = [e.source, e.target].sort().join('\0');
    const g = groups.get(key) ?? [];
    g.push(e);
    groups.set(key, g);
  }

  const offsetMap = new Map<string, number>();
  for (const group of groups.values()) {
    if (group.length === 1) {
      offsetMap.set(group[0].id, 0);
    } else {
      const step = 20; // px between parallel lines
      const mid = (group.length - 1) / 2;
      group.forEach((e, i) => {
        offsetMap.set(e.id, (i - mid) * step);
      });
    }
  }
  return offsetMap;
}

// ---------------------------------------------------------------------------
// ELK layout
// ---------------------------------------------------------------------------

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

async function computeLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  layoutType: 'forceDirected2d' | 'hierarchicalTd',
  primarySource?: string,
  onClusterClick?: (clusterId: string) => void
): Promise<{ nodes: Node[]; edges: Edge[] }> {
  // Drop edges whose source or target doesn't exist in the node list.
  // This guards against stale edges after clustering or filtering — ELK will
  // error on edges that reference unknown node IDs.
  const nodeIdSet = new Set(nodes.map(n => n.id));
  const validEdges = edges.filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target));
  const dedupedEdges = deduplicateEdges(validEdges);
  const offsetMap = assignEdgeOffsets(dedupedEdges);

  const graph = await elk.layout({
    id: 'root',
    layoutOptions: ELK_OPTIONS[layoutType],
    children: nodes.map(n => ({
      id: n.id,
      width: n.data.isCluster ? CLUSTER_WIDTH : NODE_WIDTH,
      height: n.data.isCluster ? CLUSTER_HEIGHT : NODE_HEIGHT,
    })),
    edges: dedupedEdges.map(e => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  });

  const posMap = new Map((graph.children ?? []).map(n => [n.id, { x: n.x ?? 0, y: n.y ?? 0 }]));

  const rfNodes: Node[] = nodes.map(n => {
    if (n.data.isCluster) {
      const clusterData: ClusterFlowNodeData = {
        label: n.label,
        clusterId: n.data.clusterId!,
        memberCount: n.data.memberCount ?? 0,
        statsText: n.data.hostname ?? '',
        hasAnomaly: n.data.isAnomaly,
        roleBreakdown: n.data.roleBreakdown ?? { client: 0, server: 0, both: 0, unknown: 0 },
        onExpand: onClusterClick ?? (() => {}),
        sources: n.data.sources,
        primarySource,
      };
      return {
        id: n.id,
        type: 'clusterNode',
        position: posMap.get(n.id) ?? { x: 0, y: 0 },
        data: clusterData,
        width: CLUSTER_WIDTH,
        height: CLUSTER_HEIGHT,
      };
    }
    return {
      id: n.id,
      type: 'networkNode',
      position: posMap.get(n.id) ?? { x: 0, y: 0 },
      data: {
        label: n.label,
        color: getNodeColor(n.data),
        icon: getNodeIcon(n.data),
        sources: n.data.sources,
        primarySource,
      },
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
    };
  });

  const rfEdges: Edge[] = dedupedEdges.map(e => {
    const color = getProtocolColor(e.data.protocol);
    const sources = e.data.sources;
    const isShared = sources && sources.length >= 2;
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      type: 'networkEdge',
      data: { label: e.label, offset: offsetMap.get(e.id) ?? 0, sources, primarySource },
      style: {
        stroke: color,
        strokeWidth: isShared ? 2.5 : 1.5,
      },
    };
  });

  return { nodes: rfNodes, edges: rfEdges };
}

// ---------------------------------------------------------------------------
// Custom node — Packet Tracer style: icon above, label below
// ---------------------------------------------------------------------------

function NetworkNode({ data }: NodeProps) {
  const { label, color, icon, sources, primarySource } = data as FlowNodeData;
  const isSecondaryOnly =
    sources?.length === 1 && primarySource !== undefined && sources[0] !== primarySource;
  const isShared = sources !== undefined && sources.length >= 2;
  return (
    <div
      className="network-flow-node"
      style={{
        borderColor: color,
        borderStyle: isSecondaryOnly ? 'dashed' : 'solid',
        opacity: isSecondaryOnly ? 0.8 : 1,
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="network-flow-handle"
        style={{ top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }}
      />
      <Handle
        type="source"
        position={Position.Top}
        className="network-flow-handle"
        style={{ top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }}
      />
      <div className="network-flow-icon" style={{ color }}>
        <i className={`bi ${icon}`} />
      </div>
      <span className="network-flow-label">{label}</span>
      {isShared && (
        <i
          className="bi bi-layers-fill"
          style={{
            position: 'absolute',
            bottom: 2,
            right: 2,
            fontSize: '0.6rem',
            color,
            opacity: 0.85,
          }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Custom edge — straight line with perpendicular offset per parallel edge
// ---------------------------------------------------------------------------

function NetworkEdge({ id, sourceX, sourceY, targetX, targetY, data, style }: EdgeProps) {
  const { label, offset, sources, primarySource } = (data ?? { label: '', offset: 0 }) as FlowEdgeData;
  const isSecondaryOnly =
    sources?.length === 1 && primarySource !== undefined && sources[0] !== primarySource;
  const edgeStyle = isSecondaryOnly
    ? { ...style, strokeDasharray: '6 3' }
    : style;

  // Use a canonical direction for the perpendicular so that A→B and B→A
  // both receive the same perpendicular unit vector.
  const canonicalX = sourceX < targetX || (sourceX === targetX && sourceY <= targetY);
  const cdx = canonicalX ? targetX - sourceX : sourceX - targetX;
  const cdy = canonicalX ? targetY - sourceY : sourceY - targetY;
  const len = Math.sqrt(cdx * cdx + cdy * cdy) || 1;
  const px = (-cdy / len) * offset;
  const py = (cdx / len) * offset;

  const sx = sourceX + px;
  const sy = sourceY + py;
  const tx = targetX + px;
  const ty = targetY + py;

  const labelX = sx + (tx - sx) * 0.3;
  const labelY = sy + (ty - sy) * 0.3;

  // Arrow at midpoint, pointing toward target
  const arrowX = (sx + tx) / 2;
  const arrowY = (sy + ty) / 2;
  const angle = Math.atan2(ty - sy, tx - sx) * (180 / Math.PI);
  const arrowColor = (style?.stroke as string) ?? '#999';

  const edgePath = `M ${sx},${sy} L ${tx},${ty}`;

  return (
    <>
      <BaseEdge id={id} path={edgePath} style={edgeStyle} />
      <polygon
        points="-6,-3.5 6,0 -6,3.5"
        transform={`translate(${arrowX},${arrowY}) rotate(${angle})`}
        fill={arrowColor}
      />
      {label && (
        <EdgeLabelRenderer>
          <div
            className="network-flow-edge-label nodrag nopan"
            style={{ transform: `translate(-50%,-50%) translate(${labelX}px,${labelY}px)` }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Stable type maps
// ---------------------------------------------------------------------------

const nodeTypes: NodeTypes = { networkNode: NetworkNode, clusterNode: ClusterNode };
const edgeTypes: EdgeTypes = { networkEdge: NetworkEdge };

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
    themeMode === 'dark' || (themeMode === 'system' && sysDark);
  const [rfNodes, setRfNodes] = useState<Node[]>([]);
  const [rfEdges, setRfEdges] = useState<Edge[]>([]);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  const onNodesChange = useCallback(
    (changes: NodeChange[]) => setRfNodes(nds => applyNodeChanges(changes, nds)),
    []
  );
  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) => setRfEdges(eds => applyEdgeChanges(changes, eds)),
    []
  );
  const [layouting, setLayouting] = useState(false);

  const visibleNodes = useMemo(() => {
    if (layoutType !== 'hierarchicalTd') return nodes;
    const connected = new Set(edges.flatMap(e => [e.source, e.target]));
    return nodes.filter(n => connected.has(n.id));
  }, [nodes, edges, layoutType]);

  useEffect(() => {
    let active = true;

    if (visibleNodes.length === 0) {
      setRfNodes([]);
      setRfEdges([]);
      return;
    }

    setLayouting(true);
    computeLayout(visibleNodes, edges, layoutType, primarySource, onClusterClick)
      .then(({ nodes: n, edges: e }) => {
        if (!active) return;
        setRfNodes(n);
        setRfEdges(e);
        setLayouting(false);
      })
      .catch(err => {
        if (!active) return;
        console.error('ELK layout error:', err);
        setLayouting(false);
      });

    return () => {
      active = false;
    };
  }, [visibleNodes, edges, layoutType, primarySource, onClusterClick]);

  // Signal the caller once the layout has been computed and painted.
  // Works for both the normal case (rfNodes set after ELK) and the empty-data
  // case (visibleNodes.length === 0, layouting never becomes true).
  const onLayoutCompleteRef = useRef(onLayoutComplete);
  useEffect(() => {
    onLayoutCompleteRef.current = onLayoutComplete;
  });

  useEffect(() => {
    const idle = !layouting && (rfNodes.length > 0 || visibleNodes.length === 0);
    if (!idle) return;
    const id = requestAnimationFrame(() => onLayoutCompleteRef.current?.());
    return () => cancelAnimationFrame(id);
  }, [layouting, rfNodes.length, visibleNodes.length]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      // Cluster nodes handle their own expand click via the button in ClusterNode
      if (!onNodeClick) return;
      const original = nodes.find(n => n.id === node.id);
      if (original && !original.data.isCluster) onNodeClick(original);
    },
    [nodes, onNodeClick]
  );

  const handleNodeMouseEnter = useCallback((_: React.MouseEvent, node: Node) => {
    setHoveredNodeId(node.id);
  }, []);

  const handleNodeMouseLeave = useCallback(() => {
    setHoveredNodeId(null);
  }, []);

  // When a node is hovered, dim all nodes/edges not connected to it.
  const { dimmedNodeIds, dimmedEdgeIds } = useMemo(() => {
    if (!hoveredNodeId) return { dimmedNodeIds: new Set<string>(), dimmedEdgeIds: new Set<string>() };
    const connectedEdgeIds = new Set<string>();
    const neighborIds = new Set<string>([hoveredNodeId]);
    rfEdges.forEach(e => {
      if (e.source === hoveredNodeId || e.target === hoveredNodeId) {
        connectedEdgeIds.add(e.id);
        neighborIds.add(e.source);
        neighborIds.add(e.target);
      }
    });
    const dimNodes = new Set(rfNodes.map(n => n.id).filter(id => !neighborIds.has(id)));
    const dimEdges = new Set(rfEdges.map(e => e.id).filter(id => !connectedEdgeIds.has(id)));
    return { dimmedNodeIds: dimNodes, dimmedEdgeIds: dimEdges };
  }, [hoveredNodeId, rfNodes, rfEdges]);

  // Apply/remove "dimmed" className without recomputing layout.
  const displayNodes = useMemo(
    () =>
      hoveredNodeId
        ? rfNodes.map(n => ({ ...n, className: dimmedNodeIds.has(n.id) ? 'nf-dimmed' : '' }))
        : rfNodes,
    [hoveredNodeId, rfNodes, dimmedNodeIds]
  );

  const displayEdges = useMemo(
    () =>
      hoveredNodeId
        ? rfEdges.map(e => ({ ...e, className: dimmedEdgeIds.has(e.id) ? 'nf-dimmed' : '' }))
        : rfEdges,
    [hoveredNodeId, rfEdges, dimmedEdgeIds]
  );

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
    <div className="network-graph-container">
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
        edgeTypes={edgeTypes}
        onNodeClick={handleNodeClick}
        onNodeMouseEnter={handleNodeMouseEnter}
        onNodeMouseLeave={handleNodeMouseLeave}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        nodesConnectable={false}
        nodesDraggable
        elementsSelectable
        minZoom={0.1}
      >
        <Background gap={20} color={darkMode ? '#1e2130' : '#f0f0f0'} />
        <Controls showInteractive={false} />
        {onLayoutChange && (
          <Panel position="bottom-right">
            <div className="react-flow__controls network-layout-controls">
              <button
                className={`react-flow__controls-button${layoutType === 'forceDirected2d' ? ' active' : ''}`}
                onClick={() => onLayoutChange('forceDirected2d')}
                title="Force Directed layout"
              >
                <i className="bi bi-diagram-2" />
              </button>
              <button
                className={`react-flow__controls-button${layoutType === 'hierarchicalTd' ? ' active' : ''}`}
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
});
