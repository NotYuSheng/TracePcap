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
import { getProtocolColor, NODE_TYPE_COLORS } from '@/features/network/constants';
import { deviceTypeColor } from '@/utils/deviceType';
import './NetworkGraph.css';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface NetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (node: GraphNode) => void;
  layoutType?: 'forceDirected2d' | 'hierarchicalTd';
  onLayoutChange?: (layout: 'forceDirected2d' | 'hierarchicalTd') => void;
  /** Called once after ELK layout completes and ReactFlow has painted. */
  onLayoutComplete?: () => void;
}

interface FlowNodeData extends Record<string, unknown> {
  label: string;
  color: string;
  icon: string;
}

interface FlowEdgeData extends Record<string, unknown> {
  label: string;
  offset: number; // perpendicular pixel offset for parallel edges
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NODE_WIDTH = 56;
const NODE_HEIGHT = 56;

const elk = new ELK();

// ---------------------------------------------------------------------------
// Node helpers
// ---------------------------------------------------------------------------

const SPECIFIC_NODE_TYPES = new Set([
  'dns-server', 'web-server', 'ssh-server', 'ftp-server',
  'mail-server', 'dhcp-server', 'ntp-server', 'database-server', 'router',
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
    case 'server': return '#2ecc71';
    case 'both':   return '#9b59b6';
    default:       return '#95a5a6';
  }
}

const NODE_ICONS: Record<string, string> = {
  'router':          'bi-router',
  'web-server':      'bi-globe',
  'dns-server':      'bi-search',
  'ssh-server':      'bi-terminal',
  'ftp-server':      'bi-hdd-network',
  'mail-server':     'bi-envelope',
  'dhcp-server':     'bi-broadcast',
  'ntp-server':      'bi-clock',
  'database-server': 'bi-database',
  'client':          'bi-laptop',
  'anomaly':         'bi-exclamation-triangle-fill',
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
      e.data.packetCount > best.data.packetCount ? e : best,
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
): Promise<{ nodes: Node[]; edges: Edge[] }> {
  const dedupedEdges = deduplicateEdges(edges);
  const offsetMap = assignEdgeOffsets(dedupedEdges);

  const graph = await elk.layout({
    id: 'root',
    layoutOptions: ELK_OPTIONS[layoutType],
    children: nodes.map(n => ({ id: n.id, width: NODE_WIDTH, height: NODE_HEIGHT })),
    edges: dedupedEdges.map(e => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  });

  const posMap = new Map(
    (graph.children ?? []).map(n => [n.id, { x: n.x ?? 0, y: n.y ?? 0 }]),
  );

  const rfNodes: Node[] = nodes.map(n => ({
    id: n.id,
    type: 'networkNode',
    position: posMap.get(n.id) ?? { x: 0, y: 0 },
    data: {
      label: n.label,
      color: getNodeColor(n.data),
      icon: getNodeIcon(n.data),
    },
    width: NODE_WIDTH,
    height: NODE_HEIGHT,
  }));

  const rfEdges: Edge[] = dedupedEdges.map(e => {
    const color = getProtocolColor(e.data.protocol);
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      type: 'networkEdge',
      data: { label: e.label, offset: offsetMap.get(e.id) ?? 0 },
      style: {
        stroke: color,
        strokeWidth: 1.5,
      },
    };
  });

  return { nodes: rfNodes, edges: rfEdges };
}

// ---------------------------------------------------------------------------
// Custom node — Packet Tracer style: icon above, label below
// ---------------------------------------------------------------------------

function NetworkNode({ data }: NodeProps) {
  const { label, color, icon } = data as FlowNodeData;
  return (
    <div className="network-flow-node" style={{ borderColor: color }}>
      <Handle type="target" position={Position.Top} className="network-flow-handle" style={{ top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }} />
      <Handle type="source" position={Position.Top} className="network-flow-handle" style={{ top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }} />
      <div className="network-flow-icon" style={{ color }}>
        <i className={`bi ${icon}`} />
      </div>
      <span className="network-flow-label">{label}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Custom edge — straight line with perpendicular offset per parallel edge
// ---------------------------------------------------------------------------

function NetworkEdge({ id, sourceX, sourceY, targetX, targetY, data, style }: EdgeProps) {
  const { label, offset } = (data ?? { label: '', offset: 0 }) as FlowEdgeData;

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

  const labelX = sx + (tx - sx) * 0.30;
  const labelY = sy + (ty - sy) * 0.30;

  // Arrow at midpoint, pointing toward target
  const arrowX = (sx + tx) / 2;
  const arrowY = (sy + ty) / 2;
  const angle = Math.atan2(ty - sy, tx - sx) * (180 / Math.PI);
  const arrowColor = (style?.stroke as string) ?? '#999';

  const edgePath = `M ${sx},${sy} L ${tx},${ty}`;

  return (
    <>
      <BaseEdge id={id} path={edgePath} style={style} />
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

const nodeTypes: NodeTypes = { networkNode: NetworkNode };
const edgeTypes: EdgeTypes = { networkEdge: NetworkEdge };

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export const NetworkGraph = memo(function NetworkGraph({
  nodes,
  edges,
  onNodeClick,
  layoutType = 'forceDirected2d',
  onLayoutChange,
  onLayoutComplete,
}: NetworkGraphProps) {
  const [rfNodes, setRfNodes] = useState<Node[]>([]);
  const [rfEdges, setRfEdges] = useState<Edge[]>([]);

  const onNodesChange = useCallback(
    (changes: NodeChange[]) => setRfNodes(nds => applyNodeChanges(changes, nds)),
    [],
  );
  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) => setRfEdges(eds => applyEdgeChanges(changes, eds)),
    [],
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
    computeLayout(visibleNodes, edges, layoutType)
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

    return () => { active = false; };
  }, [visibleNodes, edges, layoutType]);

  // Signal the caller once the layout has been computed and painted.
  // Works for both the normal case (rfNodes set after ELK) and the empty-data
  // case (visibleNodes.length === 0, layouting never becomes true).
  const onLayoutCompleteRef = useRef(onLayoutComplete);
  useEffect(() => { onLayoutCompleteRef.current = onLayoutComplete; });

  useEffect(() => {
    const idle =
      !layouting && (rfNodes.length > 0 || visibleNodes.length === 0);
    if (!idle) return;
    const id = requestAnimationFrame(() => onLayoutCompleteRef.current?.());
    return () => cancelAnimationFrame(id);
  }, [layouting, rfNodes.length, visibleNodes.length]);

  const handleNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    if (!onNodeClick) return;
    const original = nodes.find(n => n.id === node.id);
    if (original) onNodeClick(original);
  }, [nodes, onNodeClick]);

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
        nodes={rfNodes}
        edges={rfEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodeClick={handleNodeClick}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        nodesConnectable={false}
        nodesDraggable
        elementsSelectable
        minZoom={0.1}
      >
        <Background gap={20} color="#f0f0f0" />
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
