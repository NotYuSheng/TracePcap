import { useRef, memo } from 'react';
import { GraphCanvas, type GraphCanvasRef } from 'reagraph';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import { getProtocolColor, NODE_TYPE_COLORS } from '@/features/network/constants';
import { deviceTypeColor } from '@/utils/deviceType';
import './NetworkGraph.css';

interface NetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (node: GraphNode) => void;
  layoutType?: 'forceDirected2d' | 'hierarchicalTd';
}

// Node types that carry specific semantic meaning — device type should not override these.
const SPECIFIC_NODE_TYPES = new Set([
  'dns-server', 'web-server', 'ssh-server', 'ftp-server',
  'mail-server', 'dhcp-server', 'ntp-server', 'database-server', 'router',
]);

/**
 * Get node color:
 *   anomaly > specific port-based nodeType > device type > generic nodeType > role fallback.
 *
 * Specific server roles (DNS, HTTP, SSH, …) keep their dedicated colours.
 * Device type colours apply only to generic nodes (client / unknown).
 */
function getNodeColor(nodeData: {
  role: string;
  isAnomaly: boolean;
  nodeType?: string;
  deviceType?: string;
}): string {
  if (nodeData.isAnomaly) return NODE_TYPE_COLORS['anomaly'];

  // Specific server roles win — they carry meaningful port-based identity.
  if (nodeData.nodeType && SPECIFIC_NODE_TYPES.has(nodeData.nodeType))
    return NODE_TYPE_COLORS[nodeData.nodeType];

  // For generic nodes, device type adds useful information.
  if (nodeData.deviceType && nodeData.deviceType !== 'UNKNOWN')
    return deviceTypeColor(nodeData.deviceType);

  // Generic node type colour (client = blue, unknown = gray).
  if (nodeData.nodeType && NODE_TYPE_COLORS[nodeData.nodeType])
    return NODE_TYPE_COLORS[nodeData.nodeType];

  // Final role-based fallback.
  switch (nodeData.role) {
    case 'server': return '#2ecc71';
    case 'both':   return '#9b59b6';
    default:       return '#95a5a6';
  }
}

/**
 * Build a BFS spanning tree from `nodes` using `edges`.
 * Returns the subset of edges that form the tree (back-edges are dropped so
 * d3 stratify() receives a DAG with no cycles).  O(V+E) via adjacency list.
 */
function bfsSpanningTree(
  nodes: GraphNode[],
  edges: GraphEdge[],
): GraphEdge[] {
  // Build adjacency list: source → outgoing edges
  const adj = new Map<string, GraphEdge[]>();
  for (const edge of edges) {
    if (!adj.has(edge.source)) adj.set(edge.source, []);
    adj.get(edge.source)!.push(edge);
  }

  const incomingIds = new Set(edges.map(e => e.target));
  const rootIds = nodes.filter(n => !incomingIds.has(n.id)).map(n => n.id);

  const visited = new Set<string>();
  const treeEdges: GraphEdge[] = [];
  const queue: string[] = rootIds.length > 0 ? [...rootIds] : (nodes[0] ? [nodes[0].id] : []);
  queue.forEach(id => visited.add(id));

  const bfs = (startQueue: string[]) => {
    const q = [...startQueue];
    while (q.length > 0) {
      const current = q.shift()!;
      for (const edge of adj.get(current) ?? []) {
        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          treeEdges.push(edge);
          q.push(edge.target);
        }
      }
    }
  };

  bfs(queue);

  // Handle disconnected sub-graphs
  for (const node of nodes) {
    if (!visited.has(node.id)) {
      visited.add(node.id);
      bfs([node.id]);
    }
  }

  return treeEdges;
}

export const NetworkGraph = memo(function NetworkGraph({
  nodes,
  edges,
  onNodeClick,
  layoutType = 'forceDirected2d',
}: NetworkGraphProps) {
  const graphRef = useRef<GraphCanvasRef>(null);

  // Hierarchical layout uses D3 stratify() which requires exactly ONE root
  // (a node with no incoming edges). Network graphs almost always have multiple
  // roots, which throws "multiple roots" and silently blanks the canvas.
  //
  // Fix: for hierarchical mode —
  //   1. Drop isolated nodes (no edges) — they have no valid position in a tree.
  //   2. Inject a hidden virtual root connected to every actual root (node with
  //      no incoming edges) so stratify() always sees a single root.
  const connectedNodeIds = new Set(edges.flatMap(e => [e.source, e.target]));
  const VIRTUAL_ROOT = '__vr__';

  let displayNodes = nodes;
  let displayEdges = edges;

  if (layoutType === 'hierarchicalTd') {
    // Keep only nodes that have at least one edge
    const edgeNodes = nodes.filter(n => connectedNodeIds.has(n.id));

    // Build a spanning tree via BFS to eliminate cycles.
    // d3 stratify() requires a DAG — bidirectional edges create cycles that crash it.
    // Pre-index adjacency list for O(V+E) BFS instead of O(V*E).
    const treeEdges = bfsSpanningTree(edgeNodes, edges);

    // Determine roots in the spanning tree
    const treeTargets = new Set(treeEdges.map(e => e.target));
    const treeRootIds = edgeNodes.filter(n => !treeTargets.has(n.id)).map(n => n.id);

    if (treeRootIds.length > 1) {
      // Inject virtual root so stratify() sees exactly one root
      displayNodes = [
        {
          id: VIRTUAL_ROOT,
          label: '',
          data: { role: 'client', isAnomaly: false, totalBytes: 0 },
        } as any,
        ...edgeNodes,
      ];
      displayEdges = [
        ...treeRootIds.map(id => ({
          id: `${VIRTUAL_ROOT}_${id}`,
          source: VIRTUAL_ROOT,
          target: id,
          label: '',
          data: {
            protocol: 'TCP',
            packetCount: 1,
            totalBytes: 0,
            conversationId: '',
            bidirectional: false,
          },
        })),
        ...treeEdges,
      ];
    } else {
      displayNodes = edgeNodes;
      displayEdges = treeEdges;
    }
  }

  // Transform nodes for reagraph
  const reagraphNodes = displayNodes.map(node => ({
    id: node.id,
    label: node.id === VIRTUAL_ROOT ? '' : node.label,
    fill: node.id === VIRTUAL_ROOT ? 'transparent' : getNodeColor(node.data),
    size: node.id === VIRTUAL_ROOT ? 0.01 : Math.max(5, Math.log((node.data as any).totalBytes + 1) * 2),
    data: node.data,
  }));

  // Transform edges for reagraph
  const reagraphEdges = displayEdges.map(edge => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.source === VIRTUAL_ROOT ? '' : edge.label,
    stroke: edge.source === VIRTUAL_ROOT ? 'transparent' : getProtocolColor(edge.data.protocol),
    size: edge.source === VIRTUAL_ROOT ? 0.01 : Math.max(1, Math.log(edge.data.packetCount) * 0.5),
    data: edge.data,
  }));

  const handleNodeClick = (node: any) => {
    if (onNodeClick) {
      // Find the original node with full data
      const originalNode = nodes.find(n => n.id === node.id);
      if (originalNode) {
        onNodeClick(originalNode);
      }
    }
  };

  const resetCamera = () => {
    if (graphRef.current) {
      graphRef.current.centerGraph();
    }
  };

  if (nodes.length === 0) {
    return (
      <div className="network-graph-empty">
        <i className="bi bi-diagram-3" style={{ fontSize: '4rem', opacity: 0.3 }}></i>
        <h5 className="mt-3 text-muted">No Network Data Available</h5>
        <p className="text-muted">Upload a pcap file to visualize network topology</p>
      </div>
    );
  }

  return (
    <div className="network-graph-container">
      <GraphCanvas
        key={layoutType}
        ref={graphRef}
        nodes={reagraphNodes}
        edges={reagraphEdges}
        layoutType={layoutType}
        onNodeClick={handleNodeClick}
        labelType="all"
        edgeLabelPosition="natural"
        draggable
      />
      <button
        className="btn btn-sm btn-light reset-camera-btn"
        onClick={resetCamera}
        title="Reset camera view"
      >
        <i className="bi bi-arrows-fullscreen"></i>
      </button>
    </div>
  );
});
