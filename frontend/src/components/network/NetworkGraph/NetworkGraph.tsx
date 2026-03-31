import { useRef, memo } from 'react';
import { GraphCanvas, type GraphCanvasRef } from 'reagraph';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import { getProtocolColor, NODE_TYPE_COLORS } from '@/features/network/constants';
import './NetworkGraph.css';

interface NetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (node: GraphNode) => void;
  layoutType?: 'forceDirected2d' | 'hierarchicalTd';
}

/**
 * Get node color based on detected node type (falls back to role-based color)
 */
function getNodeColor(nodeData: { role: string; isAnomaly: boolean; nodeType?: string }): string {
  if (nodeData.isAnomaly) return NODE_TYPE_COLORS['anomaly'];
  if (nodeData.nodeType && NODE_TYPE_COLORS[nodeData.nodeType])
    return NODE_TYPE_COLORS[nodeData.nodeType];

  // Fallback to role-based colour for unclassified nodes
  switch (nodeData.role) {
    case 'server':
      return '#2ecc71'; // Green
    case 'both':
      return '#9b59b6'; // Purple
    default:
      return '#95a5a6'; // Gray
  }
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
    const incomingIds = new Set(edges.map(e => e.target));
    const rootIds = edgeNodes.filter(n => !incomingIds.has(n.id)).map(n => n.id);

    if (rootIds.length > 1) {
      // Inject virtual root node and edges — styled invisible
      displayNodes = [
        {
          id: VIRTUAL_ROOT,
          label: '',
          data: { role: 'client', isAnomaly: false, totalBytes: 0 },
        } as any,
        ...edgeNodes,
      ];
      displayEdges = [
        ...rootIds.map(id => ({
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
        ...edges,
      ];
    } else {
      displayNodes = edgeNodes;
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
