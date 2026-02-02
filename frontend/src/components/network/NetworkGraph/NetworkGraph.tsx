import { useRef, memo } from 'react';
import { GraphCanvas, type GraphCanvasRef } from 'reagraph';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import './NetworkGraph.css';

interface NetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (node: GraphNode) => void;
  layoutType?: 'forceDirected2d' | 'hierarchicalTd';
}

/**
 * Get node color based on role
 */
function getNodeColor(role: string, isAnomaly: boolean): string {
  if (isAnomaly) {
    return '#e74c3c'; // Red for anomalies
  }

  switch (role) {
    case 'client':
      return '#3498db'; // Blue
    case 'server':
      return '#2ecc71'; // Green
    case 'both':
      return '#9b59b6'; // Purple
    default:
      return '#95a5a6'; // Gray
  }
}

/**
 * Get edge color based on protocol
 */
function getProtocolColor(protocol: string): string {
  const protocolUpper = protocol.toUpperCase();

  switch (protocolUpper) {
    case 'HTTP':
      return '#2ecc71'; // Green
    case 'HTTPS':
    case 'TLS':
      return '#3498db'; // Blue
    case 'DNS':
      return '#f39c12'; // Orange
    case 'TCP':
      return '#7f8c8d'; // Gray
    case 'UDP':
      return '#f1c40f'; // Yellow
    case 'ICMP':
      return '#e67e22'; // Dark Orange
    case 'ARP':
      return '#16a085'; // Teal
    default:
      return '#95a5a6'; // Light Gray
  }
}

export const NetworkGraph = memo(function NetworkGraph({
  nodes,
  edges,
  onNodeClick,
  layoutType = 'forceDirected2d',
}: NetworkGraphProps) {
  const graphRef = useRef<GraphCanvasRef>(null);

  // Transform nodes for reagraph
  const reagraphNodes = nodes.map(node => ({
    id: node.id,
    label: node.label,
    fill: getNodeColor(node.data.role, node.data.isAnomaly),
    size: Math.max(5, Math.log(node.data.totalBytes + 1) * 2),
    data: node.data,
  }));

  // Transform edges for reagraph
  const reagraphEdges = edges.map(edge => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.label,
    stroke: getProtocolColor(edge.data.protocol),
    size: Math.max(1, Math.log(edge.data.packetCount) * 0.5),
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
