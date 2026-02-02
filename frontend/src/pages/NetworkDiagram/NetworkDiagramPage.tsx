import { useState, useMemo } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import type { GraphNode } from '@/features/network/types';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { NetworkGraph } from '@components/network/NetworkGraph';
import { NetworkControls } from '@components/network/NetworkControls';
import { NodeDetails } from '@components/network/NodeDetails';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const NetworkDiagramPage = () => {
  const { fileId, data } = useOutletContext<AnalysisOutletContext>();
  const { nodes, edges, stats, loading, error, refetch } = useNetworkData(fileId, data);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedProtocols, setSelectedProtocols] = useState<string[]>([]);
  const [layoutType, setLayoutType] = useState<'forceDirected2d' | 'hierarchicalTd'>(
    'forceDirected2d'
  );

  // Initialize protocol filter with all protocols
  useMemo(() => {
    if (stats.protocolBreakdown && selectedProtocols.length === 0) {
      setSelectedProtocols(Object.keys(stats.protocolBreakdown));
    }
  }, [stats.protocolBreakdown]);

  // Filter nodes and edges based on selected protocols
  const { filteredNodes, filteredEdges } = useMemo(() => {
    if (selectedProtocols.length === 0) {
      return { filteredNodes: nodes, filteredEdges: edges };
    }

    // Filter edges by protocol
    const filteredEdges = edges.filter(edge => selectedProtocols.includes(edge.data.protocol));

    // Get set of node IDs that have at least one visible edge
    const visibleNodeIds = new Set<string>();
    filteredEdges.forEach(edge => {
      visibleNodeIds.add(edge.source);
      visibleNodeIds.add(edge.target);
    });

    // Filter nodes to only show those with visible edges
    const filteredNodes = nodes.filter(node => visibleNodeIds.has(node.id));

    return { filteredNodes, filteredEdges };
  }, [nodes, edges, selectedProtocols]);

  const handleNodeClick = (node: GraphNode) => {
    setSelectedNode(node);
  };

  const handleCloseDetails = () => {
    setSelectedNode(null);
  };

  if (loading) {
    return <LoadingSpinner size="large" message="Building network topology..." fullPage />;
  }

  if (error) {
    return <ErrorMessage title="Failed to Load Network Data" message={error} onRetry={refetch} />;
  }

  return (
    <div className="network-diagram-page">
      <div className="row mb-3">
        <div className="col-12">
          <div className="d-flex justify-content-between align-items-center">
            <h4>
              <i className="bi bi-diagram-3 me-2"></i>
              Network Topology Diagram
            </h4>
            <div className="text-muted">
              {filteredNodes.length} nodes, {filteredEdges.length} connections
            </div>
          </div>
          {stats.isLimited && (
            <div className="alert alert-warning mt-2 mb-0">
              <i className="bi bi-exclamation-triangle me-2"></i>
              <strong>Performance Limit:</strong> Showing top {stats.displayedConversations} of{' '}
              {stats.totalConversations} conversations by packet count. This prevents browser lag
              with large captures.
            </div>
          )}
        </div>
      </div>

      <div className="row">
        <div className={selectedNode ? 'col-lg-8' : 'col-lg-9'}>
          <div className="card mb-3">
            <div className="card-body p-0" style={{ height: '600px' }}>
              <NetworkGraph
                nodes={filteredNodes}
                edges={filteredEdges}
                onNodeClick={handleNodeClick}
                layoutType={layoutType}
              />
            </div>
          </div>
        </div>

        <div className={selectedNode ? 'col-lg-4' : 'col-lg-3'}>
          <NetworkControls
            stats={stats}
            selectedProtocols={selectedProtocols}
            onProtocolFilterChange={setSelectedProtocols}
            layoutType={layoutType}
            onLayoutChange={setLayoutType}
          />

          {selectedNode && (
            <div className="mt-3">
              <NodeDetails node={selectedNode} edges={edges} onClose={handleCloseDetails} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
