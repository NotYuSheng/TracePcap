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
  const [activeLegendProtocols, setActiveLegendProtocols] = useState<string[]>([]);
  const [activeLegendNodeTypes, setActiveLegendNodeTypes] = useState<string[]>([]);

  const toggleLegendProtocol = (key: string) =>
    setActiveLegendProtocols(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    );

  const toggleLegendNodeType = (key: string) =>
    setActiveLegendNodeTypes(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    );
  const [layoutType, setLayoutType] = useState<'forceDirected2d' | 'hierarchicalTd'>(
    'forceDirected2d'
  );

  // Which node type keys actually exist in the data
  const presentNodeTypes = useMemo(() => {
    const types = new Set<string>();
    nodes.forEach(n => {
      if (n.data.isAnomaly) types.add('anomaly');
      types.add(n.data.nodeType);
    });
    return types;
  }, [nodes]);

  // Which edge legend keys actually have matching edges
  const presentEdgeLegendKeys = useMemo(() => {
    const keys = new Set<string>();
    edges.forEach(edge => {
      const proto = edge.data.protocol.toUpperCase();
      const app = (edge.data.appName ?? '').toUpperCase();
      if (proto === 'HTTP' || app === 'HTTP') keys.add('HTTP');
      if (proto === 'HTTPS' || app.includes('TLS') || app.includes('SSL') || app.includes('HTTPS')) keys.add('HTTPS');
      if (proto === 'DNS'  || app === 'DNS')  keys.add('DNS');
      if (proto === 'TCP')  keys.add('TCP');
      if (proto === 'UDP')  keys.add('UDP');
    });
    return keys;
  }, [edges]);

  // Filter nodes and edges based on active legend filters
  const { filteredNodes, filteredEdges } = useMemo(() => {
    let filtered = edges;

    // Apply legend protocol filter — show edges matching ANY selected key
    if (activeLegendProtocols.length > 0) {
      filtered = filtered.filter(edge => {
        const proto = edge.data.protocol.toUpperCase();
        const app = (edge.data.appName ?? '').toUpperCase();
        return activeLegendProtocols.some(key => {
          if (key === 'HTTPS') return proto === 'HTTPS' || app.includes('TLS') || app.includes('SSL') || app.includes('HTTPS');
          return proto === key || app.includes(key);
        });
      });
    }

    // Apply node type filter — keep edges that touch at least one node matching ANY selected type
    if (activeLegendNodeTypes.length > 0) {
      const matchingIds = new Set(
        nodes
          .filter(n =>
            activeLegendNodeTypes.some(key =>
              key === 'anomaly' ? n.data.isAnomaly : n.data.nodeType === key
            )
          )
          .map(n => n.id)
      );
      filtered = filtered.filter(
        edge => matchingIds.has(edge.source) || matchingIds.has(edge.target)
      );
    }

    // Get set of node IDs that have at least one visible edge
    const visibleNodeIds = new Set<string>();
    filtered.forEach(edge => {
      visibleNodeIds.add(edge.source);
      visibleNodeIds.add(edge.target);
    });

    return {
      filteredNodes: nodes.filter(node => visibleNodeIds.has(node.id)),
      filteredEdges: filtered,
    };
  }, [nodes, edges, activeLegendProtocols, activeLegendNodeTypes]);

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
        <div className="col-lg-8">
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

        <div className="col-lg-4">
          <NetworkControls
            stats={stats}
            layoutType={layoutType}
            onLayoutChange={setLayoutType}
            activeLegendProtocols={activeLegendProtocols}
            onLegendProtocolClick={toggleLegendProtocol}
            onLegendProtocolClear={() => setActiveLegendProtocols([])}
            activeLegendNodeTypes={activeLegendNodeTypes}
            onLegendNodeTypeClick={toggleLegendNodeType}
            onLegendNodeTypeClear={() => setActiveLegendNodeTypes([])}
            presentNodeTypes={presentNodeTypes}
            presentEdgeLegendKeys={presentEdgeLegendKeys}
          />
        </div>
      </div>

      {selectedNode && (
        <NodeDetails node={selectedNode} edges={edges} fileId={fileId} onClose={handleCloseDetails} />
      )}
    </div>
  );
};
