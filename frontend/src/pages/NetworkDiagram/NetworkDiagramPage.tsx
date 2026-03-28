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
  const [activeLegendProtocol, setActiveLegendProtocol] = useState<string | null>(null);
  const [activeLegendNodeType, setActiveLegendNodeType] = useState<string | null>(null);
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

    // Apply legend protocol isolate filter (matches transport protocol OR app name)
    if (activeLegendProtocol) {
      const key = activeLegendProtocol.toUpperCase();
      filtered = filtered.filter(edge => {
        const proto = edge.data.protocol.toUpperCase();
        const app = (edge.data.appName ?? '').toUpperCase();
        // HTTPS key also matches TLS/SSL app names
        if (key === 'HTTPS') return proto === 'HTTPS' || app.includes('TLS') || app.includes('SSL') || app.includes('HTTPS');
        return proto === key || app === key || app.startsWith(key + ' ');
      });
    }

    // Apply node type isolate filter — keep edges that touch at least one matching node,
    // then include both endpoints so the connected context is visible.
    if (activeLegendNodeType) {
      const matchingIds = new Set(
        nodes
          .filter(n =>
            activeLegendNodeType === 'anomaly'
              ? n.data.isAnomaly
              : n.data.nodeType === activeLegendNodeType
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
  }, [nodes, edges, activeLegendProtocol, activeLegendNodeType]);

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
            layoutType={layoutType}
            onLayoutChange={setLayoutType}
            activeLegendProtocol={activeLegendProtocol}
            onLegendProtocolClick={setActiveLegendProtocol}
            activeLegendNodeType={activeLegendNodeType}
            onLegendNodeTypeClick={setActiveLegendNodeType}
            presentNodeTypes={presentNodeTypes}
            presentEdgeLegendKeys={presentEdgeLegendKeys}
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
