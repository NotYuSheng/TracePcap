import { useState, useMemo, useRef, useEffect } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import type { GraphNode } from '@/features/network/types';
import { useNetworkData, CONVERSATION_LIMIT_ENABLED } from '@/features/network/hooks/useNetworkData';
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
  const [activeNodeFilters, setActiveNodeFilters] = useState<string[]>([]);

  const toggleLegendProtocol = (key: string) =>
    setActiveLegendProtocols(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    );

  const toggleNodeFilter = (key: string) =>
    setActiveNodeFilters(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    );

  const [layoutType, setLayoutType] = useState<'forceDirected2d' | 'hierarchicalTd'>(
    'forceDirected2d'
  );

  const graphCardRef = useRef<HTMLDivElement>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    const onFsChange = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, []);

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      graphCardRef.current?.requestFullscreen();
    } else {
      document.exitFullscreen();
    }
  };

  // Which node type keys actually exist in the data
  const presentNodeTypes = useMemo(() => {
    const types = new Set<string>();
    nodes.forEach(n => {
      if (n.data.isAnomaly) types.add('anomaly');
      types.add(n.data.nodeType);
    });
    return types;
  }, [nodes]);

  const presentDeviceTypes = useMemo(() => {
    const types = new Set<string>();
    nodes.forEach(n => {
      if (n.data.deviceType) types.add(n.data.deviceType);
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
      if (proto === 'HTTPS' || app.includes('TLS') || app.includes('SSL') || app.includes('HTTPS'))
        keys.add('HTTPS');
      if (proto === 'DNS' || app === 'DNS') keys.add('DNS');
      if (proto === 'TCP') keys.add('TCP');
      if (proto === 'UDP') keys.add('UDP');
      if (proto === 'ICMP' || proto === 'ICMPV6') keys.add('ICMP');
      if (proto === 'ARP') keys.add('ARP');
      if (proto === 'STP' || proto === 'RSTP') keys.add('STP');
      if (proto === 'LLDP') keys.add('LLDP');
      if (proto === 'CDP') keys.add('CDP');
      if (proto === 'EAPOL') keys.add('EAPOL');
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
          if (key === 'HTTPS')
            return (
              proto === 'HTTPS' ||
              app.includes('TLS') ||
              app.includes('SSL') ||
              app.includes('HTTPS')
            );
          if (key === 'ICMP') return proto === 'ICMP' || proto === 'ICMPV6';
          if (key === 'STP') return proto === 'STP' || proto === 'RSTP';
          return proto === key || app.includes(key);
        });
      });
    }

    // Apply combined node filter — a node matches if ANY selected filter matches it.
    // Prefixed keys: "nt:<nodeType>" for node types, "dt:<deviceType>" for device types.
    if (activeNodeFilters.length > 0) {
      const matchingIds = new Set(
        nodes
          .filter(n =>
            activeNodeFilters.some(key => {
              if (key.startsWith('nt:')) {
                const nt = key.slice(3);
                return nt === 'anomaly' ? n.data.isAnomaly : n.data.nodeType === nt;
              }
              if (key.startsWith('dt:')) return n.data.deviceType === key.slice(3);
              return false;
            })
          )
          .map(n => n.id)
      );
      filtered = filtered.filter(
        edge => matchingIds.has(edge.source) || matchingIds.has(edge.target)
      );
    }

    const hasActiveFilters =
      activeLegendProtocols.length > 0 ||
      activeNodeFilters.length > 0;

    // When filters are active, hide nodes with no visible edge.
    // When no filters are active, show all nodes (including hosts with no
    // connections in the rendered edge set) so the count matches Unique Hosts.
    let visibleNodes = nodes;
    if (hasActiveFilters) {
      const visibleNodeIds = new Set<string>();
      filtered.forEach(edge => {
        visibleNodeIds.add(edge.source);
        visibleNodeIds.add(edge.target);
      });
      visibleNodes = nodes.filter(node => visibleNodeIds.has(node.id));
    }

    return {
      filteredNodes: visibleNodes,
      filteredEdges: filtered,
    };
  }, [nodes, edges, activeLegendProtocols, activeNodeFilters]);

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
          {CONVERSATION_LIMIT_ENABLED && (
            stats.isLimited ? (
              <div className="alert alert-warning mt-2 mb-0">
                <i className="bi bi-exclamation-triangle me-2"></i>
                <strong>Performance limit active:</strong> Showing top {stats.displayedConversations?.toLocaleString()} of{' '}
                {stats.totalConversations?.toLocaleString()} conversations by packet count.{' '}
                Set <code>VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT=false</code> to render all.
              </div>
            ) : (
              <div className="alert alert-info mt-2 mb-0">
                <i className="bi bi-info-circle me-2"></i>
                <strong>Performance limit enabled</strong> — all{' '}
                {stats.totalConversations?.toLocaleString()}{' '}
                conversations are within the 500-connection limit and fully rendered.
              </div>
            )
          )}
        </div>
      </div>

      <div className="row">
        <div className="col-lg-8">
          <div className="card mb-3" ref={graphCardRef}>
            <div className="card-header d-flex justify-content-end py-1 px-2">
              <button
                className="btn btn-sm btn-light"
                onClick={toggleFullscreen}
                title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
              >
                <i className={`bi ${isFullscreen ? 'bi-fullscreen-exit' : 'bi-fullscreen'}`} />
              </button>
            </div>
            <div className="card-body p-0 network-diagram-graph-body">
              <NetworkGraph
                key={layoutType}
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
            activeNodeFilters={activeNodeFilters}
            onNodeFilterClick={toggleNodeFilter}
            onNodeFilterClear={() => setActiveNodeFilters([])}
            presentNodeTypes={presentNodeTypes}
            presentEdgeLegendKeys={presentEdgeLegendKeys}
            presentDeviceTypes={presentDeviceTypes}
          />
        </div>
      </div>

      {selectedNode && (
        <NodeDetails
          node={selectedNode}
          edges={edges}
          fileId={fileId}
          onClose={handleCloseDetails}
        />
      )}
    </div>
  );
};
