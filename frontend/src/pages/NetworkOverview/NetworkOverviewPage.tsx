import { useState, useMemo } from 'react';
import { useOutletContext } from 'react-router-dom';
import { NetworkGraph } from '@components/network/NetworkGraph';
import { NodeDetails } from '@components/network/NodeDetails';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { applySubnetClustering } from '@/features/network/services/clusterService';
import { formatBytes } from '@/utils/formatters';
import type { GraphNode } from '@/features/network/types';
import type { AnalysisOutletContext } from '@pages/Analysis/AnalysisPage';

export const NetworkOverviewPage = () => {
  const { fileId, data: analysisSummary } = useOutletContext<AnalysisOutletContext>();

  // Fetch ALL nodes — maxNodes=0 disables the significance cap so every host
  // is available for clustering even in very large captures.
  const { nodes: allNodes, edges: allEdges, loading, error, stats } = useNetworkData(
    fileId,
    analysisSummary ?? undefined,
    0
  );

  // Track which subnet clusters the user has manually expanded.
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set());
  // Selected individual host node (shown in the NodeDetails side panel).
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Apply clustering — pure transform that re-runs whenever raw data or the
  // expanded set changes. Starts with all subnets collapsed.
  const { nodes: clusteredNodes, edges: clusteredEdges } = useMemo(
    () => applySubnetClustering(allNodes, allEdges, expandedClusters),
    [allNodes, allEdges, expandedClusters]
  );

  const handleClusterClick = (clusterId: string) => {
    setExpandedClusters(prev => new Set([...prev, clusterId]));
    setSelectedNode(null);
  };

  const handleNodeClick = (node: GraphNode) => {
    // Cluster nodes open the expand overlay (handled inside NetworkGraph).
    // Individual host nodes open the NodeDetails panel.
    if (!node.data.isCluster) setSelectedNode(node);
  };

  // Edges for the selected node — use the raw (unclustered) edges so NodeDetails
  // shows all real conversations, not the aggregated cluster-level edges.
  const selectedNodeEdges = useMemo(
    () => selectedNode
      ? allEdges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
      : [],
    [selectedNode, allEdges]
  );

  const collapseAll = () => setExpandedClusters(new Set());

  const subnetCount   = clusteredNodes.filter(n => n.data.isCluster).length;
  const expandedCount = clusteredNodes.filter(n => !n.data.isCluster).length;
  const totalHosts    = allNodes.length;

  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center" style={{ minHeight: 400 }}>
        <div className="text-center">
          <div className="spinner-border text-primary mb-3" role="status" />
          <p className="text-muted mb-0">Building network overview…</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert alert-danger">
        <i className="bi bi-exclamation-triangle-fill me-2" />
        {error}
      </div>
    );
  }

  return (
    <div className="d-flex flex-column gap-3">
      {/* ── Stats bar ──────────────────────────────────────────────── */}
      <div className="d-flex flex-wrap align-items-center gap-3">
        <div className="d-flex gap-3">
          <div className="text-center">
            <div className="fw-semibold fs-5">{subnetCount}</div>
            <div className="text-muted" style={{ fontSize: '0.78rem' }}>Subnets</div>
          </div>
          <div className="vr" />
          <div className="text-center">
            <div className="fw-semibold fs-5">{totalHosts}</div>
            <div className="text-muted" style={{ fontSize: '0.78rem' }}>Total Hosts</div>
          </div>
          <div className="vr" />
          <div className="text-center">
            <div className="fw-semibold fs-5">{clusteredEdges.length}</div>
            <div className="text-muted" style={{ fontSize: '0.78rem' }}>Inter-subnet Flows</div>
          </div>
          <div className="vr" />
          <div className="text-center">
            <div className="fw-semibold fs-5">{formatBytes(stats.totalBytes)}</div>
            <div className="text-muted" style={{ fontSize: '0.78rem' }}>Total Traffic</div>
          </div>
        </div>

        {expandedClusters.size > 0 && (
          <button
            className="btn btn-sm btn-outline-secondary ms-auto"
            onClick={collapseAll}
          >
            <i className="bi bi-arrows-angle-contract me-1" />
            Collapse all ({expandedCount} hosts)
          </button>
        )}

        <div className="ms-auto text-muted" style={{ fontSize: '0.8rem' }}>
          <i className="bi bi-info-circle me-1" />
          Click a subnet node to expand it
        </div>
      </div>

      {/* ── Graph + optional NodeDetails side panel ─────────────── */}
      <div className="d-flex gap-3" style={{ minHeight: 0 }}>
        <div className="card flex-grow-1" style={{ height: '70vh', position: 'relative', overflow: 'hidden' }}>
          <NetworkGraph
            nodes={clusteredNodes}
            edges={clusteredEdges}
            onNodeClick={handleNodeClick}
            onClusterClick={handleClusterClick}
            layoutType="forceDirected2d"
          />
        </div>

        {selectedNode && (
          <div style={{ width: 340, flexShrink: 0, overflowY: 'auto', maxHeight: '70vh' }}>
            <NodeDetails
              node={selectedNode}
              edges={selectedNodeEdges}
              fileId={fileId}
              onClose={() => setSelectedNode(null)}
            />
          </div>
        )}
      </div>
    </div>
  );
};
