import { useState, useEffect, useRef } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import {
  intelligenceService,
  type GroupBy,
  type ClusterGraphResponse,
} from '@/features/intelligence/services/intelligenceService';
import { SummaryStatsBar } from '@components/intelligence/SummaryStatsBar/SummaryStatsBar';
import { ClusterGraph } from '@components/intelligence/ClusterGraph/ClusterGraph';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const NetworkIntelligencePage = () => {
  const { data, fileId } = useOutletContext<AnalysisOutletContext>();

  const [groupBy, setGroupBy] = useState<GroupBy>('asn');

  const [clusterData, setClusterData] = useState<ClusterGraphResponse | null>(null);
  const [clusterLoading, setClusterLoading] = useState(false);
  const [clusterError, setClusterError] = useState<string | null>(null);

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

  const [autoSelected, setAutoSelected] = useState(false);

  // Fetch clusters when groupBy changes
  useEffect(() => {
    if (!fileId) return;
    setClusterLoading(true);
    setClusterError(null);
    intelligenceService
      .getClusters(fileId, groupBy)
      .then(data => {
        setClusterData(data);
        // On first load, auto-switch to subnet24 if all clusters are internal
        if (!autoSelected) {
          setAutoSelected(true);
          const allInternal = data.clusters.length > 0 &&
            data.clusters.every(c => c.label.startsWith('Internal'));
          if (allInternal && groupBy === 'asn') {
            setGroupBy('subnet24');
          }
        }
      })
      .catch(e => setClusterError(e instanceof Error ? e.message : 'Failed to load cluster data'))
      .finally(() => setClusterLoading(false));
  }, [fileId, groupBy]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="network-intelligence-page">
      <div className="mb-3">
        <h4 className="mb-1">Network Intelligence</h4>
        <p className="text-muted small mb-0">
          Identify who your network is talking to, where the traffic is flowing, and where risks are concentrated —
          without reviewing individual conversations. Best suited for large captures with many hosts.
        </p>
      </div>

      {/* Summary stats */}
      <SummaryStatsBar data={data} />

      {/* Cluster graph */}
      <div className="card mb-4" ref={graphCardRef}>
        <div className="card-header d-flex justify-content-between align-items-center">
          <div>
            <h6 className="mb-0">
              <i className="bi bi-diagram-3 me-2" />
              Network Cluster View
            </h6>
            <small className="text-muted">Click a cluster node to see its member IPs and statistics.</small>
          </div>
          <button
            className="btn btn-link btn-sm p-0 text-muted"
            onClick={toggleFullscreen}
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            <i className={`bi ${isFullscreen ? 'bi-fullscreen-exit' : 'bi-fullscreen'}`} />
          </button>
        </div>
        <div className="card-body intel-cluster-card-body">
          {clusterError && (
            <div className="alert alert-warning py-2" role="alert">
              <i className="bi bi-exclamation-triangle me-2" />
              {clusterError}
            </div>
          )}
          <ClusterGraph
            data={clusterData}
            loading={clusterLoading}
            groupBy={groupBy}
            onGroupByChange={setGroupBy}
            fileId={fileId}
          />
        </div>
      </div>

    </div>
  );
};
