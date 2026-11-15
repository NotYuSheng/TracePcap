import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Spinner } from '@components/common/Spinner/Spinner';
import { NetworkGraph } from '@/components/network/NetworkGraph';
import type { GraphLayoutType, GraphNode } from '@/features/network/types';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { EntityDetailModal, graphNodeEntity } from '@components/common/EntityDetailModal';
import { buildHighlightMap } from '@/features/monitor/utils/changeHighlights';
import type { ChangeEvent, NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { conversationService } from '@/features/conversation/services/conversationService';
import { isPrivateIp } from '@/utils/ipClassification';
import './SnapshotMap.css';

interface SnapshotMapProps {
  networkId: string;
  snapshot: NetworkSnapshot;
  changeEvents: ChangeEvent[];
  /** The capture before, to list the devices that left since (they aren't in this one to draw). */
  previous?: NetworkSnapshot | null;
  /** The graph's height in pixels. */
  height?: number;
}

interface GoneDevice {
  ip: string;
  mac: string | null;
}

/** Local devices in the capture before that this capture no longer has, by MAC (or IP without one). */
function useGoneDevices(fileId: string, previousFileId: string | null): GoneDevice[] {
  // Keyed by the pair it was worked out for, so a stale answer is never shown for another capture.
  const [result, setResult] = useState<{ key: string; gone: GoneDevice[] } | null>(null);
  const key = `${previousFileId}>${fileId}`;
  useEffect(() => {
    if (!previousFileId) return;
    let alive = true;
    Promise.all([
      conversationService.getHostClassifications(previousFileId),
      conversationService.getHostClassifications(fileId),
    ])
      .then(([before, now]) => {
        if (!alive) return;
        const id = (h: { ip: string; mac?: string | null }) => h.mac || h.ip;
        const present = new Set(now.map(id));
        setResult({
          key: `${previousFileId}>${fileId}`,
          gone: before
            .filter(h => isPrivateIp(h.ip) && !present.has(id(h)))
            .map(h => ({ ip: h.ip, mac: h.mac ?? null })),
        });
      })
      .catch(() => {
        if (alive) setResult({ key: `${previousFileId}>${fileId}`, gone: [] });
      });
    return () => {
      alive = false;
    };
  }, [fileId, previousFileId]);
  return previousFileId && result?.key === key ? result.gone : [];
}

/**
 * One capture of a monitored network, as its network map: the changes that capture brought are
 * highlighted in their severity colour, and devices that left since the capture before are listed
 * under it (they aren't in this capture to draw). Click a device for its details.
 */
export function SnapshotMap({
  networkId,
  snapshot,
  changeEvents,
  previous = null,
  height = 420,
}: SnapshotMapProps) {
  const navigate = useNavigate();
  const [layoutType, setLayoutType] = useState<GraphLayoutType>('grouped');
  const [selected, setSelected] = useState<GraphNode | null>(null);
  // In this network, so its own detection rules' matches show too (#925 phase 3).
  const { nodes, edges, loading } = useNetworkData(snapshot.fileId, undefined, undefined, networkId);

  const highlighted = useMemo(() => buildHighlightMap(changeEvents, snapshot.id), [changeEvents, snapshot.id]);
  const legend = useMemo(() => {
    const seen = new Map<string, string>();
    for (const h of highlighted.values()) if (!seen.has(h.label)) seen.set(h.label, h.color);
    return [...seen.entries()];
  }, [highlighted]);
  const gone = useGoneDevices(snapshot.fileId, previous?.fileId ?? null);

  return (
    <div className="snapshot-map">
      <div className="snapshot-map-graph" style={{ height }}>
        {loading ? (
          <div className="snapshot-map-loading">
            <Spinner animation="border" size="sm" className="me-2" />
            Loading the map…
          </div>
        ) : (
          <NetworkGraph
            key={snapshot.id}
            nodes={nodes}
            edges={edges}
            highlightedNodes={highlighted}
            layoutType={layoutType}
            onLayoutChange={setLayoutType}
            onNodeClick={setSelected}
          />
        )}
      </div>
      {(legend.length > 0 || gone.length > 0) && (
        <div className="snapshot-map-legend">
          {legend.map(([label, color]) => (
            <span key={label}>
              <span className="snapshot-map-dot" style={{ borderColor: color }} aria-hidden="true" />
              {label}
            </span>
          ))}
          {gone.length > 0 && (
            <span>
              <span className="snapshot-map-dot snapshot-map-dot-gone" aria-hidden="true" />
              Gone since the capture before:{' '}
              <span className="font-monospace">
                {gone.map(g => (g.mac ? `${g.ip} (${g.mac})` : g.ip)).join(', ')}
              </span>
            </span>
          )}
        </div>
      )}
      {selected && (
        <EntityDetailModal
          {...graphNodeEntity(selected)}
          fileId={snapshot.fileId}
          graphNode={selected}
          graphEdges={edges}
          onNavigate={navigate}
          changeHighlight={
            highlighted.get(selected.label ?? '') ??
            highlighted.get(selected.data.ip ?? '') ??
            highlighted.get(selected.data.mac ?? '')
          }
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}
