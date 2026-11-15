import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Form } from '@govtechsg/sgds-react';
import { NetworkGraph } from '@/components/network/NetworkGraph';
import type { GraphLayoutType, GraphNode } from '@/features/network/types';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { useMapPlayback } from '@/features/network/hooks/useMapPlayback';
import { EntityDetailModal, graphNodeEntity } from '@components/common/EntityDetailModal';
import { buildHighlightMap } from '@/features/monitor/utils/changeHighlights';
import type { ChangeEvent, NetworkSnapshot } from '@/features/monitor/types/monitor.types';
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
  /** The play bar under the graph (time window or packet replay); traffic dots move either way. */
  controls?: boolean;
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
  controls = true,
}: SnapshotMapProps) {
  const navigate = useNavigate();
  const [layoutType, setLayoutType] = useState<GraphLayoutType>('grouped');
  const [selected, setSelected] = useState<GraphNode | null>(null);
  // Draw the devices that left since the capture before, faded, where they were.
  const [ghosts, setGhosts] = useState(false);
  // The gone device being hovered in the list: drawn and ringed on the map.
  const [hoverGone, setHoverGone] = useState<string | null>(null);
  // In this network, so its own detection rules' matches show too (#925 phase 3).
  const { nodes, edges, loading, hiddenNodesList } = useNetworkData(snapshot.fileId, undefined, undefined, networkId);

  const playback = useMapPlayback(snapshot.fileId, nodes, edges, { controls });
  // The capture before, to find the local devices this one no longer has (the backend records no
  // removal events). Its nodes are what the faded "gone" devices are drawn from.
  const before = useNetworkData(previous?.fileId ?? '', undefined, undefined, networkId);
  const goneNodes = useMemo(() => {
    if (!previous) return [];
    // Still here if either its MAC or its address still is: one capture can know a device's MAC
    // where the other only saw its IP, and a device that only changed address hasn't left.
    // Every device of both captures, not just the ones drawn: the map shows at most 50, and a device
    // past that cap is hidden, not gone.
    const all = [...nodes, ...hiddenNodesList];
    const macs = new Set(all.map(n => n.data.mac).filter(Boolean));
    const ips = new Set(all.map(n => n.data.ip).filter(Boolean));
    const ids = new Set(all.map(n => n.id));
    return [...before.nodes, ...before.hiddenNodesList].filter(
      n =>
        (n.data.isL2 || isPrivateIp(n.data.ip)) &&
        !(n.data.mac && macs.has(n.data.mac)) &&
        !(n.data.ip && ips.has(n.data.ip)) &&
        !ids.has(n.id)
    );
  }, [previous, before.nodes, before.hiddenNodesList, nodes, hiddenNodesList]);
  const drawn = useMemo(
    () => (ghosts ? goneNodes : goneNodes.filter(n => n.id === hoverGone)),
    [ghosts, goneNodes, hoverGone]
  );
  const shownNodes = useMemo(() => (drawn.length ? [...nodes, ...drawn] : nodes), [nodes, drawn]);
  // Faded through the time axis's "not seen" styling, merged with whatever the play bar is showing.
  const activeInWindow = useMemo(() => {
    if (drawn.length === 0) return playback.activeInWindow;
    const already = playback.activeInWindow && 'faintNodeIds' in playback.activeInWindow ? playback.activeInWindow.faintNodeIds : undefined;
    const faint = new Set([...(already ?? []), ...drawn.map(n => n.id)]);
    if (playback.activeInWindow) return { ...playback.activeInWindow, faintNodeIds: faint };
    return { nodeIds: new Set(shownNodes.map(n => n.id)), edgeIds: new Set(edges.map(e => e.id)), faintNodeIds: faint };
  }, [drawn, playback.activeInWindow, shownNodes, edges]);
  const changeHighlights = useMemo(() => buildHighlightMap(changeEvents, snapshot.id), [changeEvents, snapshot.id]);
  const hovered = goneNodes.find(n => n.id === hoverGone);
  const highlighted = useMemo(() => {
    if (!hovered) return changeHighlights;
    const m = new Map(changeHighlights);
    m.set(hovered.label ?? hovered.data.ip, { color: '#5925dc', label: 'Gone since the capture before' });
    return m;
  }, [changeHighlights, hovered]);
  const legend = useMemo(() => {
    const seen = new Map<string, string>();
    for (const h of highlighted.values()) if (!seen.has(h.label)) seen.set(h.label, h.color);
    return [...seen.entries()];
  }, [highlighted]);
  const gone = goneNodes;

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
            nodes={shownNodes}
            edges={edges}
            highlightedNodes={highlighted}
            layoutType={layoutType}
            onLayoutChange={setLayoutType}
            onNodeClick={setSelected}
            {...playback}
            activeInWindow={activeInWindow}
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
              {gone.length.toLocaleString()} {gone.length === 1 ? 'device' : 'devices'} gone since the capture before
            </span>
          )}
          {gone.length > 0 && (
            <Form.Check
              id={`ghosts-${snapshot.id}`}
              type="switch"
              className="snapshot-map-ghosts"
              label="Show them on the map, faded"
              checked={ghosts}
              onChange={e => setGhosts(e.target.checked)}
            />
          )}
        </div>
      )}
      {gone.length > 0 && (
        <ul className="snapshot-map-gone" aria-label="Devices gone since the capture before">
          {gone.map(g => (
            <li key={g.id}>
              <button
                type="button"
                className={`snapshot-map-gone-item${hoverGone === g.id ? ' active' : ''}`}
                aria-label={`Point out ${g.data.ip}${g.data.mac ? ` (${g.data.mac})` : ''} on the map`}
                onMouseEnter={() => setHoverGone(g.id)}
                onMouseLeave={() => setHoverGone(h => (h === g.id ? null : h))}
                onFocus={() => setHoverGone(g.id)}
                onBlur={() => setHoverGone(h => (h === g.id ? null : h))}
              >
                <span className="font-monospace">{g.data.ip}</span>
                {g.data.mac && <span className="snapshot-map-gone-mac font-monospace">{g.data.mac}</span>}
              </button>
            </li>
          ))}
        </ul>
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
