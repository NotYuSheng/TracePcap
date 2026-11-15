import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Card, Form } from '@govtechsg/sgds-react';
import { NetworkDiagramView } from '@/pages/NetworkDiagram/NetworkDiagramView';
import { useNetworkDiagramFilterState } from '@/features/network/hooks/useNetworkDiagramFilterState';
import { useGoneDevices } from '@/features/monitor/hooks/useGoneDevices';
import { buildHighlightMap } from '@/features/monitor/utils/changeHighlights';
import { ChangeList } from '@/components/monitor/ChangeList';
import {
  SnapshotContextTab,
  SnapshotInsightsTab,
  SnapshotSecurityPane,
  SnapshotSubnetsTab,
} from '@/components/monitor/SnapshotTabs';
import type { ChangeEvent, NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import './CapturePane.css';

type Tab = 'map' | 'changes' | 'security' | 'subnets' | 'context' | 'insights';

interface CapturePaneProps {
  networkId: string;
  snapshot: NetworkSnapshot;
  previous: NetworkSnapshot | null;
  index: number;
  total: number;
  onStep: (delta: -1 | 1) => void;
  snapshots: NetworkSnapshot[];
  changeEvents: ChangeEvent[];
  onPatchChange: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
  onSnapshotUpdated: (updated: NetworkSnapshot) => void;
}

const when = (s: NetworkSnapshot) =>
  new Date(s.startTime ?? s.addedAt).toLocaleString(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

/**
 * One capture of a monitored network, beside the Timeline's list: its network map (the analysis
 * page's full diagram, with the changes it brought and the devices gone since the capture before),
 * its changes, security signals, subnets, context and notes, and insights. What the capture pop-up
 * used to hold, without leaving the page.
 */
export function CapturePane({
  networkId,
  snapshot,
  previous,
  index,
  total,
  onStep,
  snapshots,
  changeEvents,
  onPatchChange,
  onSnapshotUpdated,
}: CapturePaneProps) {
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>('map');
  // Shared across captures, so stepping keeps the filters you set.
  const filters = useNetworkDiagramFilterState();
  const [ghosts, setGhosts] = useState(false);
  const [hoverGone, setHoverGone] = useState<string | null>(null);

  const changes = useMemo(() => changeEvents.filter(e => e.toSnapshotId === snapshot.id), [changeEvents, snapshot.id]);
  const gone = useGoneDevices(networkId, snapshot, previous);
  const hovered = gone.find(n => n.id === hoverGone);
  const ghostNodes = useMemo(
    () => (ghosts ? gone : hovered ? [hovered] : []),
    [ghosts, gone, hovered]
  );
  const changeHighlights = useMemo(() => buildHighlightMap(changeEvents, snapshot.id), [changeEvents, snapshot.id]);
  const highlights = useMemo(() => {
    if (!hovered) return changeHighlights;
    const m = new Map(changeHighlights);
    m.set(hovered.label ?? hovered.data.ip, { color: '#5925dc', label: 'Gone since the capture before' });
    return m;
  }, [changeHighlights, hovered]);
  const legend = useMemo(() => {
    const seen = new Map<string, string>();
    for (const h of changeHighlights.values()) if (!seen.has(h.label)) seen.set(h.label, h.color);
    return [...seen.entries()];
  }, [changeHighlights]);

  // ← → step between captures, unless typing.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
      if (document.querySelector('.modal.show')) return;
      if (e.key === 'ArrowLeft' && index > 0) onStep(-1);
      if (e.key === 'ArrowRight' && index < total - 1) onStep(1);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [index, total, onStep]);

  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: 'map', label: 'Map' },
    { id: 'changes', label: 'Changes', count: changes.length },
    { id: 'security', label: 'Security', count: snapshot.securitySignalCount || undefined },
    { id: 'subnets', label: 'Subnets', count: snapshot.subnetOverrides?.length || undefined },
    { id: 'context', label: 'Context & notes' },
    { id: 'insights', label: 'Insights' },
  ];

  const belowGraph = (
    <div className="capture-gone">
      <div className="capture-legend">
        {legend.map(([label, color]) => (
          <span key={label}>
            <span className="capture-dot" style={{ borderColor: color }} aria-hidden="true" />
            {label}
          </span>
        ))}
        {gone.length > 0 && (
          <>
            <span>
              <span className="capture-dot capture-dot-gone" aria-hidden="true" />
              {gone.length.toLocaleString()} {gone.length === 1 ? 'device' : 'devices'} gone since the capture before
            </span>
            <Form.Check
              id={`ghosts-${snapshot.id}`}
              type="switch"
              className="capture-ghosts"
              label="Show them on the map, faded"
              checked={ghosts}
              onChange={e => setGhosts(e.target.checked)}
            />
          </>
        )}
      </div>
      {gone.length > 0 && (
        <ul className="capture-gone-list" aria-label="Devices gone since the capture before">
          {gone.map(g => (
            <li key={g.id}>
              <button
                type="button"
                className={`capture-gone-item${hoverGone === g.id ? ' active' : ''}`}
                aria-label={`Point out ${g.data.ip}${g.data.mac ? ` (${g.data.mac})` : ''} on the map`}
                onMouseEnter={() => setHoverGone(g.id)}
                onMouseLeave={() => setHoverGone(h => (h === g.id ? null : h))}
                onFocus={() => setHoverGone(g.id)}
                onBlur={() => setHoverGone(h => (h === g.id ? null : h))}
              >
                <span className="font-monospace">{g.data.ip}</span>
                {g.data.mac && <span className="capture-gone-mac font-monospace">{g.data.mac}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );

  return (
    <Card className="capture-pane">
      <div className="capture-head">
        <div className="capture-title">
          <h2>{snapshot.fileName}</h2>
          <span className="text-muted small">
            {when(snapshot)} · {previous ? `compared with ${when(previous)}` : 'the baseline'}
          </span>
        </div>
        <div className="capture-nav">
          <Button size="sm" variant="outline-secondary" disabled={index <= 0} onClick={() => onStep(-1)} aria-label="Earlier capture">
            <i className="bi bi-chevron-left" aria-hidden="true" />
          </Button>
          <span className="small text-muted">
            {index + 1} of {total}
          </span>
          <Button size="sm" variant="outline-secondary" disabled={index >= total - 1} onClick={() => onStep(1)} aria-label="Later capture">
            <i className="bi bi-chevron-right" aria-hidden="true" />
          </Button>
          <Button size="sm" variant="outline-secondary" onClick={() => navigate(`/analysis/${snapshot.fileId}`)}>
            Open the capture <i className="bi bi-box-arrow-up-right ms-1" aria-hidden="true" />
          </Button>
        </div>
      </div>
      <div className="capture-tabs" role="tablist" aria-label="This capture">
        {tabs.map(t => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={`capture-tab${tab === t.id ? ' active' : ''}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
            {t.count !== undefined && <span className="capture-tab-count">{t.count.toLocaleString()}</span>}
          </button>
        ))}
      </div>
      <div className="capture-body" role="tabpanel">
        {tab === 'map' && (
          <NetworkDiagramView
            fileId={snapshot.fileId}
            networkId={networkId}
            networkDiagramFilters={filters}
            showTitle={false}
            monitor={{ highlights, ghostNodes, belowGraph }}
          />
        )}
        {tab === 'changes' &&
          (changes.length ? (
            <ChangeList events={changes} snapshots={snapshots} onPatch={onPatchChange} pageSize={12} />
          ) : (
            <p className="text-muted mb-0">
              {previous ? 'Nothing changed since the capture before.' : 'The baseline: later captures are compared with it.'}
            </p>
          ))}
        {tab === 'security' && <SnapshotSecurityPane networkId={networkId} fileId={snapshot.fileId} />}
        {tab === 'subnets' && (
          <SnapshotSubnetsTab key={snapshot.id} networkId={networkId} snapshot={snapshot} onSnapshotUpdated={onSnapshotUpdated} />
        )}
        {tab === 'context' && (
          <SnapshotContextTab key={snapshot.id} networkId={networkId} snapshot={snapshot} onSnapshotUpdated={onSnapshotUpdated} />
        )}
        {tab === 'insights' && <SnapshotInsightsTab networkId={networkId} snapshotId={snapshot.id} />}
      </div>
    </Card>
  );
}
