import { useMemo, useState } from 'react';
import { Button, Card, Modal } from '@govtechsg/sgds-react';
import type { GraphEdge, GraphNode } from '@/features/network/types';
import { VolumeHeatmap, type VolumePair } from '@components/network/VolumeHeatmap';
import { formatBytes } from '@/utils/formatters';
import './TrafficCard.css';

type View = 'pairs' | 'matrix' | null;
const VIEW_KEY = 'tracepcap.trafficCard.view';
const PAIRS_SHOWN = 8;

function readView(): View {
  try {
    const v = localStorage.getItem(VIEW_KEY);
    return v === 'pairs' || v === 'matrix' ? v : null;
  } catch {
    return null;
  }
}

export interface BusyPair {
  source: string;
  target: string;
  bytes: number;
  packets: number;
  apps: string[];
}

/** Traffic between each pair of hosts, both directions together, busiest first. */
export function busiestPairs(edges: GraphEdge[], limit = PAIRS_SHOWN): BusyPair[] {
  const byPair = new Map<string, BusyPair & { appSet: Set<string> }>();
  for (const e of edges) {
    const [a, b] = e.source < e.target ? [e.source, e.target] : [e.target, e.source];
    const key = `${a}|${b}`;
    const p = byPair.get(key) ?? {
      source: a,
      target: b,
      bytes: 0,
      packets: 0,
      apps: [],
      appSet: new Set<string>(),
    };
    p.bytes += e.data.totalBytes;
    p.packets += e.data.packetCount;
    p.appSet.add(e.data.appName ?? e.data.protocol);
    byPair.set(key, p);
  }
  return [...byPair.values()]
    .sort((x, y) => y.bytes - x.bytes)
    .slice(0, limit)
    .map(({ appSet, ...p }) => ({ ...p, apps: [...appSet] }));
}

interface Props {
  totals: { nodes: number; edges: number; packets: number; bytes: number };
  shown: { nodes: number; edges: number };
  /** The hosts and connections the diagram is drawing (after filters). */
  nodes: GraphNode[];
  edges: GraphEdge[];
  dark: boolean;
  focusedHost: string | null;
  selectedPair: VolumePair | null;
  onSelectPair: (p: VolumePair | null) => void;
  onHostClick: (n: GraphNode) => void;
}

/**
 * Traffic (design B): the diagram's totals, always in view, with the busiest pairs and the
 * node-to-node matrix as tabs. Collapsed by default; the open tab is remembered.
 */
export function TrafficCard({
  totals,
  shown,
  nodes,
  edges,
  dark,
  focusedHost,
  selectedPair,
  onSelectPair,
  onHostClick,
}: Props) {
  const [view, setView] = useState<View>(readView);
  const [fullscreen, setFullscreen] = useState(false);
  const pick = (v: View) => {
    const next = view === v ? null : v;
    setView(next);
    try {
      if (next) localStorage.setItem(VIEW_KEY, next);
      else localStorage.removeItem(VIEW_KEY);
    } catch {
      // Not remembered: the card still works.
    }
  };

  const labels = useMemo(
    () => new Map(nodes.map(n => [n.id, n.data.hostname || n.data.ip])),
    [nodes]
  );
  const pairs = useMemo(() => busiestPairs(edges), [edges]);
  const max = pairs[0]?.bytes || 1;
  const filtered = shown.nodes !== totals.nodes || shown.edges !== totals.edges;

  const heatmap = (
    <VolumeHeatmap
      nodes={nodes}
      edges={edges}
      dark={dark}
      focusedHost={focusedHost}
      selectedPair={selectedPair}
      onCellClick={onSelectPair}
      onHostClick={onHostClick}
    />
  );

  return (
    <Card className="mb-3 traffic-card">
      <Card.Body className="pb-0">
        <h2 className="traffic-title">Traffic</h2>
        <div className="traffic-totals">
          <div>
            <b>{totals.nodes.toLocaleString()}</b> hosts
          </div>
          <div>
            <b>{totals.edges.toLocaleString()}</b> connections
          </div>
          <div>
            <b>{totals.packets.toLocaleString()}</b> packets
          </div>
          <div>
            <b>{formatBytes(totals.bytes)}</b> in total
          </div>
          <span className="traffic-shown">
            {filtered
              ? `${shown.nodes} hosts · ${shown.edges} connections shown (filtered)`
              : `All ${shown.nodes} shown`}
          </span>
        </div>
        <div className="traffic-tabs" role="tablist" aria-label="Traffic views">
          {(['pairs', 'matrix'] as const).map(v => (
            <button
              key={v}
              type="button"
              role="tab"
              aria-selected={view === v}
              aria-expanded={view === v}
              className={`traffic-tab${view === v ? ' active' : ''}`}
              onClick={() => pick(v)}
            >
              {v === 'pairs' ? 'Busiest pairs' : 'Matrix'}
            </button>
          ))}
          {view === 'matrix' && (
            <Button
              variant="link"
              size="sm"
              className="ms-auto text-muted"
              onClick={() => setFullscreen(true)}
              aria-label="Show the matrix full screen"
            >
              <i className="bi bi-fullscreen" aria-hidden="true" />
            </Button>
          )}
        </div>
      </Card.Body>

      {view === 'pairs' && (
        <div className="traffic-panel" role="tabpanel">
          {pairs.length === 0 ? (
            <p className="text-muted small mb-0">No connections shown.</p>
          ) : (
            <ol className="traffic-pairs">
              {pairs.map(p => {
                const on = selectedPair?.source === p.source && selectedPair?.target === p.target;
                return (
                  <li key={`${p.source}|${p.target}`}>
                    <button
                      type="button"
                      className={`traffic-pair${on ? ' active' : ''}`}
                      aria-pressed={on}
                      onClick={() =>
                        onSelectPair(on ? null : { source: p.source, target: p.target })
                      }
                    >
                      <span className="traffic-pair-hosts">
                        {labels.get(p.source) ?? p.source} ↔ {labels.get(p.target) ?? p.target}
                      </span>
                      <span className="traffic-pair-apps">{p.apps.join(', ')}</span>
                      <span className="traffic-bar" aria-hidden="true">
                        <span style={{ width: `${Math.max(2, (p.bytes / max) * 100)}%` }} />
                      </span>
                      <span className="traffic-pair-bytes">{formatBytes(p.bytes)}</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          )}
          <p className="small text-muted mt-2 mb-0">Click a pair to highlight it in the diagram.</p>
        </div>
      )}

      {view === 'matrix' && !fullscreen && (
        <div className="traffic-panel tp-heatmap-body" role="tabpanel">
          {heatmap}
        </div>
      )}

      {fullscreen && (
        <Modal show onHide={() => setFullscreen(false)} fullscreen>
          <Modal.Header closeButton>
            <Modal.Title>Traffic between each pair of hosts</Modal.Title>
          </Modal.Header>
          <Modal.Body className="tp-heatmap-body">{heatmap}</Modal.Body>
        </Modal>
      )}
    </Card>
  );
}
