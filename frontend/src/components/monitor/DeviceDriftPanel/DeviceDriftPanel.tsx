import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect, type CSSProperties } from 'react';
import { Badge, Button, Modal } from '@govtechsg/sgds-react';
import { apiClient } from '@/services/api/client';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { parseDateTime } from '@/utils/dateUtils';
import { buildDeviceSignals, confidenceLevel } from '@/utils/deviceType';

/** Deterministic hue (0–360) from any string. */
function stringHue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffffffff;
  return Math.abs(h) % 360;
}

/** Muted badge style derived from string — works in light and dark mode. */
function hashBadgeStyle(s: string): CSSProperties {
  const hue = stringHue(s);
  return {
    background: `hsl(${hue}, 40%, 88%)`,
    color: `hsl(${hue}, 50%, 28%)`,
    border: `1px solid hsl(${hue}, 35%, 72%)`,
  };
}

interface DeviceDriftPanelProps {
  snapshots: NetworkSnapshot[];
}

interface HostClassification {
  mac: string | null;
  ip: string | null;
  manufacturer: string | null;
  deviceType: string | null;
  confidence: number | null;
  ttl: number | null;
}

interface ConversationSummary {
  appName: string | null;
  tsharkProtocol: string | null;
}

interface ConversationsResponse {
  data: ConversationSummary[];
}

interface DeviceSnapshotEntry {
  snap: NetworkSnapshot;
  host: HostClassification;
  apps: string[];
  protocols: string[];
}

function formatSnapTime(snap: NetworkSnapshot): string {
  if (!snap.startTime) return snap.fileName;
  const ms = parseDateTime(snap.startTime as unknown as string | number[]);
  return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

export const DeviceDriftPanel = ({ snapshots }: DeviceDriftPanelProps) => {
  const [selectedMac, setSelectedMac] = useState<string | null>(null);
  const [macHistory, setMacHistory] = useState<Map<string, DeviceSnapshotEntry[]>>(new Map());
  const [latestMacs, setLatestMacs] = useState<Set<string>>(new Set());
  const [macLastSeen, setMacLastSeen] = useState<Map<string, NetworkSnapshot>>(new Map());
  const [loading, setLoading] = useState(false);
  const [modalLoading, setModalLoading] = useState(false);
  const [historyPage, setHistoryPage] = useState(0);
  const HISTORY_PAGE_SIZE = 5;

  useEffect(() => {
    if (!selectedMac) return;
    const totalPages = Math.ceil((macHistory.get(selectedMac)?.length ?? 0) / HISTORY_PAGE_SIZE);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowLeft') { e.preventDefault(); setHistoryPage(p => Math.max(0, p - 1)); }
      else if (e.key === 'ArrowRight') { e.preventDefault(); setHistoryPage(p => Math.min(totalPages - 1, p + 1)); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [selectedMac, macHistory, HISTORY_PAGE_SIZE]);

  const sorted = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);

  // Load host classifications for all snapshots
  useEffect(() => {
    if (sorted.length === 0) return;
    setLoading(true);
    Promise.all(
      sorted.map(snap =>
        apiClient
          .get<HostClassification[]>(`/files/${snap.fileId}/host-classifications`)
          .then(r => ({ snap, hosts: r.data.filter(h => h.mac) }))
          .catch(() => ({ snap, hosts: [] as HostClassification[] }))
      )
    ).then(results => {
      const history = new Map<string, DeviceSnapshotEntry[]>();
      const lastSeen = new Map<string, NetworkSnapshot>();

      for (const { snap, hosts } of results) {
        for (const host of hosts) {
          const mac = host.mac!;
          if (!history.has(mac)) history.set(mac, []);
          history.get(mac)!.push({ snap, host, apps: [], protocols: [] });
          lastSeen.set(mac, snap);
        }
      }

      setMacHistory(history);
      setMacLastSeen(lastSeen);
      const latest = results[results.length - 1];
      setLatestMacs(new Set(latest?.hosts.map(h => h.mac!).filter(Boolean) ?? []));
      setLoading(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshots.map(s => s.id).join(',')]);

  // When a MAC is selected, fetch conversations for each snapshot entry to get protocols/apps
  const openModal = (mac: string) => {
    setSelectedMac(mac);
    setHistoryPage(0);
    const entries = macHistory.get(mac) ?? [];
    if (entries.every(e => e.apps.length > 0 || e.protocols.length > 0)) return; // already loaded
    setModalLoading(true);
    Promise.all(
      entries.map(entry =>
        entry.host.ip
          ? apiClient
              .get<ConversationsResponse>(`/conversations/${entry.snap.fileId}?ip=${entry.host.ip}&pageSize=10000`)
              .then(r => {
                const convs = r.data.data;
                return {
                  ...entry,
                  apps: [...new Set(convs.map(c => c.appName).filter(Boolean) as string[])].sort(),
                  protocols: [...new Set(convs.map(c => c.tsharkProtocol).filter(Boolean) as string[])].sort(),
                };
              })
              .catch(() => entry)
          : Promise.resolve(entry)
      )
    ).then(enriched => {
      setMacHistory(prev => {
        const next = new Map(prev);
        next.set(mac, enriched);
        return next;
      });
      setModalLoading(false);
    });
  };

  const active = Array.from(latestMacs);
  const absent: string[] = [];
  for (const [mac] of macLastSeen.entries()) {
    if (!latestMacs.has(mac)) absent.push(mac);
  }

  if (loading) {
    return <div className="text-muted small text-center py-3"><Spinner animation="border" size="sm" className="me-2" />Loading…</div>;
  }

  const total = active.length + absent.length;
  if (total === 0) {
    return <div className="text-muted small text-center py-3">No devices found. Add at least one snapshot.</div>;
  }

  const selectedHistory = selectedMac ? (macHistory.get(selectedMac) ?? []) : [];
  const isActive = selectedMac ? latestMacs.has(selectedMac) : false;

  return (
    <>
      <div className="d-flex flex-wrap gap-2">
        {active.map(mac => (
          <Button
            key={mac}
            type="button"
            variant="secondary"
            size="sm"
            className="border-0 py-0 px-1"
            style={{ fontSize: '0.75em', ...hashBadgeStyle(mac) }}
            onClick={() => openModal(mac)}
            title="View device history"
          >
            {mac}
          </Button>
        ))}
        {absent.map(mac => (
          <Button
            key={mac}
            type="button"
            variant="secondary"
            size="sm"
            className="text-decoration-line-through border-0 py-0 px-1"
            style={{ fontSize: '0.75em', opacity: 0.5, ...hashBadgeStyle(mac) }}
            onClick={() => openModal(mac)}
            title="View device history"
          >
            {mac}
          </Button>
        ))}
      </div>
      {absent.length > 0 && (
        <small className="text-muted d-block mt-2">
          <i className="bi bi-info-circle me-1"></i>
          Greyed-out devices are no longer seen. Click any device for history.
        </small>
      )}

      <Modal show={!!selectedMac} onHide={() => setSelectedMac(null)} centered size="lg">
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="bi bi-device-hdd me-2"></i>
            {selectedMac}
            {' '}
            <Badge bg={isActive ? 'success' : 'secondary'} className="ms-2">
              {isActive ? 'Active' : 'Gone'}
            </Badge>
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedHistory.length === 0 ? (
            <p className="text-muted">No history available.</p>
          ) : (
            <>
              {/* Summary row from latest entry */}
              {(() => {
                const latest = selectedHistory[selectedHistory.length - 1].host;
                const signals = buildDeviceSignals({
                  manufacturer: latest.manufacturer ?? undefined,
                  ttl: latest.ttl ?? undefined,
                  confidence: latest.confidence ?? 0,
                });
                const level = latest.confidence != null ? confidenceLevel(latest.confidence) : null;
                return (
                  <div className="mb-3">
                    <div className="d-flex gap-4 flex-wrap mb-2">
                      {latest.manufacturer && (
                        <div>
                          <small className="text-muted d-block">Manufacturer</small>
                          <strong>{latest.manufacturer}</strong>
                        </div>
                      )}
                      {latest.deviceType && (
                        <div>
                          <small className="text-muted d-block">Device Type</small>
                          <strong>{latest.deviceType}</strong>
                        </div>
                      )}
                      {latest.ttl != null && (
                        <div>
                          <small className="text-muted d-block">TTL</small>
                          <strong>{latest.ttl}</strong>
                        </div>
                      )}
                      {latest.confidence != null && (
                        <div>
                          <small className="text-muted d-block">Confidence</small>
                          <strong>{latest.confidence}% {level && <span className="text-muted fw-normal">— {level}</span>}</strong>
                        </div>
                      )}
                    </div>
                    {signals.length > 0 && (
                      <div className="border rounded p-2" style={{ background: 'var(--tp-bg-subtle)' }}>
                        <small className="text-muted fw-semibold d-block mb-1">
                          <i className="bi bi-info-circle me-1"></i>How this is derived
                        </small>
                        <ul className="mb-0 ps-3" style={{ fontSize: '0.78rem' }}>
                          {signals.map((s, i) => <li key={i} className="text-muted">{s}</li>)}
                        </ul>
                      </div>
                    )}
                  </div>
                );
              })()}
              <h6 className="text-muted fw-semibold mb-2">Snapshot History</h6>
              {modalLoading ? (
                <div className="text-muted small text-center py-2">
                  <Spinner animation="border" size="sm" className="me-2" />Loading protocols & apps…
                </div>
              ) : (() => {
                const totalPages = Math.ceil(selectedHistory.length / HISTORY_PAGE_SIZE);
                const pageRows = selectedHistory.slice(
                  historyPage * HISTORY_PAGE_SIZE,
                  (historyPage + 1) * HISTORY_PAGE_SIZE,
                );
                return (
                  <>
                    <table className="table table-sm table-hover mb-0">
                      <thead>
                        <tr>
                          <th className="text-muted fw-normal">#</th>
                          <th className="text-muted fw-normal">Snapshot</th>
                          <th className="text-muted fw-normal">IP Address</th>
                          <th className="text-muted fw-normal">Device Type</th>
                          <th className="text-muted fw-normal">Protocols / Apps</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pageRows.map(({ snap, host, protocols, apps }, pageIdx) => {
                          const globalIdx = historyPage * HISTORY_PAGE_SIZE + pageIdx;
                          return (
                            <tr key={`${snap.id}-${globalIdx}`}>
                              <td><small className="text-muted">{snap.snapshotOrder + 1}</small></td>
                              <td>
                                <small className="text-muted d-block">{formatSnapTime(snap)}</small>
                                <small className="text-muted text-break" style={{ fontSize: '0.7rem' }}>{snap.fileName}</small>
                              </td>
                              <td>
                                <code>{host.ip ?? '—'}</code>
                                {globalIdx > 0 && host.ip !== selectedHistory[globalIdx - 1].host.ip && (
                                  <Badge bg="warning" text="dark" className="ms-1" style={{ fontSize: '0.65rem' }}>changed</Badge>
                                )}
                              </td>
                              <td><small className="text-muted">{host.deviceType ?? '—'}</small></td>
                              <td>
                                {protocols.length === 0 && apps.length === 0 ? (
                                  <small className="text-muted">—</small>
                                ) : (
                                  <div className="d-flex flex-wrap gap-1">
                                    {protocols.map(p => (
                                      <Badge key={p} style={{ fontSize: '0.65rem', fontWeight: 400, ...hashBadgeStyle(p) }}>{p}</Badge>
                                    ))}
                                    {apps.map(a => (
                                      <Badge key={a} style={{ fontSize: '0.65rem', fontWeight: 400, ...hashBadgeStyle(a) }}>{a}</Badge>
                                    ))}
                                  </div>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    {totalPages > 1 && (
                      <div className="d-flex align-items-center justify-content-between mt-2">
                        <small className="text-muted">
                          {historyPage * HISTORY_PAGE_SIZE + 1}–{Math.min((historyPage + 1) * HISTORY_PAGE_SIZE, selectedHistory.length)} of {selectedHistory.length}
                        </small>
                        <div className="d-flex gap-1">
                          <Button
                            size="sm"
                            variant="outline-secondary"
                            disabled={historyPage === 0}
                            onClick={() => setHistoryPage(p => p - 1)}
                          >
                            <i className="bi bi-chevron-left" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline-secondary"
                            disabled={historyPage >= totalPages - 1}
                            onClick={() => setHistoryPage(p => p + 1)}
                          >
                            <i className="bi bi-chevron-right" />
                          </Button>
                        </div>
                      </div>
                    )}
                  </>
                );
              })()}
            </>
          )}
        </Modal.Body>
      </Modal>
    </>
  );
};
