import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect, type CSSProperties } from 'react';
import { Badge, Button, Modal } from '@govtechsg/sgds-react';
import { apiClient } from '@/services/api/client';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { parseDateTime } from '@/utils/dateUtils';
import { buildDeviceSignals, confidenceLevel, type DeviceSignalInfo } from '@/utils/deviceType';
import { entityNotesService, type EntityNote } from '@/features/notes/services/entityNotesService';
import { insightsService } from '@/features/insights/services/insightsService';
import type { NodeRole } from '@/features/insights/types/insights.types';
import { staleTooltip } from '@/features/insights/utils/nodeRoleStaleness';
import { RoleEditModal } from '@components/common/RoleEditModal';

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
    '--badge-hue': hue,
    background: `hsl(${hue}, 40%, 88%)`,
    color: `hsl(${hue}, 50%, 28%)`,
    border: `1px solid hsl(${hue}, 35%, 72%)`,
  } as CSSProperties;
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
  roleLabel?: string | null;
  roleOrigin?: string | null;
  roleStale?: boolean;
}

function formatSnapTime(snap: NetworkSnapshot): string {
  if (!snap.startTime) return snap.fileName;
  const ms = parseDateTime(snap.startTime as unknown as string | number[]);
  return new Date(ms).toLocaleDateString('en-GB', { month: 'short', day: 'numeric', year: 'numeric' });
}

export const DeviceDriftPanel = ({ snapshots }: DeviceDriftPanelProps) => {
  const [selectedMac, setSelectedMac] = useState<string | null>(null);
  const [macHistory, setMacHistory] = useState<Map<string, DeviceSnapshotEntry[]>>(new Map());
  const [latestMacs, setLatestMacs] = useState<Set<string>>(new Set());
  const [macLastSeen, setMacLastSeen] = useState<Map<string, NetworkSnapshot>>(new Map());
  const [loading, setLoading] = useState(false);
  const [modalLoading, setModalLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [historyPage, setHistoryPage] = useState(0);
  const HISTORY_PAGE_SIZE = 5;

  // Notes state
  const [noteText, setNoteText] = useState('');
  const [savedNote, setSavedNote] = useState<EntityNote | null>(null);
  const [noteSaving, setNoteSaving] = useState(false);
  const [modalTab, setModalTab] = useState<'details' | 'notes'>('details');

  // Role state — present-day summary; per-snapshot editing is done via RoleEditModal.
  const [role, setRole] = useState<NodeRole | null>(null);
  const [editingRole, setEditingRole] = useState<{ fileId: string; name: string } | null>(null);

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
    setModalTab('details');
    setNoteText('');
    setSavedNote(null);
    setRole(null);
    setEditingRole(null);
    entityNotesService.getNote('DEVICE', mac).then(note => {
      if (note) { setSavedNote(note); setNoteText(note.note); }
    });
    const entries = macHistory.get(mac) ?? [];
    // Present-day role = the latest snapshot in which this device appears.
    const latestFid = entries[entries.length - 1]?.snap.fileId;
    if (latestFid) {
      insightsService.getNodeRole('DEVICE', mac, latestFid).then(r => setRole(r ?? null)).catch(() => {});
    }
    if (entries.every(e => e.apps.length > 0 || e.protocols.length > 0)) return; // already loaded
    setModalLoading(true);
    Promise.all(
      entries.map(entry =>
        Promise.all([
          entry.host.ip
            ? apiClient
                .get<ConversationsResponse>(`/conversations/${entry.snap.fileId}?ip=${entry.host.ip}&pageSize=10000`)
                .then(r => ({
                  apps: [...new Set((r?.data?.data ?? []).map(c => c.appName).filter(Boolean) as string[])].sort(),
                  protocols: [...new Set((r?.data?.data ?? []).map(c => c.tsharkProtocol).filter(Boolean) as string[])].sort(),
                }))
                .catch(() => ({ apps: entry.apps, protocols: entry.protocols }))
            : Promise.resolve({ apps: entry.apps, protocols: entry.protocols }),
          insightsService.getNodeRole('DEVICE', mac, entry.snap.fileId).catch(() => null),
        ]).then(([conv, role]) => ({
          ...entry,
          ...conv,
          roleLabel: role?.roleLabel ?? null,
          roleOrigin: role?.origin ?? null,
          roleStale: !!role?.staleSince,
        }))
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

  // Refetch the present-day role + per-snapshot roles after an edit in the history table.
  const reloadDeviceRoles = async (mac: string) => {
    const entries = macHistory.get(mac) ?? [];
    const latestFid = entries[entries.length - 1]?.snap.fileId;
    if (latestFid) {
      insightsService.getNodeRole('DEVICE', mac, latestFid).then(r => setRole(r ?? null)).catch(() => {});
    }
    const updated = await Promise.all(
      entries.map(async e => {
        const r = await insightsService.getNodeRole('DEVICE', mac, e.snap.fileId).catch(() => null);
        return { ...e, roleLabel: r?.roleLabel ?? null, roleOrigin: r?.origin ?? null, roleStale: !!r?.staleSince };
      }),
    );
    setMacHistory(prev => { const next = new Map(prev); next.set(mac, updated); return next; });
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

  const q = search.trim().toLowerCase();
  const visibleActive = q ? active.filter(mac => mac.toLowerCase().includes(q)) : active;
  const visibleAbsent = q ? absent.filter(mac => mac.toLowerCase().includes(q)) : absent;

  return (
    <>
      <div className="mb-3">
        <input
          type="search"
          className="form-control form-control-sm"
          placeholder="Search MAC addresses…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>
      <div className="d-flex flex-wrap gap-2">
        {visibleActive.map(mac => (
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
        {visibleAbsent.map(mac => (
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
        <Modal.Header closeButton className="flex-column align-items-start pb-1">
          <Modal.Title className="d-flex align-items-center gap-2 flex-wrap">
            <i className="bi bi-device-hdd me-1"></i>
            <span className="font-monospace">{selectedMac}</span>
            {(() => {
              if (isActive) return <Badge bg="success" style={{ fontSize: '0.7rem' }}>Active</Badge>;
              const lastSnap = selectedMac ? macLastSeen.get(selectedMac) : null;
              const lastTime = lastSnap?.startTime ? parseDateTime(lastSnap.startTime as unknown as string | number[]) : null;
              const days = lastTime ? Math.floor((Date.now() - lastTime) / 86400000) : null;
              return <Badge bg="secondary" style={{ fontSize: '0.7rem' }}>Inactive{days != null && days > 0 ? ` · ${days}d ago` : ''}</Badge>;
            })()}
          </Modal.Title>
          <ul className="nav nav-pills gap-1 mt-2" style={{ paddingTop: '2px', paddingBottom: '2px' }}>
            <li className="nav-item">
              <button
                className={`nav-link py-1 px-3${modalTab === 'details' ? ' active' : ''}`}
                style={{ fontSize: '0.875rem' }}
                onClick={() => setModalTab('details')}
              >
                <i className="bi bi-info-circle me-1" />Details
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link py-1 px-3${modalTab === 'notes' ? ' active' : ''}`}
                style={{ fontSize: '0.875rem' }}
                onClick={() => setModalTab('notes')}
              >
                <i className="bi bi-sticky me-1" />
                Notes
                {savedNote && <span className="badge bg-warning text-dark ms-1" style={{ fontSize: '0.6rem' }}>1</span>}
              </button>
            </li>
          </ul>
        </Modal.Header>
        <Modal.Body>
          {modalTab === 'notes' && (
            <div>
              <p className="text-muted small mb-2">Notes are saved globally for this device and persist across all captures.</p>
              <textarea
                className="form-control mb-2"
                rows={6}
                style={{ fontSize: '0.875rem' }}
                placeholder={`Add notes about ${selectedMac}…`}
                value={noteText}
                onChange={e => setNoteText(e.target.value)}
              />
              {savedNote && (
                <p className="text-muted" style={{ fontSize: '0.7rem' }}>
                  Last updated: {new Date(savedNote.updatedAt).toLocaleString('en-GB')}
                </p>
              )}
              <div className="d-flex gap-2">
                <Button
                  size="sm"
                  variant="primary"
                  disabled={noteSaving || noteText === (savedNote?.note ?? '')}
                  onClick={async () => {
                    setNoteSaving(true);
                    try {
                      const updated = await entityNotesService.upsertNote('DEVICE', selectedMac!, noteText);
                      setSavedNote(updated);
                    } finally { setNoteSaving(false); }
                  }}
                >
                  {noteSaving ? <span className="spinner-border spinner-border-sm me-1" /> : <i className="bi bi-floppy me-1" />}
                  Save Note
                </Button>
                {savedNote && (
                  <Button
                    size="sm"
                    variant="outline-danger"
                    onClick={async () => {
                      await entityNotesService.deleteNote('DEVICE', selectedMac!);
                      setSavedNote(null);
                      setNoteText('');
                    }}
                  >
                    <i className="bi bi-trash me-1" />Delete
                  </Button>
                )}
              </div>
            </div>
          )}
          {modalTab === 'details' && selectedHistory.length === 0 ? (
            <p className="text-muted">No history available.</p>
          ) : modalTab === 'details' && (
            <>
              {/* Role section — read-only present-day summary; edit per snapshot in the history table below */}
              <div className="mb-4">
                <h6 className="border-bottom pb-1 mb-2">Role <span className="text-muted fw-normal" style={{ fontSize: '0.75rem' }}>· present-day (latest snapshot)</span></h6>
                {!role && <p className="text-muted small fst-italic mb-0">No role assigned. Set one per snapshot in the history below.</p>}
                {role && (
                  <div className={`p-2 rounded small ${role.confirmedByHuman && role.staleSince ? 'bg-warning-subtle border border-warning' : 'bg-light'}`}>
                    <div className="fw-semibold">
                      {role.roleLabel || <span className="text-muted fst-italic">No label</span>}
                      {role.llmSuggested && !role.confirmedByHuman && <span className="badge bg-warning text-dark ms-2" style={{ fontSize: '0.65rem' }}><i className="bi bi-stars me-1" />AI suggested</span>}
                      {role.confirmedByHuman && <span className="badge bg-secondary ms-2" style={{ fontSize: '0.65rem' }}><i className="bi bi-tag me-1" />Manual label</span>}
                      {role.confirmedByHuman && role.staleSince && <span className="badge bg-warning text-dark ms-2" style={{ fontSize: '0.65rem' }} title={staleTooltip(role)}><i className="bi bi-exclamation-triangle me-1" />Stale</span>}
                    </div>
                    {role.roleDescription && <div className="text-muted mt-1">{role.roleDescription}</div>}
                  </div>
                )}
              </div>

              {/* Summary row from latest entry */}
              {(() => {
                const latestEntry = selectedHistory[selectedHistory.length - 1];
                const latest = latestEntry.host;
                const signalInfo: DeviceSignalInfo = {
                  manufacturer: latest.manufacturer ?? undefined,
                  ttl: latest.ttl ?? undefined,
                  confidence: latest.confidence ?? 0,
                  deviceType: latest.deviceType ?? undefined,
                  apps: latestEntry.apps,
                };
                const { fired, missing } = buildDeviceSignals(signalInfo);
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
                          <strong>{latest.confidence}%{level && <span className="text-muted fw-normal"> — {level}</span>}</strong>
                        </div>
                      )}
                    </div>
                    {fired.length > 0 && (
                      <div className="border rounded p-2 mb-2" style={{ background: 'var(--tp-bg-subtle)' }}>
                        <small className="text-muted fw-semibold d-block mb-1">
                          <i className="bi bi-bar-chart-steps me-1"></i>How this is derived
                        </small>
                        <ul className="mb-0 ps-3" style={{ fontSize: '0.78rem' }}>
                          {fired.map((s, i) => <li key={i} className="text-muted">{s}</li>)}
                        </ul>
                        <small className="text-muted d-block mt-2" style={{ fontSize: '0.72rem' }}>
                          Weights add to each type's score. Confidence = how far ahead the winner is over the runner-up (a 60-point lead = 100%).
                        </small>
                      </div>
                    )}
                    {missing.length > 0 && (
                      <div className="border rounded p-2" style={{ background: 'var(--bs-warning-bg-subtle, #fff3cd)', borderColor: 'var(--bs-warning-border-subtle, #ffc107)' }}>
                        <small className="fw-semibold d-block mb-1" style={{ color: 'var(--bs-warning-text-emphasis, #664d03)' }}>
                          <i className="bi bi-lightbulb me-1"></i>What would improve confidence
                        </small>
                        <ul className="mb-0 ps-3" style={{ fontSize: '0.78rem', color: 'var(--bs-warning-text-emphasis, #664d03)' }}>
                          {missing.map((s, i) => <li key={i}>{s}</li>)}
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
                    <div className="table-responsive rounded border overflow-hidden">
                    <table className="table table-sm table-hover mb-0">
                      <thead className="table-light" style={{ fontSize: '0.8rem' }}>
                        <tr>
                          <th className="text-muted fw-normal">#</th>
                          <th className="text-muted fw-normal">Snapshot</th>
                          <th className="text-muted fw-normal">IP Address</th>
                          <th className="text-muted fw-normal">Device Type</th>
                          <th className="text-muted fw-normal">Role</th>
                          <th className="text-muted fw-normal">Protocols / Apps</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pageRows.map(({ snap, host, protocols, apps, roleLabel, roleOrigin, roleStale }, pageIdx) => {
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
                                <div className="d-inline-flex align-items-center gap-1">
                                  {roleLabel ? <small>{roleLabel}</small> : <small className="text-muted">—</small>}
                                  {roleLabel && roleOrigin === 'CARRIED_FORWARD' && (
                                    <Badge bg="light" text="secondary" className="border" style={{ fontSize: '0.55rem', fontWeight: 400 }} title="Inherited from an earlier snapshot (carried forward), not set here">carried</Badge>
                                  )}
                                  {roleStale && (
                                    <Badge bg="warning" text="dark" style={{ fontSize: '0.6rem' }} title="Label flagged stale in this snapshot">
                                      <i className="bi bi-exclamation-triangle" />
                                    </Badge>
                                  )}
                                  <button className="btn btn-link btn-sm p-0 ms-1 text-muted" style={{ fontSize: '0.75rem', lineHeight: 1 }} title="Edit role for this snapshot" onClick={() => setEditingRole({ fileId: snap.fileId, name: snap.fileName })}>
                                    <i className="bi bi-pencil" />
                                  </button>
                                </div>
                              </td>
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
                    </div>
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

      {editingRole && selectedMac && (
        <RoleEditModal
          entityType="DEVICE"
          entityKey={selectedMac}
          fileId={editingRole.fileId}
          snapshotName={editingRole.name}
          onClose={() => setEditingRole(null)}
          onSaved={() => reloadDeviceRoles(selectedMac)}
        />
      )}
    </>
  );
};
