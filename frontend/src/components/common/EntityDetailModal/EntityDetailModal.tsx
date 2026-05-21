import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '@/services/api/client';
import {
  entityNotesService,
  type EntityNote,
  type EntityHistoryEntry,
  type EntityType,
} from '@/features/notes/services/entityNotesService';
import { insightsService } from '@/features/insights/services/insightsService';
import type { NodeRole } from '@/features/insights/types/insights.types';
import { buildDeviceSignals, confidenceLevel, type DeviceSignalInfo } from '@/utils/deviceType';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { parseDateTime } from '@/utils/dateUtils';
import { Badge } from '@govtechsg/sgds-react';

type Tab = 'details' | 'notes';

interface HostClassification {
  ip: string | null;
  mac: string | null;
  manufacturer: string | null;
  deviceType: string | null;
  confidence: number | null;
  ttl: number | null;
}

interface IpSnapshotEntry {
  snap: NetworkSnapshot;
  host: HostClassification | null;
  apps: string[];
  protocols: string[];
}

interface EntityDetailModalProps {
  entityType: EntityType;
  entityKey: string;
  /** Display label (may differ from key) */
  displayName: string;
  /** Current file ID — used to fetch stats and mark history rows */
  fileId: string;
  /** Badge element rendered in the modal header */
  badge?: React.ReactNode;
  /** Whether the entity was seen in the most recent snapshot (Monitor context) */
  isActive?: boolean;
  /** ISO timestamp of last seen time — used to compute "inactive X days ago" */
  lastSeenTime?: string | null;
  /** Called when "View conversations" is clicked */
  onViewConversations?: () => void;
  /** Monitor snapshots — when provided for IP type, shows per-snapshot MAC/device history */
  snapshots?: NetworkSnapshot[];
  onClose: () => void;
  zIndex?: number;
}

interface ConvRow {
  srcIp: string;
  dstIp: string;
  packetCount: number;
  totalBytes: number;
}

interface ConvApiResponse {
  data: ConvRow[];
  total: number;
}

interface EntityStats {
  conversationCount: number;
  packetCount: number;
  totalBytes: number;
  /** Distinct peer IPs (for APPLICATION/PROTOCOL only) */
  topPeers: { ip: string; bytes: number }[];
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

function formatNumber(num: number): string {
  return num.toLocaleString();
}

export function EntityDetailModal({
  entityType,
  entityKey,
  displayName,
  fileId,
  badge,
  isActive,
  lastSeenTime,
  onViewConversations,
  snapshots,
  onClose,
  zIndex,
}: EntityDetailModalProps) {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<Tab>('details');
  const [nestedIp, setNestedIp] = useState<string | null>(null);

  // Details state
  const [stats, setStats] = useState<EntityStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(false);
  const [statsError, setStatsError] = useState<string | null>(null);

  // Notes state
  const [noteText, setNoteText] = useState('');
  const [savedNote, setSavedNote] = useState<EntityNote | null>(null);
  const [noteSaving, setNoteSaving] = useState(false);
  const [noteDeleting, setNoteDeleting] = useState(false);

  // Node role state (IP and DEVICE only)
  const showRole = entityType === 'IP' || entityType === 'DEVICE';
  const [role, setRole] = useState<NodeRole | null>(null);
  const [roleLoading, setRoleLoading] = useState(false);
  const [roleSuggesting, setRoleSuggesting] = useState(false);
  const [roleSuggestError, setRoleSuggestError] = useState<string | null>(null);
  const [roleInfoOpen, setRoleInfoOpen] = useState(false);
  const [roleEditing, setRoleEditing] = useState(false);
  const [roleLabelDraft, setRoleLabelDraft] = useState('');
  const [roleDescDraft, setRoleDescDraft] = useState('');
  const [roleSaving, setRoleSaving] = useState(false);

  // History state
  const [history, setHistory] = useState<EntityHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  // Host classification for IP type
  const [hostClass, setHostClass] = useState<HostClassification | null>(null);

  // Per-snapshot MAC/device history for IP type (when snapshots prop is provided)
  const [ipSnapHistory, setIpSnapHistory] = useState<IpSnapshotEntry[]>([]);
  const [ipHistoryLoading, setIpHistoryLoading] = useState(false);

  // ESC closes — but not if a nested IP modal is open (let the nested one handle it first)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !nestedIp) { e.stopImmediatePropagation(); onClose(); }
    };
    document.addEventListener('keydown', onKeyDown, { capture: true });
    return () => document.removeEventListener('keydown', onKeyDown, { capture: true });
  }, [onClose, nestedIp]);

  // Lock background scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, []);

  // Load node role on mount for IP/DEVICE
  useEffect(() => {
    if (!showRole) return;
    setRoleLoading(true);
    insightsService
      .getNodeRole(entityType, entityKey)
      .then(r => setRole(r))
      .finally(() => setRoleLoading(false));
  }, [showRole, entityType, entityKey]);

  // Fetch host classification for IP type
  useEffect(() => {
    if (entityType !== 'IP' || !fileId) return;
    apiClient
      .get<HostClassification[]>(`/files/${fileId}/host-classifications`)
      .then(r => {
        const match = r.data.find(h => h.ip === entityKey);
        setHostClass(match ?? null);
      })
      .catch(() => {});
  }, [entityType, entityKey, fileId]);

  // Load per-snapshot MAC/device history for IP type when snapshots are provided
  useEffect(() => {
    if (entityType !== 'IP' || !snapshots || snapshots.length === 0) return;
    setIpHistoryLoading(true);
    const sorted = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);
    Promise.all(
      sorted.map(snap =>
        apiClient
          .get<HostClassification[]>(`/files/${snap.fileId}/host-classifications`)
          .then(r => ({ snap, host: r.data.find(h => h.ip === entityKey) ?? null }))
          .catch(() => ({ snap, host: null }))
      )
    ).then(results => {
      // Only keep snapshots where this IP appeared
      const seen = results.filter(r => r.host !== null);
      if (seen.length === 0) { setIpSnapHistory([]); setIpHistoryLoading(false); return; }
      // Fetch conversations for protocols/apps per seen snapshot
      return Promise.all(
        seen.map(({ snap, host }) =>
          apiClient
            .get<{ data: { appName: string | null; tsharkProtocol: string | null }[] }>(
              `/conversations/${snap.fileId}?ip=${encodeURIComponent(entityKey)}&pageSize=10000`
            )
            .then(r => ({
              snap,
              host,
              apps: [...new Set(r.data.data.map(c => c.appName).filter(Boolean) as string[])].sort(),
              protocols: [...new Set(r.data.data.map(c => c.tsharkProtocol).filter(Boolean) as string[])].sort(),
            }))
            .catch(() => ({ snap, host, apps: [], protocols: [] }))
        )
      ).then(entries => { setIpSnapHistory(entries); setIpHistoryLoading(false); });
    }).catch(() => setIpHistoryLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityType, entityKey, snapshots?.map(s => s.id).join(',')]);

  // Fetch stats for the Details tab (only when fileId is present)
  useEffect(() => {
    if (!fileId || (entityType !== 'APPLICATION' && entityType !== 'PROTOCOL')) return;
    setStatsLoading(true);
    setStatsError(null);
    const param = entityType === 'APPLICATION' ? `apps=${encodeURIComponent(entityKey)}` : `l7Protocols=${encodeURIComponent(entityKey)}`;
    apiClient
      .get<ConvApiResponse>(`/conversations/${fileId}?${param}&pageSize=500&page=1`)
      .then(res => {
        const rows = res.data.data;
        const total = res.data.total;
        const packets = rows.reduce((s, r) => s + r.packetCount, 0);
        const bytes = rows.reduce((s, r) => s + r.totalBytes, 0);
        // Aggregate bytes per peer IP
        const peerBytes = new Map<string, number>();
        for (const r of rows) {
          peerBytes.set(r.srcIp, (peerBytes.get(r.srcIp) ?? 0) + r.totalBytes);
          peerBytes.set(r.dstIp, (peerBytes.get(r.dstIp) ?? 0) + r.totalBytes);
        }
        const topPeers = Array.from(peerBytes.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([ip, b]) => ({ ip, bytes: b }));
        setStats({ conversationCount: total, packetCount: packets, totalBytes: bytes, topPeers });
      })
      .catch(() => setStatsError('Failed to load details'))
      .finally(() => setStatsLoading(false));
  }, [fileId, entityType, entityKey]);

  // Load note on mount
  useEffect(() => {
    entityNotesService.getNote(entityType, entityKey).then(note => {
      if (note) { setSavedNote(note); setNoteText(note.note); }
    });
  }, [entityType, entityKey]);

  // Load history on mount
  useEffect(() => {
    if (history.length > 0 || historyLoading) return;
    setHistoryLoading(true);
    setHistoryError(null);
    entityNotesService
      .getHistory(entityType, entityKey)
      .then(entries => setHistory(entries))
      .catch(() => setHistoryError('Failed to load history'))
      .finally(() => setHistoryLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityType, entityKey]);

  const handleSuggestRole = async () => {
    if (!fileId) return;
    setRoleSuggesting(true);
    setRoleSuggestError(null);
    try {
      const suggested = await insightsService.suggestNodeRole(entityType, entityKey, fileId);
      setRole(suggested);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Suggestion failed.';
      setRoleSuggestError(msg);
    } finally {
      setRoleSuggesting(false);
    }
  };

  const handleAcceptRole = async () => {
    if (!role) return;
    setRoleSaving(true);
    try {
      const updated = await insightsService.upsertNodeRole(
        entityType,
        entityKey,
        role.roleLabel ?? '',
        role.roleDescription ?? '',
        true,
      );
      setRole(updated);
    } finally {
      setRoleSaving(false);
    }
  };

  const handleDiscardRole = async () => {
    setRoleSaving(true);
    try {
      await insightsService.deleteNodeRole(entityType, entityKey);
      setRole(null);
    } finally {
      setRoleSaving(false);
    }
  };

  const handleOpenEdit = () => {
    setRoleLabelDraft(role?.roleLabel ?? '');
    setRoleDescDraft(role?.roleDescription ?? '');
    setRoleEditing(true);
  };

  const handleSaveRole = async () => {
    setRoleSaving(true);
    try {
      const updated = await insightsService.upsertNodeRole(
        entityType,
        entityKey,
        roleLabelDraft,
        roleDescDraft,
        true,
      );
      setRole(updated);
      setRoleEditing(false);
    } finally {
      setRoleSaving(false);
    }
  };

  const handleSaveNote = async () => {
    setNoteSaving(true);
    try {
      const updated = await entityNotesService.upsertNote(entityType, entityKey, noteText);
      setSavedNote(updated);
    } finally { setNoteSaving(false); }
  };

  const handleDeleteNote = async () => {
    setNoteDeleting(true);
    try {
      await entityNotesService.deleteNote(entityType, entityKey);
      setSavedNote(null);
      setNoteText('');
    } finally { setNoteDeleting(false); }
  };

  const noteChanged = noteText !== (savedNote?.note ?? '');

  function formatSnapTime(snap: NetworkSnapshot): string {
    if (!snap.startTime) return snap.fileName;
    const ms = parseDateTime(snap.startTime as unknown as string | number[]);
    return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }

  function stringHue(s: string): number {
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffffffff;
    return Math.abs(h) % 360;
  }

  function hashBadgeStyle(s: string) {
    const hue = stringHue(s);
    return {
      background: `hsl(${hue}, 40%, 88%)`,
      color: `hsl(${hue}, 50%, 28%)`,
      border: `1px solid hsl(${hue}, 35%, 72%)`,
    };
  }

  const entityLabel =
    entityType === 'PROTOCOL' ? 'protocol'
    : entityType === 'APPLICATION' ? 'application'
    : entityType === 'DEVICE' ? 'device'
    : 'IP address';

  // Compute status badge for monitor context
  const statusBadge = isActive != null ? (() => {
    if (isActive) {
      return <span className="badge bg-success ms-2" style={{ fontSize: '0.7rem' }}>Active</span>;
    }
    if (lastSeenTime) {
      const days = Math.floor((Date.now() - new Date(lastSeenTime).getTime()) / 86400000);
      return <span className="badge bg-secondary ms-2" style={{ fontSize: '0.7rem' }}>Inactive{days > 0 ? ` · ${days}d ago` : ''}</span>;
    }
    return <span className="badge bg-secondary ms-2" style={{ fontSize: '0.7rem' }}>Inactive</span>;
  })() : null;

  return (
    <>
    <div
      className="modal fade show d-block"
      style={{ backgroundColor: 'rgba(0,0,0,0.5)', zIndex: zIndex ?? 1055 }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="entity-detail-title"
    >
      <div className="modal-dialog modal-lg modal-dialog-scrollable">
        <div className="modal-content">
          <div className="modal-header">
            <h5 id="entity-detail-title" className="modal-title d-flex align-items-center gap-2 flex-wrap">
              {displayName}
              {badge}
              {statusBadge}
            </h5>
            <button type="button" className="btn-close ms-3" onClick={onClose} title="Close (Esc)" />
          </div>

          {/* Tabs */}
          <div className="modal-header py-0 border-bottom-0">
            <ul className="nav nav-pills gap-1" style={{ paddingTop: '4px', paddingBottom: '4px' }}>
              {(['details', 'notes'] as Tab[]).map(tab => (
                <li key={tab} className="nav-item">
                  <button
                    className={`nav-link py-1 px-3${activeTab === tab ? ' active' : ''}`}
                    style={{ fontSize: '0.875rem' }}
                    onClick={() => setActiveTab(tab)}
                  >
                    {tab === 'details' && <i className="bi bi-bar-chart me-1" />}
                    {tab === 'notes' && (
                      <>
                        <i className="bi bi-sticky me-1" />
                        {savedNote && (
                          <span className="badge bg-warning text-dark ms-1" style={{ fontSize: '0.6rem' }}>1</span>
                        )}
                      </>
                    )}
                    {tab.charAt(0).toUpperCase() + tab.slice(1)}
                  </button>
                </li>
              ))}
            </ul>
          </div>

          <div className="modal-body">

            {/* ── DETAILS TAB ──────────────────────────────────────── */}
            {activeTab === 'details' && (
              <div>
                {/* ── Role section (IP and DEVICE only) ── */}
                {showRole && (
                  <div className="mb-4">
                    <h6 className="border-bottom pb-1 mb-2 d-flex align-items-center justify-content-between">
                      <span>Role</span>
                      {!roleEditing && !roleLoading && (
                        <div className="d-flex gap-1">
                          <button
                            className="btn btn-outline-secondary btn-sm py-0"
                            style={{ fontSize: '0.75rem' }}
                            onClick={handleOpenEdit}
                          >
                            <i className="bi bi-pencil me-1" />Edit
                          </button>
                          {fileId && (
                            <div className="d-flex align-items-center gap-1">
                              <button
                                className="btn btn-outline-secondary btn-sm py-0"
                                style={{ fontSize: '0.75rem' }}
                                onClick={handleSuggestRole}
                                disabled={roleSuggesting}
                              >
                                {roleSuggesting
                                  ? <><span className="spinner-border spinner-border-sm me-1" role="status" />Suggesting…</>
                                  : <><i className="bi bi-stars me-1" />Suggest with AI</>
                                }
                              </button>
                              <button
                                className="btn btn-link btn-sm p-0 text-muted"
                                style={{ fontSize: '0.8rem', lineHeight: 1 }}
                                onClick={() => setRoleInfoOpen(o => !o)}
                                title="How does this work?"
                              >
                                <i className="bi bi-info-circle" />
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </h6>

                    {roleInfoOpen && (
                      <div className="p-2 rounded mb-2 small text-muted" style={{ background: 'var(--tp-bg-subtle, #f8f9fa)', border: '1px solid var(--bs-border-color)' }}>
                        <strong>How it works:</strong> The AI analyses traffic signals for this entity — manufacturer OUI, device type, TTL, observed applications and protocols — and suggests an operational role label. If the signals are too sparse or generic to make a meaningful assessment, it will decline rather than guess.
                      </div>
                    )}

                    {roleLoading && (
                      <div className="text-muted small fst-italic">Loading role…</div>
                    )}

                    {roleSuggestError && (
                      <div className="d-flex align-items-start gap-2 p-2 rounded mb-2 small" style={{ background: 'var(--bs-warning-bg-subtle, #fff3cd)', color: 'var(--bs-warning-text-emphasis, #664d03)', border: '1px solid var(--bs-warning-border-subtle, #ffc107)' }}>
                        <i className="bi bi-exclamation-triangle-fill mt-1 flex-shrink-0" />
                        <span>{roleSuggestError}</span>
                      </div>
                    )}

                    {!roleLoading && !role && !roleEditing && (
                      <p className="text-muted small fst-italic mb-0">
                        No role assigned.
                      </p>
                    )}

                    {!roleLoading && role && !roleEditing && (
                      <div
                        className={`p-2 rounded small ${role.llmSuggested && !role.confirmedByHuman ? 'bg-warning-subtle border border-warning-subtle' : 'bg-light'}`}
                      >
                        <div className="fw-semibold">
                          {role.roleLabel || <span className="text-muted fst-italic">No label</span>}
                          {role.llmSuggested && !role.confirmedByHuman && (
                            <span className="badge bg-warning text-dark ms-2" style={{ fontSize: '0.65rem' }}>
                              <i className="bi bi-stars me-1" />AI suggested
                            </span>
                          )}
                          {role.confirmedByHuman && (
                            <span className="badge bg-success ms-2" style={{ fontSize: '0.65rem' }}>
                              <i className="bi bi-check-circle me-1" />Confirmed
                            </span>
                          )}
                        </div>
                        {role.roleDescription && (
                          <div className="text-muted mt-1">{role.roleDescription}</div>
                        )}
                        {role.llmSuggested && !role.confirmedByHuman && (
                          <div className="d-flex gap-2 mt-2">
                            <button
                              className="btn btn-success btn-sm py-0"
                              style={{ fontSize: '0.75rem' }}
                              onClick={handleAcceptRole}
                              disabled={roleSaving}
                            >
                              <i className="bi bi-check-lg me-1" />Accept
                            </button>
                            <button
                              className="btn btn-outline-secondary btn-sm py-0"
                              style={{ fontSize: '0.75rem' }}
                              onClick={handleDiscardRole}
                              disabled={roleSaving}
                            >
                              <i className="bi bi-x-lg me-1" />Discard
                            </button>
                          </div>
                        )}
                      </div>
                    )}

                    {roleEditing && (
                      <div>
                        <input
                          className="form-control form-control-sm mb-2"
                          placeholder="Role label (e.g. SCADA Controller)"
                          value={roleLabelDraft}
                          onChange={e => setRoleLabelDraft(e.target.value)}
                        />
                        <textarea
                          className="form-control form-control-sm mb-2"
                          rows={2}
                          placeholder="Description (optional)"
                          value={roleDescDraft}
                          onChange={e => setRoleDescDraft(e.target.value)}
                        />
                        <div className="d-flex gap-2">
                          <button
                            className="btn btn-primary btn-sm py-0"
                            style={{ fontSize: '0.75rem' }}
                            onClick={handleSaveRole}
                            disabled={roleSaving || !roleLabelDraft.trim()}
                          >
                            {roleSaving
                              ? <><span className="spinner-border spinner-border-sm me-1" role="status" />Saving…</>
                              : <><i className="bi bi-floppy me-1" />Save</>
                            }
                          </button>
                          <button
                            className="btn btn-outline-secondary btn-sm py-0"
                            style={{ fontSize: '0.75rem' }}
                            onClick={() => setRoleEditing(false)}
                            disabled={roleSaving}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Host classification signals for IP type */}
                {entityType === 'IP' && hostClass && (
                  <div className="mb-4">
                    <h6 className="border-bottom pb-1 mb-2">Device Classification</h6>
                    <div className="d-flex gap-4 flex-wrap mb-2">
                      {hostClass.manufacturer && (
                        <div>
                          <small className="text-muted d-block">Manufacturer</small>
                          <strong>{hostClass.manufacturer}</strong>
                        </div>
                      )}
                      {hostClass.deviceType && (
                        <div>
                          <small className="text-muted d-block">Device Type</small>
                          <strong>{hostClass.deviceType}</strong>
                        </div>
                      )}
                      {hostClass.ttl != null && (
                        <div>
                          <small className="text-muted d-block">TTL</small>
                          <strong>{hostClass.ttl}</strong>
                        </div>
                      )}
                      {hostClass.confidence != null && (
                        <div>
                          <small className="text-muted d-block">Confidence</small>
                          <strong>{hostClass.confidence}%{hostClass.confidence != null && <span className="text-muted fw-normal"> — {confidenceLevel(hostClass.confidence)}</span>}</strong>
                        </div>
                      )}
                    </div>
                    {(() => {
                      const signalInfo: DeviceSignalInfo = {
                        manufacturer: hostClass.manufacturer ?? undefined,
                        ttl: hostClass.ttl ?? undefined,
                        confidence: hostClass.confidence ?? 0,
                        deviceType: hostClass.deviceType ?? undefined,
                        apps: [],
                      };
                      const { fired, missing } = buildDeviceSignals(signalInfo);
                      return (
                        <>
                          {fired.length > 0 && (
                            <div className="border rounded p-2 mb-2" style={{ background: 'var(--tp-bg-subtle)', fontSize: '0.78rem' }}>
                              <small className="text-muted fw-semibold d-block mb-1">
                                <i className="bi bi-bar-chart-steps me-1" />How this is derived
                              </small>
                              <ul className="mb-0 ps-3">
                                {fired.map((s, i) => <li key={i} className="text-muted">{s}</li>)}
                              </ul>
                            </div>
                          )}
                          {missing.length > 0 && (
                            <div className="border rounded p-2" style={{ background: 'var(--bs-warning-bg-subtle, #fff3cd)', borderColor: 'var(--bs-warning-border-subtle, #ffc107)', fontSize: '0.78rem' }}>
                              <small className="fw-semibold d-block mb-1" style={{ color: 'var(--bs-warning-text-emphasis, #664d03)' }}>
                                <i className="bi bi-lightbulb me-1" />What would improve confidence
                              </small>
                              <ul className="mb-0 ps-3" style={{ color: 'var(--bs-warning-text-emphasis, #664d03)' }}>
                                {missing.map((s, i) => <li key={i}>{s}</li>)}
                              </ul>
                            </div>
                          )}
                        </>
                      );
                    })()}
                  </div>
                )}

                {/* Stats fetched from conversations API */}
                {fileId && (entityType === 'APPLICATION' || entityType === 'PROTOCOL') && (
                  <>
                    {statsLoading && (
                      <div className="text-center py-4">
                        <div className="spinner-border spinner-border-sm text-primary" role="status" />
                        <p className="text-muted mt-2 small">Loading stats…</p>
                      </div>
                    )}
                    {statsError && (
                      <div className="alert alert-warning py-2 small">{statsError}</div>
                    )}
                    {!statsLoading && !statsError && stats && (
                      <>
                        <div className="row g-3 mb-4">
                          <div className="col-4 text-center">
                            <div className="fw-bold fs-5">{formatNumber(stats.conversationCount)}</div>
                            <small className="text-muted">Conversations</small>
                          </div>
                          <div className="col-4 text-center">
                            <div className="fw-bold fs-5">{formatNumber(stats.packetCount)}</div>
                            <small className="text-muted">Packets</small>
                          </div>
                          <div className="col-4 text-center">
                            <div className="fw-bold fs-5">{formatBytes(stats.totalBytes)}</div>
                            <small className="text-muted">Total bytes</small>
                          </div>
                        </div>

                        {stats.topPeers.length > 0 && (
                          <>
                            <h6 className="border-bottom pb-1 mb-2">
                              Top IPs{stats.topPeers.length === 10 ? ' (top 10)' : ''}
                            </h6>
                            <div className="table-responsive rounded border overflow-hidden">
                              <table className="table table-sm table-hover mb-0">
                                <thead className="table-light" style={{ fontSize: '0.8rem' }}>
                                  <tr>
                                    <th>IP Address</th>
                                    <th className="text-end">Bytes</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {stats.topPeers.map(peer => (
                                    <tr
                                      key={peer.ip}
                                      style={{ cursor: 'pointer' }}
                                      onClick={() => setNestedIp(peer.ip)}
                                      title="View IP details"
                                    >
                                      <td className="font-monospace small">{peer.ip}</td>
                                      <td className="text-end small">{formatBytes(peer.bytes)}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </>
                        )}
                      </>
                    )}
                  </>
                )}

                {/* Fallback for entity types without file stats and no role section */}
                {!showRole && (!fileId || (entityType !== 'APPLICATION' && entityType !== 'PROTOCOL')) && (
                  <p className="text-muted small fst-italic">
                    No per-file stats available in this context.
                  </p>
                )}

                {onViewConversations && (
                  <div className="mt-3">
                    <button
                      className="btn btn-outline-primary btn-sm"
                      onClick={() => { onClose(); onViewConversations(); }}
                    >
                      <i className="bi bi-chat-dots me-1" />
                      View Conversations
                    </button>
                  </div>
                )}

                {/* ── Snapshot History (IP + snapshots) or Capture History (generic) ── */}
                {entityType === 'IP' && snapshots && snapshots.length > 0 ? (
                  <div className="mt-4">
                    <h6 className="text-muted fw-semibold mb-2">
                      <i className="bi bi-clock-history me-1" />Snapshot History
                    </h6>
                    {ipHistoryLoading && (
                      <div className="text-muted small py-2">
                        <span className="spinner-border spinner-border-sm me-2" role="status" />Loading…
                      </div>
                    )}
                    {!ipHistoryLoading && ipSnapHistory.length === 0 && (
                      <p className="text-muted small fst-italic">Not seen in any snapshots.</p>
                    )}
                    {!ipHistoryLoading && ipSnapHistory.length > 0 && (
                      <div className="table-responsive rounded border overflow-hidden">
                        <table className="table table-sm table-hover mb-0">
                          <thead className="table-light" style={{ fontSize: '0.8rem' }}>
                            <tr>
                              <th className="text-muted fw-normal">#</th>
                              <th className="text-muted fw-normal">Snapshot</th>
                              <th className="text-muted fw-normal">MAC Address</th>
                              <th className="text-muted fw-normal">Manufacturer</th>
                              <th className="text-muted fw-normal">Device Type</th>
                              <th className="text-muted fw-normal">Protocols / Apps</th>
                            </tr>
                          </thead>
                          <tbody>
                            {ipSnapHistory.map(({ snap, host, protocols, apps }, idx) => (
                              <tr key={snap.id}>
                                <td><small className="text-muted">{snap.snapshotOrder + 1}</small></td>
                                <td>
                                  <small className="text-muted d-block">{formatSnapTime(snap)}</small>
                                  <small className="text-muted text-break" style={{ fontSize: '0.7rem' }}>{snap.fileName}</small>
                                </td>
                                <td>
                                  <code style={{ fontSize: '0.75rem' }}>{host?.mac ?? '—'}</code>
                                  {idx > 0 && host?.mac && ipSnapHistory[idx - 1].host?.mac &&
                                    host.mac !== ipSnapHistory[idx - 1].host!.mac && (
                                      <Badge bg="warning" text="dark" className="ms-1" style={{ fontSize: '0.65rem' }}>changed</Badge>
                                    )}
                                </td>
                                <td><small className="text-muted">{host?.manufacturer ?? '—'}</small></td>
                                <td><small className="text-muted">{host?.deviceType ?? '—'}</small></td>
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
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="mt-4">
                    <h6 className="text-muted fw-semibold mb-2">
                      <i className="bi bi-clock-history me-1" />Capture History
                    </h6>
                    {historyLoading && (
                      <div className="text-muted small py-2">
                        <span className="spinner-border spinner-border-sm me-2" role="status" />Loading…
                      </div>
                    )}
                    {historyError && (
                      <div className="alert alert-warning py-2 small">{historyError}</div>
                    )}
                    {!historyLoading && !historyError && history.length === 0 && (
                      <p className="text-muted small fst-italic">Not seen in any uploaded files.</p>
                    )}
                    {!historyLoading && history.length > 0 && (
                      <div className="table-responsive rounded border overflow-hidden">
                        <table className="table table-sm table-hover mb-0">
                          <thead className="table-light" style={{ fontSize: '0.8rem' }}>
                            <tr>
                              <th className="text-muted fw-normal">File</th>
                              <th className="text-muted fw-normal">Capture Start</th>
                              <th className="text-end text-muted fw-normal">Packets</th>
                              <th className="text-end text-muted fw-normal">Bytes</th>
                            </tr>
                          </thead>
                          <tbody>
                            {history.map(entry => (
                              <tr
                                key={entry.fileId}
                                style={{ cursor: 'pointer' }}
                                onClick={() => { onClose(); navigate(`/analysis/${entry.fileId}`); }}
                                title="Open in analysis"
                              >
                                <td className="small">{entry.fileName}</td>
                                <td className="small text-muted">
                                  {entry.startTime ? new Date(entry.startTime).toLocaleString() : '—'}
                                </td>
                                <td className="text-end small text-muted">
                                  {entry.packetCount != null ? formatNumber(entry.packetCount) : '—'}
                                </td>
                                <td className="text-end small text-muted">
                                  {entry.totalBytes != null ? formatBytes(entry.totalBytes) : '—'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* ── NOTES TAB ────────────────────────────────────────── */}
            {activeTab === 'notes' && (
              <div>
                <p className="text-muted small mb-2">
                  Notes are saved globally for this {entityLabel} and persist across all captures.
                </p>
                <textarea
                  className="form-control mb-2"
                  rows={6}
                  style={{ fontSize: '0.875rem' }}
                  placeholder={`Add notes about ${displayName}…`}
                  value={noteText}
                  onChange={e => setNoteText(e.target.value)}
                />
                {savedNote && (
                  <p className="text-muted" style={{ fontSize: '0.7rem' }}>
                    Last updated: {new Date(savedNote.updatedAt).toLocaleString()}
                  </p>
                )}
                <div className="d-flex gap-2">
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={handleSaveNote}
                    disabled={noteSaving || !noteChanged}
                  >
                    {noteSaving ? (
                      <><span className="spinner-border spinner-border-sm me-1" role="status" />Saving…</>
                    ) : (
                      <><i className="bi bi-floppy me-1" />Save Note</>
                    )}
                  </button>
                  {savedNote && (
                    <button
                      className="btn btn-outline-danger btn-sm"
                      onClick={handleDeleteNote}
                      disabled={noteDeleting}
                    >
                      {noteDeleting
                        ? <span className="spinner-border spinner-border-sm" role="status" />
                        : <><i className="bi bi-trash me-1" />Delete</>
                      }
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>

    {nestedIp && (
      <EntityDetailModal
        entityType="IP"
        entityKey={nestedIp}
        displayName={nestedIp}
        fileId={fileId}
        onClose={() => setNestedIp(null)}
        zIndex={(zIndex ?? 1055) + 10}
      />
    )}
    </>
  );
}
