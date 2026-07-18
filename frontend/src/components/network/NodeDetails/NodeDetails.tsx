import { useEffect, useState } from 'react';
import { Badge, Modal } from '@govtechsg/sgds-react';
import { useNavigate } from 'react-router-dom';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import { getProtocolColor } from '@/features/network/constants';
import { AXIS_ORDER, AXIS_META, detectAxisConflict, axisFacts, type AxisKey } from '@/features/network/classificationAxes';
import { DEVICE_TYPES, deviceTypeLabel } from '@/utils/deviceType';
import { HostnameSourceBadge } from '@components/common/HostnameSourceBadge/HostnameSourceBadge';
import { Pagination } from '@components/common/Pagination/Pagination';
import { EntityDetailModal } from '@components/common/EntityDetailModal';
import { RoleSection } from '@components/common/EntityDetailModal/sections/RoleSection';
import { useEntityRole } from '@components/common/EntityDetailModal/hooks/useEntityRole';
import { insightsService } from '@/features/insights/services/insightsService';
import { conversationService } from '@/features/conversation/services/conversationService';
import { AdjudicationPanel } from '@components/common/AdjudicationPanel/AdjudicationPanel';
import type { HostIdentity } from '@/types';
import { ServiceLogTab } from '@components/network/ServiceLogTab/ServiceLogTab';
import { getServiceTab, type ServiceTabConfig } from '@/features/network/serviceTabs';
import type { NodeHighlight } from '@/components/network/NetworkGraph/NetworkGraph';
import {
  entityNotesService,
  type EntityNote,
  type EntityHistoryEntry,
  type EntityType,
} from '@/features/notes/services/entityNotesService';
import './NodeDetails.css';
import { Alert } from '@components/common/Alert';

interface NodeDetailsProps {
  node: GraphNode;
  edges: GraphEdge[];
  fileId: string;
  onClose: () => void;
  changeHighlight?: NodeHighlight;
  zIndex?: number;
}

/** Predefined override/evidence label options for the Identity panel; it appends an "Other…"
 *  free-text. Derived from the canonical device-type config so a rename/addition there flows here. */
const DEVICE_LABELS = DEVICE_TYPES.filter(t => t !== 'UNKNOWN').map(deviceTypeLabel);

type BaseTab = 'details' | 'history' | 'notes';
/** Active tab id: a base tab, or a service-role tab keyed as `svc:<role>` (e.g. "svc:dns"). */
type Tab = BaseTab | string;

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

export function NodeDetails({ node, edges, fileId, onClose, changeHighlight, zIndex }: NodeDetailsProps) {
  const navigate = useNavigate();
  // Evidence header explainer modal, and which axis fact row is expanded to its derivation.
  const [evidenceInfoOpen, setEvidenceInfoOpen] = useState(false);
  const [expandedAxis, setExpandedAxis] = useState<AxisKey | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('details');
  const [peersPage, setPeersPage] = useState(1);
  const [historyPage, setHistoryPage] = useState(1);
  const HISTORY_PAGE_SIZE = 10;
  const [nestedIp, setNestedIp] = useState<string | null>(null);

  // Live adjudicated identity: seeded from the graph node, re-fetched after an override/evidence
  // change so the panel reflects the new verdict without reloading the whole graph.
  const [liveIdentity, setLiveIdentity] = useState<HostIdentity | null>(null);
  const refreshIdentity = () => {
    conversationService
      .getHostIdentities(fileId)
      .then(list => setLiveIdentity(list.find(i => i.ip === node.data.ip) ?? null))
      .catch(() => {});
  };

  // Notes state
  const [noteText, setNoteText] = useState('');
  const [savedNote, setSavedNote] = useState<EntityNote | null>(null);
  const [noteSaving, setNoteSaving] = useState(false);
  const [noteDeleting, setNoteDeleting] = useState(false);

  // History state
  const [history, setHistory] = useState<EntityHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  // Per-file role label/stale for each history row (#369), keyed by fileId.
  const [historyRoles, setHistoryRoles] = useState<Record<string, { label: string | null; origin: string | null; stale: boolean }>>({});

  // Determine entity type and key for notes/history
  const entityType: EntityType = node.data.isL2 ? 'DEVICE' : 'IP';
  const entityKey = node.data.isL2
    ? (node.data.mac ?? node.data.ip)
    : node.data.ip;

  // Per-file node role (#369): editable in this snapshot's context.
  const role = useEntityRole(entityType, entityKey ?? '', fileId, !!entityKey);

  // ESC closes the modal — but not if a nested IP modal is open (let the nested one handle it first)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !nestedIp) {
        e.stopImmediatePropagation();
        onClose();
      }
    };
    document.addEventListener('keydown', onKeyDown, { capture: true });
    return () => document.removeEventListener('keydown', onKeyDown, { capture: true });
  }, [onClose, nestedIp]);

  // Lock background scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, []);

  // Load note on mount
  useEffect(() => {
    entityNotesService.getNote(entityType, entityKey).then(note => {
      if (note) {
        setSavedNote(note);
        setNoteText(note.note);
      }
    });
  }, [entityType, entityKey]);

  // Reset history when the entity changes so a reused modal reloads fresh. Also reset the peers
  // and history page counters — NodeDetails isn't remounted between node selections, so without
  // this a user on page 3 of one node lands on page 3 of the next node's (shorter) data.
  useEffect(() => {
    setHistory([]);
    setHistoryRoles({});
    setHistoryError(null);
    setPeersPage(1);
    setHistoryPage(1);
    // Re-fetched identity is per-node: without this reset, clicking another node while the reused
    // panel is open shows the PREVIOUS node's post-override verdict on the new node.
    setLiveIdentity(null);
    setExpandedAxis(null);
  }, [entityType, entityKey]);

  // Load history when History tab is first opened
  useEffect(() => {
    if (activeTab !== 'history') return;
    if (history.length > 0 || historyLoading) return;
    setHistoryLoading(true);
    setHistoryError(null);
    entityNotesService
      .getHistory(entityType, entityKey)
      .then(entries => {
        setHistory(entries);
        // Fetch each file's role label so the history doubles as a role-change trail.
        Promise.all(
          entries.map(e =>
            insightsService
              .getNodeRole(entityType, entityKey ?? '', e.fileId)
              .then(r => [e.fileId, { label: r?.roleLabel ?? null, origin: r?.origin ?? null, stale: !!r?.staleSince }] as const)
              .catch(() => [e.fileId, { label: null, origin: null, stale: false }] as const),
          ),
        ).then(pairs => setHistoryRoles(Object.fromEntries(pairs)));
      })
      .catch(() => setHistoryError('Failed to load history'))
      .finally(() => setHistoryLoading(false));
  }, [activeTab, entityType, entityKey, history.length, historyLoading]);

  const handleSaveNote = async () => {
    setNoteSaving(true);
    try {
      const updated = await entityNotesService.upsertNote(entityType, entityKey, noteText);
      setSavedNote(updated);
    } finally {
      setNoteSaving(false);
    }
  };

  const handleDeleteNote = async () => {
    setNoteDeleting(true);
    try {
      await entityNotesService.deleteNote(entityType, entityKey);
      setSavedNote(null);
      setNoteText('');
    } finally {
      setNoteDeleting(false);
    }
  };

  const connectedEdges = edges.filter(e => e.source === node.id || e.target === node.id);

  // Build per-peer summary: peerIp → { packets, bytes, apps }
  const peerMap = new Map<string, { packets: number; bytes: number; apps: Set<string> }>();
  connectedEdges.forEach(edge => {
    const peer = edge.source === node.id ? edge.target : edge.source;
    const existing = peerMap.get(peer) ?? { packets: 0, bytes: 0, apps: new Set() };
    existing.packets += edge.data.packetCount;
    existing.bytes += edge.data.totalBytes;
    const label = edge.data.appName ?? edge.data.protocol;
    existing.apps.add(label);
    peerMap.set(peer, existing);
  });

  const peers = Array.from(peerMap.entries()).sort((a, b) => b[1].bytes - a[1].bytes);
  const PEERS_PAGE_SIZE = 15;
  const peersTotalPages = Math.ceil(peers.length / PEERS_PAGE_SIZE);
  const peersPageClamped = Math.min(peersPage, Math.max(1, peersTotalPages));
  const visiblePeers = peers.slice(
    (peersPageClamped - 1) * PEERS_PAGE_SIZE,
    peersPageClamped * PEERS_PAGE_SIZE,
  );

  const historyTotalPages = Math.ceil(history.length / HISTORY_PAGE_SIZE);
  const historyPageClamped = Math.min(historyPage, Math.max(1, historyTotalPages));
  const visibleHistory = history.slice(
    (historyPageClamped - 1) * HISTORY_PAGE_SIZE,
    historyPageClamped * HISTORY_PAGE_SIZE,
  );


  // Service-role tabs (DNS today; web/API servers later) for the roles this host was detected serving.
  const serviceTabs = (node.data.serviceRoles ?? [])
    .map(getServiceTab)
    .filter((t): t is ServiceTabConfig<unknown, unknown> => Boolean(t));
  const activeServiceTab = serviceTabs.find(t => `svc:${t.role}` === activeTab);

  // If the selected service tab is no longer offered (e.g. the modal re-rendered for a node without
  // that role), fall back to Details so the body never goes blank.
  useEffect(() => {
    const isBaseTab = activeTab === 'details' || activeTab === 'history' || activeTab === 'notes';
    if (!isBaseTab && !activeServiceTab) setActiveTab('details');
  }, [activeTab, activeServiceTab]);

  const noteChanged = noteText !== (savedNote?.note ?? '');

  return (
    <div
      className="modal fade show d-block"
      style={{ backgroundColor: 'rgba(0,0,0,0.5)', zIndex: zIndex ?? 1055 }}
      onClick={e => {
        if (e.target === e.currentTarget) onClose();
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="node-details-title"
    >
      <div className="modal-dialog modal-lg modal-dialog-scrollable">
        <div className="modal-content">
          <div className="modal-header">
            <div id="node-details-title" className="modal-title">
              <div className="fw-semibold">Node Details</div>
              <div className="font-monospace fw-normal" style={{ fontSize: '0.85rem', color: '#6c757d' }}>
                {node.data.ip}
                {node.data.hostname && (
                  <span className="ms-2 node-details-hostname">({node.data.hostname})</span>
                )}
              </div>
            </div>
            <button
              type="button"
              className="btn-close ms-3"
              onClick={onClose}
              title="Close (Esc)"
            />
          </div>

          {/* Tabs */}
          <div className="modal-header py-0 border-bottom-0">
            <ul className="nav nav-pills gap-1" style={{ paddingTop: '4px', paddingBottom: '4px' }}>
              {(['details', 'history', 'notes'] as Tab[]).map(tab => (
                <li key={tab} className="nav-item">
                  <button
                    className={`nav-link py-1 px-3${activeTab === tab ? ' active' : ''}`}
                    style={{ fontSize: '0.875rem' }}
                    onClick={() => setActiveTab(tab)}
                  >
                    {tab === 'details' && <i className="bi bi-info-circle me-1" />}
                    {tab === 'history' && <i className="bi bi-clock-history me-1" />}
                    {tab === 'notes' && (
                      <>
                        <i className="bi bi-sticky me-1" />
                        {savedNote && <span className="badge bg-warning text-dark ms-1" style={{ fontSize: '0.6rem' }}>1</span>}
                      </>
                    )}
                    {tab.charAt(0).toUpperCase() + tab.slice(1)}
                  </button>
                </li>
              ))}
              {serviceTabs.map(svc => {
                const id = `svc:${svc.role}`;
                return (
                  <li key={id} className="nav-item">
                    <button
                      className={`nav-link py-1 px-3${activeTab === id ? ' active' : ''}`}
                      style={{ fontSize: '0.875rem' }}
                      onClick={() => setActiveTab(id)}
                    >
                      <i className={`bi ${svc.icon} me-1`} />
                      {svc.label}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>

          <div className="modal-body">
            {/* Change event highlight banner */}
            {changeHighlight && (
              <div
                className="d-flex align-items-center gap-2 rounded p-2 mb-3 small"
                style={{ background: changeHighlight.color + '22', border: `1px solid ${changeHighlight.color}55` }}
              >
                <span
                  style={{ width: 10, height: 10, borderRadius: '50%', background: changeHighlight.color, flexShrink: 0, display: 'inline-block' }}
                />
                <span style={{ color: changeHighlight.color, fontWeight: 600 }}>
                  {changeHighlight.label}
                </span>
                {changeHighlight.description && (
                  <span className="text-muted">— {changeHighlight.description}</span>
                )}
              </div>
            )}

            {/* ── DETAILS TAB ────────────────────────────────────────── */}
            {activeTab === 'details' && (
              <>
                {/* Ghost node warning */}
                {node.data.ghostFlags && node.data.ghostFlags.length > 0 && (
                  <Alert
                    variant="warning"
                    className="d-flex align-items-start gap-2 p-2 mb-3 small"
                  >
                    <i className="bi bi-slash-circle mt-1 flex-shrink-0" />
                    <div>
                      <span className="fw-semibold">Phantom node</span>
                      <span className="ms-2">
                        {node.data.ghostFlags.includes('arp-no-reply') && 'ARP request target — never replied.'}
                        {node.data.ghostFlags.includes('ttl-exceeded') && 'Traceroute intermediate hop — only appeared via ICMP TTL-exceeded replies.'}
                        {node.data.ghostFlags.includes('icmp-unreachable') && !node.data.ghostFlags.includes('arp-no-reply') && !node.data.ghostFlags.includes('ttl-exceeded') && 'ICMP probe target — never responded.'}
                        {node.data.ghostFlags.includes('no-response') && !node.data.ghostFlags.includes('arp-no-reply') && !node.data.ghostFlags.includes('icmp-unreachable') && !node.data.ghostFlags.includes('ttl-exceeded') && 'Scan target — received traffic but never sent a reply.'}
                      </span>
                      <div className="mt-1 d-flex flex-wrap gap-1">
                        {node.data.ghostFlags.map(flag => {
                          const meta: Record<string, { label: string; color: string }> = {
                            'no-response':      { label: 'No response',      color: '#e74c3c' },
                            'arp-no-reply':     { label: 'ARP no-reply',     color: '#e67e22' },
                            'icmp-unreachable': { label: 'ICMP unreachable', color: '#c0392b' },
                            'ttl-exceeded':     { label: 'TTL exceeded',     color: '#8e44ad' },
                          };
                          const { label, color } = meta[flag] ?? { label: flag, color: '#6c757d' };
                          return (
                            <span key={flag} className="badge" style={{ backgroundColor: color, color: '#fff', fontSize: '0.7rem' }}>
                              {label}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  </Alert>
                )}

                {/* Identity */}
                <div className="row mb-3">
                  <div className="col-sm-6">
                    <dl className="row mb-0 small">
                      <dt className="col-5 text-muted">IP</dt>
                      <dd className="col-7 font-monospace mb-1">{node.data.ip}</dd>

                      {node.data.mac && (
                        <>
                          <dt className="col-5 text-muted">MAC</dt>
                          <dd className="col-7 font-monospace mb-1">{node.data.mac}</dd>
                        </>
                      )}

                      {node.data.hostname && (
                        <>
                          <dt className="col-5 text-muted">Hostname</dt>
                          <dd className="col-7 mb-1 d-flex align-items-center gap-1">
                            <span>{node.data.hostname}</span>
                            <HostnameSourceBadge source={node.data.hostnameSource} />
                          </dd>
                        </>
                      )}

                    </dl>
                  </div>

                  <div className="col-sm-6">
                    <dl className="row mb-0 small">
                      <dt className="col-7 text-muted">Packets sent</dt>
                      <dd className="col-5 mb-1">{formatNumber(node.data.packetsSent)}</dd>
                      <dt className="col-7 text-muted">Packets received</dt>
                      <dd className="col-5 mb-1">{formatNumber(node.data.packetsReceived)}</dd>
                      <dt className="col-7 text-muted">Bytes sent</dt>
                      <dd className="col-5 mb-1">{formatBytes(node.data.bytesSent)}</dd>
                      <dt className="col-7 text-muted">Bytes received</dt>
                      <dd className="col-5 mb-1">{formatBytes(node.data.bytesReceived)}</dd>
                      <dt className="col-7 text-muted fw-bold">Total bytes</dt>
                      <dd className="col-5 mb-1 fw-bold">{formatBytes(node.data.totalBytes)}</dd>
                    </dl>
                  </div>
                </div>

                {/* Adjudicated identity — explainability, override & evidence in one panel.
                    Rendered even when no identity was adjudicated (label "Unknown"): a host the
                    adjudicator never saw (no conversations, pre-adjudicator file, failed fetch) is
                    exactly one an analyst may want to label, so the tools must not disappear. */}
                {!node.data.isL2 && (
                  <AdjudicationPanel
                    fileId={fileId}
                    question="host-identity"
                    entityKey={node.data.ip}
                    title="Identity"
                    labelOptions={DEVICE_LABELS}
                    zIndex={zIndex}
                    verdict={{
                      label: liveIdentity?.primaryLabel ?? node.data.identityLabel ?? 'Unknown',
                      basis: (liveIdentity?.basis ?? node.data.identityBasis ?? 'MACHINE') as 'HUMAN' | 'MACHINE',
                      confidence: liveIdentity?.confidence ?? node.data.identityConfidence,
                      contested: liveIdentity?.contested ?? node.data.identityContested ?? false,
                      candidates: (liveIdentity?.candidates ?? node.data.identityCandidates) ?? undefined,
                    }}
                    onChanged={refreshIdentity}
                  />
                )}

                {/* Evidence behind Identity (#499) — the independent signals the verdict weighed.
                    Sits under Identity so it reads as "the verdict, and why". Click a badge to
                    inspect & adjudicate that axis; the header ⓘ explains the model. */}
                {!node.data.isL2 && (
                  <div className="mb-4">
                    <h6 className="border-bottom pb-1 mb-2 d-flex align-items-center">
                      <span className="text-muted fw-normal" style={{ fontSize: '0.8rem' }}>
                        Evidence weighed
                      </span>
                      <i
                        role="button"
                        aria-label="How Identity and this evidence relate"
                        className="bi bi-info-circle ms-1 text-muted"
                        style={{ cursor: 'pointer', fontSize: '0.8rem' }}
                        onClick={e => {
                          e.stopPropagation();
                          setEvidenceInfoOpen(true);
                        }}
                      />
                    </h6>
                    {/* Facts only, no per-axis badge — a badge picks one label, which is a
                        conclusion, and conclusions belong to the Identity verdict alone (#499).
                        The row lists what was observed; expanding it opens the derivation and the
                        analyst tools (override / evidence), which feed the Identity vote. */}
                    {AXIS_ORDER.map(key => {
                      const meta = AXIS_META[key];
                      const facts = axisFacts(node.data, key);
                      const expanded = expandedAxis === key;
                      return (
                        <div key={key} className="mb-1">
                          <div
                            role="button"
                            title={`Inspect ${meta.label} — ${meta.caption}`}
                            className="d-flex align-items-center gap-2"
                            style={{ fontSize: '0.8rem', cursor: 'pointer' }}
                            onClick={e => {
                              e.stopPropagation();
                              setExpandedAxis(expanded ? null : key);
                            }}
                          >
                            <span className="text-muted" style={{ minWidth: '100px' }}>{meta.label}</span>
                            {facts.length > 0 ? (
                              <span className="flex-grow-1">{facts.join(' · ')}</span>
                            ) : (
                              <span className="text-muted fst-italic flex-grow-1">Nothing observed</span>
                            )}
                            <i className={`bi text-muted ${expanded ? 'bi-chevron-up' : 'bi-chevron-down'}`} />
                          </div>
                          {/* Facts are measurements — there is no per-axis conclusion to dispute,
                              so no adjudication tools here. Overrides and evidence live on the
                              Identity panel, where they actually feed the vote. */}
                          {expanded && (
                            <div className="mt-2 ms-2 ps-2 border-start text-muted" style={{ fontSize: '0.72rem' }}>
                              {meta.derivation}
                            </div>
                          )}
                        </div>
                      );
                    })}
                    {(() => {
                      // A human verdict resolves the contest by definition (mirrors
                      // applyIdentities, which clears deviceType on HUMAN basis at graph build) —
                      // without this, the banner keeps citing the superseded machine verdict
                      // after an in-panel "I disagree".
                      const humanVerdict =
                        (liveIdentity?.basis ?? node.data.identityBasis) === 'HUMAN';
                      const { conflict, detail } = detectAxisConflict(
                        humanVerdict ? { ...node.data, deviceType: undefined } : node.data,
                      );
                      return conflict ? (
                        <div
                          className="d-flex align-items-start gap-1 mt-2 text-warning-emphasis"
                          style={{ fontSize: '0.72rem' }}
                        >
                          <i className="bi bi-exclamation-triangle-fill mt-1" />
                          <span>
                            <strong>Evidence conflicts.</strong> {detail} Worth a look — if the
                            service evidence is right, correct Identity with <em>“I disagree”</em>.
                          </span>
                        </div>
                      ) : null;
                    })()}
                  </div>
                )}

                {/* Role — the operator's assigned label (persists across captures, feeds Monitor
                    change-detection). Distinct from the measured Identity above: this is a name you
                    give the host, not a classification. Grouped directly beneath Identity (#499). */}
                {entityKey && <RoleSection fileId={fileId} role={role} raisedModal={zIndex != null} />}

                {/* Protocols */}
                <div className="mb-3">
                  <h6 className="border-bottom pb-1 mb-2">Protocols</h6>
                  <div className="d-flex flex-wrap gap-1">
                    {node.data.protocols.map(p => (
                      <span
                        key={p}
                        className="badge"
                        style={{ backgroundColor: getProtocolColor(p), color: '#fff' }}
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Connections table */}
                <div>
                  <h6 className="border-bottom pb-1 mb-2">
                    Connections ({peers.length} peer{peers.length !== 1 ? 's' : ''})
                  </h6>
                  <div className="table-responsive rounded border overflow-hidden">
                    <table className="table table-sm table-hover mb-0">
                      <thead className="table-light" style={{ fontSize: '0.8rem' }}>
                        <tr>
                          <th>Peer IP</th>
                          <th>Application / Protocol</th>
                          <th className="text-end">Packets</th>
                          <th className="text-end">Bytes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visiblePeers.map(([ip, info]) => (
                          <tr
                            key={ip}
                            className="node-details-peer-row"
                            title="Click to view conversations"
                            onClick={() => {
                              onClose();
                              navigate(
                                `/analysis/${fileId}/conversations?srcIp=${node.data.ip}&peerIp=${ip}`
                              );
                            }}
                          >
                            <td className="font-monospace small">
                              <button
                                className="btn btn-link btn-sm p-0 font-monospace text-start"
                                style={{ fontSize: 'inherit' }}
                                onClick={e => {
                                  e.stopPropagation();
                                  setNestedIp(ip);
                                }}
                              >
                                {ip}
                              </button>
                              <i className="bi bi-arrow-right-circle ms-1 text-muted node-details-peer-icon"></i>
                            </td>
                            <td>
                              {Array.from(info.apps).map(app => (
                                <Badge key={app} bg="light" text="dark" className="me-1 border">
                                  {app}
                                </Badge>
                              ))}
                            </td>
                            <td className="text-end small">{formatNumber(info.packets)}</td>
                            <td className="text-end small">{formatBytes(info.bytes)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {peersTotalPages > 1 && (
                    <Pagination
                      currentPage={peersPageClamped}
                      totalPages={peersTotalPages}
                      totalItems={peers.length}
                      pageSize={PEERS_PAGE_SIZE}
                      onPageChange={setPeersPage}
                      showPageSizeSelector={false}
                    />
                  )}
                </div>
              </>
            )}

            {/* ── HISTORY TAB ────────────────────────────────────────── */}
            {activeTab === 'history' && (
              <div>
                <p className="text-muted small mb-3">
                  Files in which this {entityType === 'DEVICE' ? 'device (MAC)' : 'IP address'} has appeared, most recent first.
                </p>
                {historyLoading && (
                  <div className="text-center py-4">
                    <div className="spinner-border spinner-border-sm text-primary" role="status" />
                    <p className="text-muted mt-2 small">Loading history…</p>
                  </div>
                )}
                {historyError && (
                  <div className="alert alert-warning py-2 small">{historyError}</div>
                )}
                {!historyLoading && !historyError && history.length === 0 && (
                  <p className="text-muted small fst-italic">No history found across uploaded files.</p>
                )}
                {!historyLoading && history.length > 0 && (
                  <div className="table-responsive rounded border overflow-hidden">
                    <table className="table table-sm table-hover mb-0">
                      <thead className="table-light" style={{ fontSize: '0.8rem' }}>
                        <tr>
                          <th>File</th>
                          <th>Role</th>
                          <th>Capture Start</th>
                          <th className="text-end">Packets</th>
                          <th className="text-end">Bytes</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleHistory.map(entry => (
                          <tr
                            key={entry.fileId}
                            className={entry.fileId === fileId ? 'table-active' : ''}
                          >
                            <td className="small">
                              {entry.fileName}
                              {entry.fileId === fileId && (
                                <span className="badge bg-primary ms-2" style={{ fontSize: '0.6rem' }}>current</span>
                              )}
                            </td>
                            <td className="small">
                              {historyRoles[entry.fileId]?.label ? (
                                <span className="d-inline-flex align-items-center gap-1">
                                  {historyRoles[entry.fileId].label}
                                  {historyRoles[entry.fileId].origin === 'CARRIED_FORWARD' && (
                                    <span className="badge bg-light text-secondary border" style={{ fontSize: '0.55rem', fontWeight: 400 }} title="Inherited from an earlier snapshot (carried forward)">carried</span>
                                  )}
                                  {historyRoles[entry.fileId].stale && (
                                    <span className="badge bg-warning text-dark" style={{ fontSize: '0.6rem' }} title="Label flagged stale in this file">
                                      <i className="bi bi-exclamation-triangle" />
                                    </span>
                                  )}
                                </span>
                              ) : (
                                <span className="text-muted">—</span>
                              )}
                            </td>
                            <td className="small">
                              {entry.startTime
                                ? new Date(entry.startTime).toLocaleString('en-GB')
                                : '—'}
                            </td>
                            <td className="text-end small">
                              {entry.packetCount != null ? formatNumber(entry.packetCount) : '—'}
                            </td>
                            <td className="text-end small">
                              {entry.totalBytes != null ? formatBytes(entry.totalBytes) : '—'}
                            </td>
                            <td className="text-end">
                              <button
                                className="btn btn-link btn-sm p-0 text-muted"
                                title="Go to this analysis"
                                onClick={() => {
                                  onClose();
                                  navigate(`/analysis/${entry.fileId}`);
                                }}
                              >
                                <i className="bi bi-box-arrow-up-right" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {historyTotalPages > 1 && (
                      <Pagination
                        currentPage={historyPageClamped}
                        totalPages={historyTotalPages}
                        totalItems={history.length}
                        pageSize={HISTORY_PAGE_SIZE}
                        onPageChange={setHistoryPage}
                        showPageSizeSelector={false}
                      />
                    )}
                  </div>
                )}
              </div>
            )}

            {/* ── NOTES TAB ──────────────────────────────────────────── */}
            {activeTab === 'notes' && (
              <div>
                <p className="text-muted small mb-2">
                  Notes are saved globally for this {entityType === 'DEVICE' ? 'device' : 'IP address'} and persist across all captures.
                </p>
                <textarea
                  className="form-control mb-2"
                  rows={6}
                  style={{ fontSize: '0.875rem' }}
                  placeholder={`Add notes about ${entityKey}…`}
                  value={noteText}
                  onChange={e => setNoteText(e.target.value)}
                />
                {savedNote && (
                  <p className="text-muted" style={{ fontSize: '0.7rem' }}>
                    Last updated: {new Date(savedNote.updatedAt).toLocaleString('en-GB')}
                  </p>
                )}
                <div className="d-flex gap-2">
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={handleSaveNote}
                    disabled={noteSaving || !noteChanged}
                  >
                    {noteSaving ? (
                      <>
                        <span className="spinner-border spinner-border-sm me-1" role="status" />
                        Saving…
                      </>
                    ) : (
                      <>
                        <i className="bi bi-floppy me-1" />
                        Save Note
                      </>
                    )}
                  </button>
                  {savedNote && (
                    <button
                      className="btn btn-outline-danger btn-sm"
                      onClick={handleDeleteNote}
                      disabled={noteDeleting}
                    >
                      {noteDeleting ? (
                        <span className="spinner-border spinner-border-sm" role="status" />
                      ) : (
                        <>
                          <i className="bi bi-trash me-1" />
                          Delete
                        </>
                      )}
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* ── SERVICE-ROLE TAB (DNS, …) ──────────────────────────── */}
            {activeServiceTab && (
              <ServiceLogTab fileId={fileId} ip={node.data.ip} config={activeServiceTab} />
            )}
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

      {/* Evidence model explainer (#499) — how Identity relates to the evidence rows. Raised above
          the node panel's own z-index so it isn't hidden behind it in monitor mode (modal-in-modal). */}
      <Modal
        show={evidenceInfoOpen}
        onHide={() => setEvidenceInfoOpen(false)}
        centered
        className="tp-nested-modal"
        backdropClassName="tp-nested-modal-backdrop"
      >
        <Modal.Header closeButton>
          <Modal.Title style={{ fontSize: '1rem' }}>How this host is classified</Modal.Title>
        </Modal.Header>
        <Modal.Body style={{ fontSize: '0.85rem' }}>
          <p className="mb-1">The model is <strong>facts → votes → verdict</strong>:</p>
          <ul>
            <li>
              The three rows are the <strong>measured facts</strong>, each independent:{' '}
              <strong>Hardware</strong> (MAC manufacturer, TTL), <strong>Ports / Service</strong>{' '}
              (detected service role, or the app nDPI identified), <strong>Behaviour</strong> (who
              opened the connections).
            </li>
            <li>
              The classifier reads those facts and <strong>votes</strong> on device types with
              weights — shown with each candidate’s score under <em>Why</em> in the Identity panel.
              One fact can support several types.
            </li>
            <li>
              <strong>Identity</strong> is the adjudicated <strong>verdict</strong> of that vote —
              the only place a confidence percentage belongs.
            </li>
          </ul>
          <p className="mb-0">
            Click any fact row to see how it was derived. To weigh in, use the Identity panel:{' '}
            <em>Add evidence</em> feeds the vote; <em>“I disagree”</em> sets the verdict yourself.
          </p>
        </Modal.Body>
      </Modal>
    </div>
  );
}
