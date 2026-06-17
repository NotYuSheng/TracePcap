import { useEffect, useState } from 'react';
import { Badge } from '@govtechsg/sgds-react';
import { useNavigate } from 'react-router-dom';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import { NODE_TYPE_CONFIG, getProtocolColor } from '@/features/network/constants';
import { deviceTypeLabel, deviceTypeColor } from '@/utils/deviceType';
import { NodeClassificationPopup } from '@components/common/NodeClassificationPopup/NodeClassificationPopup';
import { EntityDetailModal } from '@components/common/EntityDetailModal';
import type { NodeHighlight } from '@/components/network/NetworkGraph/NetworkGraph';
import {
  entityNotesService,
  type EntityNote,
  type EntityHistoryEntry,
  type EntityType,
} from '@/features/notes/services/entityNotesService';
import './NodeDetails.css';

interface NodeDetailsProps {
  node: GraphNode;
  edges: GraphEdge[];
  fileId: string;
  onClose: () => void;
  changeHighlight?: NodeHighlight;
  zIndex?: number;
}

type Tab = 'details' | 'history' | 'notes';

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

function getRoleBadgeClass(role: string): string {
  switch (role) {
    case 'client':
      return 'bg-primary';
    case 'server':
      return 'bg-success';
    case 'both':
      return 'bg-secondary';
    default:
      return 'bg-light text-dark';
  }
}

export function NodeDetails({ node, edges, fileId, onClose, changeHighlight, zIndex }: NodeDetailsProps) {
  const navigate = useNavigate();
  const [classificationPopupOpen, setClassificationPopupOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>('details');
  const [nestedIp, setNestedIp] = useState<string | null>(null);

  // Notes state
  const [noteText, setNoteText] = useState('');
  const [savedNote, setSavedNote] = useState<EntityNote | null>(null);
  const [noteSaving, setNoteSaving] = useState(false);
  const [noteDeleting, setNoteDeleting] = useState(false);

  // History state
  const [history, setHistory] = useState<EntityHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  // Determine entity type and key for notes/history
  const entityType: EntityType = node.data.isL2 ? 'DEVICE' : 'IP';
  const entityKey = node.data.isL2
    ? (node.data.mac ?? node.data.ip)
    : node.data.ip;

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

  // Load history when History tab is first opened
  useEffect(() => {
    if (activeTab !== 'history') return;
    if (history.length > 0 || historyLoading) return;
    setHistoryLoading(true);
    setHistoryError(null);
    entityNotesService
      .getHistory(entityType, entityKey)
      .then(entries => setHistory(entries))
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
  const initiatedCount = connectedEdges.filter(e => e.source === node.id).length;
  const receivedCount = connectedEdges.filter(e => e.target === node.id).length;

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

  const typeInfo = NODE_TYPE_CONFIG[node.data.nodeType] ?? NODE_TYPE_CONFIG['unknown'];

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
                  <div className="d-flex align-items-start gap-2 rounded p-2 mb-3 small" style={{ background: '#fff3cd', border: '1px solid #ffc10755' }}>
                    <i className="bi bi-slash-circle text-warning mt-1 flex-shrink-0" />
                    <div>
                      <span className="fw-semibold text-warning-emphasis">Phantom node</span>
                      <span className="text-muted ms-2">
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
                  </div>
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
                          <dd className="col-7 mb-1">{node.data.hostname}</dd>
                        </>
                      )}

                      <dt className="col-5 text-muted">Classification</dt>
                      <dd className="col-7 mb-1">
                        {(() => {
                          const isGeneric =
                            node.data.nodeType === 'client' || node.data.nodeType === 'unknown';
                          let badgeContent: React.ReactNode;
                          if (!isGeneric) {
                            badgeContent = (
                              <span className={`badge ${typeInfo.badgeClass}`}>{typeInfo.label}</span>
                            );
                          } else if (node.data.deviceType) {
                            badgeContent = (
                              <span
                                className="badge"
                                style={{
                                  backgroundColor: deviceTypeColor(node.data.deviceType),
                                  color: '#fff',
                                }}
                              >
                                {deviceTypeLabel(node.data.deviceType)}
                              </span>
                            );
                          } else {
                            badgeContent = (
                              <span className={`badge ${getRoleBadgeClass(node.data.role)}`}>
                                {node.data.role.charAt(0).toUpperCase() + node.data.role.slice(1)}
                              </span>
                            );
                          }
                          return (
                            <span
                              role="button"
                              title="Click for classification details"
                              style={{ cursor: 'pointer' }}
                              onClick={e => {
                                e.stopPropagation();
                                setClassificationPopupOpen(true);
                              }}
                            >
                              {badgeContent}
                            </span>
                          );
                        })()}
                      </dd>
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
                        {peers.map(([ip, info]) => (
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
                          <th>Capture Start</th>
                          <th className="text-end">Packets</th>
                          <th className="text-end">Bytes</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.map(entry => (
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
                              {entry.startTime
                                ? new Date(entry.startTime).toLocaleString()
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

      {classificationPopupOpen && (
        <NodeClassificationPopup
          info={{
            ip: node.data.ip,
            nodeType: node.data.nodeType,
            typeLabel: typeInfo.label,
            typeBadgeClass: typeInfo.badgeClass,
            typeEvidence: node.data.nodeTypeEvidence,
            role: node.data.role,
            initiated: initiatedCount,
            received: receivedCount,
            deviceType: node.data.deviceType,
            deviceConfidence: node.data.deviceConfidence,
            manufacturer: node.data.manufacturer,
            ttl: node.data.ttl,
          }}
          onClose={() => setClassificationPopupOpen(false)}
        />
      )}
    </div>
  );
}
