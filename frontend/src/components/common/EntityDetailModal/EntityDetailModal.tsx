import { useEffect, useRef, useState } from 'react';
import { useEscapeLayer } from '@utils/useEscapeLayer';
import { useEntityRole } from './hooks/useEntityRole';
import { useEntityStats } from './hooks/useEntityStats';
import { useEntityNote } from './hooks/useEntityNote';
import { useEntityHistory } from './hooks/useEntityHistory';
import { useIpSnapshotHistory } from './hooks/useIpSnapshotHistory';
import { RoleSection } from './sections/RoleSection';
import { HostIdentitySection } from '@components/common/HostIdentitySection';
import { EntityStatsSection } from './sections/EntityStatsSection';
import { SnapshotHistoryTable } from './sections/SnapshotHistoryTable';
import { CaptureHistoryTable } from './sections/CaptureHistoryTable';
import { NotesTab } from './sections/NotesTab';
import { GraphNodeDetailsSection } from './sections/GraphNodeDetailsSection';
import { GraphHistoryTab } from './sections/GraphHistoryTab';
import { ServiceLogTab } from '@components/network/ServiceLogTab/ServiceLogTab';
import { getServiceTab, type ServiceTabConfig } from '@/features/network/serviceTabs';
import type { EntityDetailModalProps, Tab } from './types';
import './EntityDetailModal.css';

export function EntityDetailModal({
  entityType,
  entityKey,
  displayName,
  fileId,
  badge,
  isActive,
  lastSeenTime,
  lastSeenFileName,
  onViewConversations,
  snapshots,
  onClose,
  zIndex,
  graphNode,
  graphEdges,
  changeHighlight,
  onNavigate,
}: EntityDetailModalProps) {
  const [activeTab, setActiveTab] = useState<Tab>('details');
  const [nestedIp, setNestedIp] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  const showRole = entityType === 'IP' || entityType === 'DEVICE';

  // Graph context (#578): when a node is supplied, the modal renders the network-graph host detail —
  // traffic counters + Connections table + a History tab + service-role log tabs.
  const isGraph = !!graphNode;
  const serviceTabs: ServiceTabConfig<unknown, unknown>[] = isGraph
    ? (graphNode!.data.serviceRoles ?? [])
        .map(getServiceTab)
        .filter((t): t is ServiceTabConfig<unknown, unknown> => Boolean(t))
    : [];
  const activeServiceTab = serviceTabs.find(t => `svc:${t.role}` === activeTab);
  // A peer/history navigation: route via the caller, then close (the graph is behind this modal).
  const navigateAndClose = (path: string) => { onClose(); onNavigate?.(path); };

  const role = useEntityRole(entityType, entityKey, fileId, showRole);
  const { stats, statsLoading, statsError } = useEntityStats(entityType, entityKey, fileId);
  const note = useEntityNote(entityType, entityKey);
  const { history, historyLoading, historyError } = useEntityHistory(entityType, entityKey);
  const { ipSnapHistory, ipHistoryLoading, reload: reloadIpHistory } = useIpSnapshotHistory(entityType, entityKey, snapshots);

  // ESC closes this panel — but only while it is the topmost layer. The shared stack defers to a
  // nested EntityDetailModal (registered after this one) and to any SGDS modal opened from inside
  // it (role help, evidence explainer, add evidence), which stack above via `tp-nested-modal`.
  useEscapeLayer(onClose, { ref: dialogRef });

  // Lock background scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, []);

  // If the active service tab is no longer offered (modal reused for a node without that role),
  // fall back to Details so the body never goes blank.
  useEffect(() => {
    const isBaseTab = activeTab === 'details' || activeTab === 'notes' || activeTab === 'history';
    if (!isBaseTab && !activeServiceTab) setActiveTab('details');
  }, [activeTab, activeServiceTab]);

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
    const parsedTime = lastSeenTime ? new Date(lastSeenTime).getTime() : null;
    const days = parsedTime !== null && !Number.isNaN(parsedTime)
      ? Math.floor((Date.now() - parsedTime) / 86400000)
      : null;
    const agoText = days != null && days > 0 ? ` · ${days}d ago` : '';
    const tooltip = lastSeenFileName ? `Last seen in ${lastSeenFileName}` : undefined;
    return (
      <span className="badge bg-secondary ms-2 d-inline-flex align-items-center" style={{ fontSize: '0.7rem', gap: '0.5rem' }} title={tooltip}>
        <span>Inactive{agoText}</span>
        {lastSeenFileName && (
          <span className="fw-normal opacity-75 ps-2 border-start border-light border-opacity-50">
            <i className="bi bi-camera-reels me-1"></i>{lastSeenFileName}
          </span>
        )}
      </span>
    );
  })() : null;

  const hasFileStats = !!fileId && (entityType === 'APPLICATION' || entityType === 'PROTOCOL');
  const showSnapshotHistory =
    (entityType === 'IP' || entityType === 'DEVICE') && !!snapshots && snapshots.length > 0;

  return (
    <>
    <div
      ref={dialogRef}
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

          {/* Tabs — graph context adds a History tab (cross-capture role trail) and service-role tabs. */}
          <div className="modal-header py-0 border-bottom-0">
            <ul className="nav nav-pills gap-1" style={{ paddingTop: '4px', paddingBottom: '4px' }}>
              {((isGraph ? ['details', 'history', 'notes'] : ['details', 'notes']) as Tab[]).map(tab => (
                <li key={tab} className="nav-item">
                  <button
                    className={`nav-link py-1 px-3${activeTab === tab ? ' active' : ''}`}
                    style={{ fontSize: '0.875rem' }}
                    onClick={() => setActiveTab(tab)}
                  >
                    {tab === 'details' && <i className="bi bi-bar-chart me-1" />}
                    {tab === 'history' && <i className="bi bi-clock-history me-1" />}
                    {tab === 'notes' && (
                      <>
                        <i className="bi bi-sticky me-1" />
                        {note.savedNote && (
                          <span className="badge bg-warning text-dark ms-1" style={{ fontSize: '0.6rem' }}>1</span>
                        )}
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

            {/* ── DETAILS TAB ──────────────────────────────────────── */}
            {activeTab === 'details' && (
              <div>
                {/* Change-event highlight banner (Monitor snapshot / Compare diff). */}
                {changeHighlight && (
                  <div
                    className="d-flex align-items-center gap-2 rounded p-2 mb-3 small"
                    style={{ background: changeHighlight.color + '22', border: `1px solid ${changeHighlight.color}55` }}
                  >
                    <span style={{ width: 10, height: 10, borderRadius: '50%', background: changeHighlight.color, flexShrink: 0, display: 'inline-block' }} />
                    <span style={{ color: changeHighlight.color, fontWeight: 600 }}>{changeHighlight.label}</span>
                    {changeHighlight.description && <span className="text-muted">— {changeHighlight.description}</span>}
                  </div>
                )}

                {/* Multi-snapshot context: role is edited per-snapshot in the history table below,
                    so the top card is a read-only present-day summary. */}
                {showRole && <RoleSection fileId={fileId} role={role} readOnly={showSnapshotHistory} raisedModal={zIndex != null} />}

                {entityType === 'IP' && fileId && (
                  <HostIdentitySection fileId={fileId} ip={entityKey} zIndex={zIndex} />
                )}

                {/* Graph host detail: traffic counters, protocol chips, per-peer Connections table. */}
                {isGraph && !graphNode!.data.isL2 && graphEdges && (
                  <GraphNodeDetailsSection
                    node={graphNode!}
                    edges={graphEdges}
                    fileId={fileId}
                    onOpenPeer={setNestedIp}
                    onNavigate={navigateAndClose}
                  />
                )}

                {hasFileStats && (
                  <EntityStatsSection
                    stats={stats}
                    statsLoading={statsLoading}
                    statsError={statsError}
                    onSelectPeer={setNestedIp}
                  />
                )}

                {/* Fallback for entity types without file stats and no role section */}
                {!showRole && !hasFileStats && !isGraph && (
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

                {/* Cross-capture history: the graph surface has its own tab for it (role trail), so
                    only the non-graph entity panel renders it inline here. */}
                {!isGraph && (showSnapshotHistory ? (
                  <SnapshotHistoryTable
                    entityType={entityType}
                    entityKey={entityKey}
                    ipSnapHistory={ipSnapHistory}
                    ipHistoryLoading={ipHistoryLoading}
                    onRoleChanged={() => { reloadIpHistory(); role.reload(); }}
                  />
                ) : (
                  <CaptureHistoryTable
                    history={history}
                    historyLoading={historyLoading}
                    historyError={historyError}
                    onClose={onClose}
                  />
                ))}
              </div>
            )}

            {/* ── HISTORY TAB (graph context only) ─────────────────── */}
            {activeTab === 'history' && isGraph && (
              <GraphHistoryTab
                entityType={entityType}
                entityKey={entityKey}
                fileId={fileId}
                onNavigate={navigateAndClose}
              />
            )}

            {/* ── SERVICE-ROLE TAB (DNS, …) ────────────────────────── */}
            {activeServiceTab && graphNode && (
              <ServiceLogTab fileId={fileId} ip={graphNode.data.ip} config={activeServiceTab} />
            )}

            {/* ── NOTES TAB ────────────────────────────────────────── */}
            {activeTab === 'notes' && (
              <NotesTab
                entityLabel={entityLabel}
                displayName={displayName}
                noteText={note.noteText}
                setNoteText={note.setNoteText}
                savedNote={note.savedNote}
                noteSaving={note.noteSaving}
                noteDeleting={note.noteDeleting}
                noteChanged={note.noteChanged}
                onSave={note.save}
                onDelete={note.remove}
              />
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
