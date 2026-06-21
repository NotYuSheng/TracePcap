import { useEffect, useState } from 'react';
import { useEntityRole } from './hooks/useEntityRole';
import { useEntityStats } from './hooks/useEntityStats';
import { useEntityNote } from './hooks/useEntityNote';
import { useEntityHistory } from './hooks/useEntityHistory';
import { useHostClassification } from './hooks/useHostClassification';
import { useIpSnapshotHistory } from './hooks/useIpSnapshotHistory';
import { RoleSection } from './sections/RoleSection';
import { HostClassificationSection } from './sections/HostClassificationSection';
import { EntityStatsSection } from './sections/EntityStatsSection';
import { SnapshotHistoryTable } from './sections/SnapshotHistoryTable';
import { CaptureHistoryTable } from './sections/CaptureHistoryTable';
import { NotesTab } from './sections/NotesTab';
import type { EntityDetailModalProps, Tab } from './types';

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
  const [activeTab, setActiveTab] = useState<Tab>('details');
  const [nestedIp, setNestedIp] = useState<string | null>(null);

  const showRole = entityType === 'IP' || entityType === 'DEVICE';

  const role = useEntityRole(entityType, entityKey, fileId, showRole);
  const { stats, statsLoading, statsError } = useEntityStats(entityType, entityKey, fileId);
  const note = useEntityNote(entityType, entityKey);
  const { history, historyLoading, historyError } = useEntityHistory(entityType, entityKey);
  const hostClass = useHostClassification(entityType, entityKey, fileId);
  const { ipSnapHistory, ipHistoryLoading } = useIpSnapshotHistory(entityType, entityKey, snapshots);

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

  const hasFileStats = !!fileId && (entityType === 'APPLICATION' || entityType === 'PROTOCOL');
  const showSnapshotHistory = entityType === 'IP' && !!snapshots && snapshots.length > 0;

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
                        {note.savedNote && (
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
                {showRole && <RoleSection fileId={fileId} role={role} />}

                {entityType === 'IP' && hostClass && (
                  <HostClassificationSection hostClass={hostClass} />
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
                {!showRole && !hasFileStats && (
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

                {showSnapshotHistory ? (
                  <SnapshotHistoryTable ipSnapHistory={ipSnapHistory} ipHistoryLoading={ipHistoryLoading} />
                ) : (
                  <CaptureHistoryTable
                    history={history}
                    historyLoading={historyLoading}
                    historyError={historyError}
                    onClose={onClose}
                  />
                )}
              </div>
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
