import { useEffect, useState } from 'react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { insightsService } from '@/features/insights/services/insightsService';
import type { EntityType } from '@/features/notes/services/entityNotesService';

interface RoleEditModalProps {
  entityType: EntityType;
  entityKey: string;
  /** The snapshot's file this role applies to. */
  fileId: string;
  /** Context label shown in the header, e.g. the snapshot file name. */
  snapshotName?: string;
  onClose: () => void;
  /** Called after a successful save/dismiss so the parent can refetch. */
  onSaved: () => void;
  zIndex?: number;
}

/**
 * Per-snapshot role editor (#369). Opened from a Snapshot History row's Edit action; edits the role
 * for that specific snapshot (applying from that snapshot forward), with an AI suggestion that reads
 * the snapshot's own traffic.
 */
export function RoleEditModal({
  entityType,
  entityKey,
  fileId,
  snapshotName,
  onClose,
  onSaved,
  zIndex,
}: RoleEditModalProps) {
  const [label, setLabel] = useState('');
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [suggesting, setSuggesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);
  const [hasRole, setHasRole] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    insightsService
      .getNodeRole(entityType, entityKey, fileId)
      .then(r => {
        if (!active) return;
        setLabel(r?.roleLabel ?? '');
        setDescription(r?.roleDescription ?? '');
        setStale(!!r?.staleSince);
        setHasRole(!!r);
      })
      .catch(() => {})
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [entityType, entityKey, fileId]);

  const suggest = async () => {
    setSuggesting(true);
    setError(null);
    try {
      const s = await insightsService.suggestNodeRolePreview(entityType, entityKey, fileId);
      setLabel(s.roleLabel ?? '');
      setDescription(s.roleDescription ?? '');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Suggestion failed.');
    } finally {
      setSuggesting(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await insightsService.upsertNodeRole(entityType, entityKey, label, description, true, fileId);
      onSaved();
      onClose();
    } catch {
      setError('Failed to save role.');
    } finally {
      setSaving(false);
    }
  };

  const dismiss = async () => {
    setSaving(true);
    setError(null);
    try {
      await insightsService.dismissNodeRoleStaleness(entityType, entityKey, fileId);
      onSaved();
      onClose();
    } catch {
      setError('Failed to dismiss.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="modal fade show d-block"
      style={{ backgroundColor: 'rgba(0,0,0,0.5)', zIndex: zIndex ?? 1200 }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
      role="dialog"
      aria-modal="true"
    >
      <div className="modal-dialog modal-dialog-centered">
        <div className="modal-content">
          <div className="modal-header py-2">
            <h6 className="modal-title mb-0">
              Edit role
              {snapshotName && <span className="text-muted fw-normal ms-2" style={{ fontSize: '0.8rem' }}>· {snapshotName}</span>}
            </h6>
            <button type="button" className="btn-close" onClick={onClose} />
          </div>
          <div className="modal-body">
            <p className="text-muted small">
              Sets the role for <code>{entityKey}</code> in this snapshot; it carries forward to later snapshots.
            </p>
            {loading ? (
              <div className="text-muted small py-2"><Spinner size="sm" className="me-2" />Loading…</div>
            ) : (
              <>
                {stale && (
                  <Alert variant="warning" className="p-2 mb-2 small">
                    This label was flagged stale in this snapshot. Update it, or dismiss to accept the current behaviour.
                  </Alert>
                )}
                {error && (
                  <Alert variant="warning" className="p-2 mb-2 small d-flex align-items-start gap-2">
                    <i className="bi bi-exclamation-triangle-fill mt-1 flex-shrink-0" /><span>{error}</span>
                  </Alert>
                )}
                <label className="form-label small mb-1">Role label</label>
                <input
                  className="form-control form-control-sm mb-2"
                  placeholder="e.g. File Server (SMB)"
                  value={label}
                  onChange={e => setLabel(e.target.value)}
                  autoFocus
                />
                <label className="form-label small mb-1">Description (optional)</label>
                <textarea
                  className="form-control form-control-sm mb-2"
                  rows={2}
                  placeholder="Short description of what this host does"
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                />
                <button
                  className="btn btn-outline-primary btn-sm"
                  onClick={suggest}
                  disabled={suggesting || saving}
                  title="Ask the AI to classify this node from this snapshot's traffic"
                >
                  {suggesting
                    ? <><Spinner size="sm" className="me-1" />Suggesting…</>
                    : <><i className="bi bi-stars me-1" />Suggest with AI</>}
                </button>
              </>
            )}
          </div>
          <div className="modal-footer py-2 d-flex justify-content-between">
            <div>
              {stale && hasRole && (
                <button className="btn btn-outline-secondary btn-sm" onClick={dismiss} disabled={saving}>
                  <i className="bi bi-check-lg me-1" />Dismiss — still correct
                </button>
              )}
            </div>
            <div className="d-flex gap-2">
              <button className="btn btn-outline-secondary btn-sm" onClick={onClose} disabled={saving}>Cancel</button>
              <button className="btn btn-primary btn-sm" onClick={save} disabled={saving || loading || !label.trim()}>
                {saving ? <><Spinner size="sm" className="me-1" />Saving…</> : 'Save'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
