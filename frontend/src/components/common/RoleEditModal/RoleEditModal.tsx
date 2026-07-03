import { useEffect, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
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
    <Modal show onHide={onClose} centered>
      <Modal.Header closeButton>
        <Modal.Title style={{ fontSize: '1rem' }}>
          Edit role
          {snapshotName && <span className="text-muted fw-normal ms-2" style={{ fontSize: '0.8rem' }}>· {snapshotName}</span>}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <p className="text-muted small mb-2">
          Sets the role for <code>{entityKey}</code> from this snapshot onward — it applies to this
          snapshot and <strong>carries forward</strong> to later ones. <strong>Earlier snapshots are
          not changed.</strong> To label the whole timeline, edit the first snapshot the entity
          appears in.
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
            <Form.Label className="small mb-1">Role label</Form.Label>
            <Form.Control
              size="sm"
              className="mb-2"
              placeholder="e.g. File Server (SMB)"
              value={label}
              onChange={e => setLabel(e.target.value)}
              autoFocus
            />
            <Form.Label className="small mb-1">Description (optional)</Form.Label>
            <Form.Control
              as="textarea"
              size="sm"
              className="mb-2"
              rows={2}
              placeholder="Short description of what this host does"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
            <Button
              variant="outline-primary"
              size="sm"
              onClick={suggest}
              disabled={suggesting || saving}
              title="Ask the AI to classify this node from this snapshot's traffic"
            >
              {suggesting
                ? <><Spinner size="sm" className="me-1" />Suggesting…</>
                : <><i className="bi bi-stars me-1" />Suggest with AI</>}
            </Button>
          </>
        )}
      </Modal.Body>
      <Modal.Footer className="d-flex justify-content-between">
        <div>
          {stale && hasRole && (
            <Button variant="outline-secondary" size="sm" onClick={dismiss} disabled={saving}>
              <i className="bi bi-check-lg me-1" />Dismiss — still correct
            </Button>
          )}
        </div>
        <div className="d-flex gap-2">
          <Button variant="outline-secondary" size="sm" onClick={onClose} disabled={saving}>Cancel</Button>
          <Button variant="primary" size="sm" onClick={save} disabled={saving || loading || !label.trim()}>
            {saving ? <><Spinner size="sm" className="me-1" />Saving…</> : 'Save'}
          </Button>
        </div>
      </Modal.Footer>
    </Modal>
  );
}
