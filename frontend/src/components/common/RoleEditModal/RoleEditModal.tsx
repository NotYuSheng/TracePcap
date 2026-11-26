import { SideDrawer } from '@components/common/SideDrawer';
import { useEffect, useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { PermissionLock } from '@components/common/PermissionLock';
import { usePermission } from '@/features/me/useMe';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { insightsService } from '@/features/insights/services/insightsService';
import type { EntityType } from '@/features/notes/services/entityNotesService';
import { aiJobsService } from '@/features/aiJobs/aiJobsService';
import { useAiJob } from '@/features/aiJobs/useAiJob';
import { AiJobStatus } from '@components/common/AiJobStatus/AiJobStatus';

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
  const [starting, setStarting] = useState(false);
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

  // The suggestion runs in the background (one job at a time for the model); the same job as the
  // host card's, so asking from both places doesn't ask twice.
  const previewJob = useAiJob<{ roleLabel?: string; roleDescription?: string }>('ROLE_PREVIEW', fileId, {
    onDone: s => {
      setLabel(s?.roleLabel ?? '');
      setDescription(s?.roleDescription ?? '');
    },
    onFailed: job => setError(job.error?.message || 'Suggestion failed.'),
  }, `${entityType}:${entityKey}`);
  const suggesting = starting || previewJob.active;

  const ai = usePermission('ASK_AI');
  const labels = usePermission('LABEL_HOSTS');
  const suggest = async () => {
    setStarting(true);
    setError(null);
    try {
      await previewJob.start(() => aiJobsService.startRoleSuggestion(fileId, entityType, entityKey, true));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Suggestion failed.');
    } finally {
      setStarting(false);
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
    <SideDrawer
      show
      onHide={onClose}
      title={<>Edit role
              {snapshotName && <span className="text-muted fw-normal ms-2" style={{ fontSize: '0.8rem' }}>· {snapshotName}</span>}</>}
      titleId="role-edit-title"
      footer={
        <>
          <div className="d-flex justify-content-between w-100">
            <div>
              {stale && hasRole && (
                <Button variant="outline-secondary" size="sm" onClick={dismiss} disabled={saving || !labels.allowed}>
                  <i className="bi bi-check-lg me-1" />Dismiss — still correct
                </Button>
              )}
            </div>
            <div className="d-flex gap-2">
              <Button variant="outline-secondary" size="sm" onClick={onClose} disabled={saving}>Cancel</Button>
              <PermissionLock action="LABEL_HOSTS" className="align-self-center" />
              <Button variant="primary" size="sm" onClick={save} disabled={saving || loading || !label.trim() || !labels.allowed}>
                {saving ? <><Spinner size="sm" className="me-1" />Saving…</> : 'Save'}
              </Button>
            </div>
          </div>
        </>
      }
    >
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
            disabled={suggesting || saving || !ai.allowed}
          >
            {suggesting
              ? <><Spinner size="sm" className="me-1" />Suggesting…</>
              : <><i className="bi bi-stars me-1" />Suggest with AI</>}
          </Button>
          <PermissionLock action="ASK_AI" className="ms-1 align-self-center" />
          {previewJob.active && previewJob.job && (
            <div className="mt-2">
              <AiJobStatus
                compact
                job={previewJob.job}
                doing="Suggesting a role"
                whenDone="You can close this; the suggestion fills in here when you're back."
                onCancel={() => { previewJob.cancel().catch(() => {}); }}
              />
            </div>
          )}
        </>
      )}
    </SideDrawer>
  );
}
