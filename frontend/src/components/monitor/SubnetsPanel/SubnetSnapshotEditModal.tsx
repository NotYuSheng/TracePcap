import { useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { insightsService } from '@/features/insights/services/insightsService';
import { subnetService } from '@/features/subnets/services/subnetService';
import type { NetworkSnapshot, SubnetOverrideInput } from '@/features/monitor/types/monitor.types';

interface SubnetSnapshotEditModalProps {
  subnetId: number;
  networkId: string;
  cidr: string;
  snapshot: NetworkSnapshot;
  onClose: () => void;
  /** Called after a successful save with the label that was set for this snapshot (or null). */
  onSaved: (label: string | null) => void;
}

/**
 * Per-snapshot subnet label editor (the subnet analog of {@link RoleEditModal}). Opened from a
 * Snapshot History row; sets this subnet's label/description *for that snapshot only* via a
 * snapshot subnet override, leaving the global definition and other snapshots untouched.
 */
export function SubnetSnapshotEditModal({ subnetId, networkId, cidr, snapshot, onClose, onSaved }: SubnetSnapshotEditModalProps) {
  const existing = (snapshot.subnetOverrides ?? []).find(o => o.cidr === cidr);
  const [label, setLabel] = useState(existing?.label ?? '');
  const [description, setDescription] = useState(existing?.description ?? '');
  const [saving, setSaving] = useState(false);
  const [suggesting, setSuggesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const suggest = async () => {
    setSuggesting(true);
    setError(null);
    try {
      // Scope the suggestion to THIS snapshot's traffic (per-snapshot AI, like the role editor).
      const s = await subnetService.suggestLabel(subnetId, networkId, snapshot.fileId);
      if (s.label) setLabel(s.label);
      if (s.description) setDescription(s.description);
    } catch (err: unknown) {
      const apiMsg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      setError(apiMsg ?? (err instanceof Error ? err.message : 'Suggestion failed. Check that the LLM server is reachable (LLM_BASE_URL).'));
    } finally {
      setSuggesting(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      // patchSnapshot replaces the whole override set, so merge this CIDR into the existing rows.
      const others: SubnetOverrideInput[] = (snapshot.subnetOverrides ?? [])
        .filter(o => o.cidr !== cidr)
        .map(o => ({ cidr: o.cidr, label: o.label, description: o.description, inherited: o.inherited }));
      const merged: SubnetOverrideInput[] = [
        ...others,
        { cidr, label: label.trim() || null, description: description.trim() || null, inherited: false },
      ];
      await insightsService.patchSnapshot(networkId, snapshot.id, { subnetOverrides: merged });
      onSaved(label.trim() || null);
      onClose();
    } catch {
      setError('Failed to save the per-snapshot label.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal show onHide={onClose} centered>
      <Modal.Header closeButton>
        <Modal.Title style={{ fontSize: '1rem' }}>
          Edit label for this snapshot
          <span className="text-muted fw-normal ms-2" style={{ fontSize: '0.8rem' }}>· {snapshot.fileName}</span>
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <p className="text-muted small mb-2">
          Sets <code className="font-monospace">{cidr}</code>'s label for this snapshot only. It
          overrides the present-day label here without changing the global definition or other
          snapshots. Leave blank to fall back to the global label.
        </p>
        {error && (
          <Alert variant="warning" className="p-2 mb-2 small d-flex align-items-start gap-2">
            <i className="bi bi-exclamation-triangle-fill mt-1 flex-shrink-0" /><span>{error}</span>
          </Alert>
        )}
        <Form.Label className="small mb-1">Label</Form.Label>
        <Form.Control
          size="sm"
          className="mb-2"
          placeholder="e.g. IoT sensor cluster"
          value={label}
          onChange={e => setLabel(e.target.value)}
          autoFocus
        />
        <Form.Label className="small mb-1">Description (optional)</Form.Label>
        <Form.Control
          as="textarea"
          size="sm"
          className="mb-2"
          rows={3}
          placeholder="What this subnet was in this snapshot"
          value={description}
          onChange={e => setDescription(e.target.value)}
        />
        <Button
          variant="outline-primary"
          size="sm"
          onClick={suggest}
          disabled={suggesting || saving}
          title="Ask the AI to infer this subnet's label from this snapshot's member behaviour"
        >
          {suggesting
            ? <><Spinner size="sm" className="me-1" />Suggesting…</>
            : <><i className="bi bi-stars me-1" />Suggest with AI</>}
        </Button>
      </Modal.Body>
      <Modal.Footer className="d-flex justify-content-end gap-2">
        <Button variant="outline-secondary" size="sm" onClick={onClose} disabled={saving}>Cancel</Button>
        <Button variant="primary" size="sm" onClick={save} disabled={saving}>
          {saving ? <><Spinner size="sm" className="me-1" />Saving…</> : 'Save'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
