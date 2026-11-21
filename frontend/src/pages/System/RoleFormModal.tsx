import { useEffect, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { env } from '@/config/env';
import type { Role } from '@/features/me/meService';

/** A Keycloak-friendly role name from a display name: "Incident responder" → "incident-responder". */
function keyFromLabel(label: string): string {
  return label
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[^a-z0-9]+|-+$/g, '');
}

const KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export interface RoleFormValues {
  key: string;
  label: string;
  description: string;
  copyFrom: string;
}

interface Props {
  show: boolean;
  /** The custom role being edited; absent when creating one. */
  editing?: Role;
  roles: Role[];
  onHide: () => void;
  onSubmit: (values: RoleFormValues) => Promise<void>;
}

/**
 * Create a custom role, or rename one. Its Keycloak name is fixed once created: it's what Keycloak
 * assigns, so changing it would silently take the role away from everyone who has it.
 */
export function RoleFormModal({ show, editing, roles, onHide, onSubmit }: Props) {
  const [label, setLabel] = useState('');
  const [key, setKey] = useState('');
  const [keyTouched, setKeyTouched] = useState(false);
  const [description, setDescription] = useState('');
  const [copyFrom, setCopyFrom] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!show) return;
    setLabel(editing?.label ?? '');
    setKey(editing?.key ?? '');
    setKeyTouched(!!editing);
    setDescription(editing?.description ?? '');
    setCopyFrom('');
    setError(null);
  }, [show, editing]);

  const effectiveKey = keyTouched ? key : keyFromLabel(label);
  const taken = !editing && roles.some(r => r.key === effectiveKey);
  const keyInvalid = !editing && effectiveKey !== '' && !KEY_PATTERN.test(effectiveKey);
  const canSave = label.trim() !== '' && effectiveKey !== '' && !taken && !keyInvalid && !saving;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSave) return;
    setSaving(true);
    setError(null);
    try {
      await onSubmit({
        key: effectiveKey,
        label: label.trim(),
        description: description.trim(),
        copyFrom,
      });
      onHide();
    } catch (err) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      setError(msg ?? "Couldn't save the role. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal show={show} onHide={saving ? () => undefined : onHide} centered>
      <Form onSubmit={submit}>
        <Modal.Header closeButton>
          <Modal.Title>{editing ? `Edit ${editing.label}` : 'New role'}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form.Group className="mb-3" controlId="role-label">
            <Form.Label>Name</Form.Label>
            <Form.Control
              value={label}
              maxLength={60}
              autoFocus
              placeholder="Incident responder"
              onChange={e => setLabel(e.target.value)}
            />
          </Form.Group>
          <Form.Group className="mb-3" controlId="role-key">
            <Form.Label>Keycloak client role</Form.Label>
            <Form.Control
              className="font-monospace"
              value={effectiveKey}
              maxLength={100}
              disabled={!!editing}
              isInvalid={taken || keyInvalid}
              onChange={e => {
                setKeyTouched(true);
                setKey(e.target.value.trim());
              }}
            />
            <Form.Control.Feedback type="invalid">
              {taken
                ? 'There is already a role with this name.'
                : "Letters, digits, '-', '_' and '.' only, starting with a letter or digit."}
            </Form.Control.Feedback>
            <Form.Text>
              {editing ? (
                "Can't change: it's what Keycloak assigns. To use another name, create a new role."
              ) : (
                <>
                  Someone has this role when Keycloak gives them the client role of this name on{' '}
                  <code>{env.OIDC_CLIENT_ID}</code>. Your identity team creates it there and assigns
                  it to groups.
                </>
              )}
            </Form.Text>
          </Form.Group>
          <Form.Group className="mb-3" controlId="role-description">
            <Form.Label>Description</Form.Label>
            <Form.Control
              as="textarea"
              rows={2}
              maxLength={255}
              value={description}
              placeholder="Who it's for and what they do"
              onChange={e => setDescription(e.target.value)}
            />
          </Form.Group>
          {!editing && (
            <Form.Group controlId="role-copy-from">
              <Form.Label>Start from</Form.Label>
              <Form.Select value={copyFrom} onChange={e => setCopyFrom(e.target.value)}>
                <option value="">Nothing: seeing captures only</option>
                {roles.map(r => (
                  <option key={r.key} value={r.key}>
                    {r.label}'s permissions
                  </option>
                ))}
              </Form.Select>
              <Form.Text>You can change any permission afterwards.</Form.Text>
            </Form.Group>
          )}
          {error && (
            <Alert variant="danger" className="py-2 mt-3 mb-0 small">
              {error}
            </Alert>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button type="button" variant="outline-secondary" onClick={onHide} disabled={saving}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={!canSave}>
            {saving && <Spinner animation="border" size="sm" className="me-1" />}
            {editing ? 'Save' : 'Create role'}
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
}
