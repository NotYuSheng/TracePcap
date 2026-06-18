import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect } from 'react';
import { Alert, Button, Form, Modal } from '@govtechsg/sgds-react';

interface EditNetworkModalProps {
  show: boolean;
  onHide: () => void;
  initialName: string;
  initialDescription: string | null;
  onSave: (name: string, description: string) => Promise<void>;
}

export const EditNetworkModal = ({
  show,
  onHide,
  initialName,
  initialDescription,
  onSave,
}: EditNetworkModalProps) => {
  const [name, setName] = useState(initialName);
  const [description, setDescription] = useState(initialDescription ?? '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (show) {
      setName(initialName);
      setDescription(initialDescription ?? '');
      setError(null);
    }
  }, [show, initialName, initialDescription]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await onSave(name.trim(), description.trim());
      onHide();
    } catch {
      setError('Failed to save changes. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleHide = () => {
    if (saving) return;
    onHide();
  };

  return (
    <Modal show={show} onHide={handleHide}>
      <Modal.Header closeButton>
        <Modal.Title>Edit Network</Modal.Title>
      </Modal.Header>
      <form onSubmit={handleSubmit}>
        <Modal.Body>
          {error && <Alert variant="danger" className="py-2">{error}</Alert>}
          <Form.Group className="mb-3">
            <Form.Label className="fw-semibold" htmlFor="edit-network-name">
              Name <span className="text-danger">*</span>
            </Form.Label>
            <Form.Control
              id="edit-network-name"
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              maxLength={255}
              required
              autoFocus
            />
          </Form.Group>
          <Form.Group className="mb-3">
            <Form.Label className="fw-semibold" htmlFor="edit-network-desc">
              Description
            </Form.Label>
            <Form.Control
              id="edit-network-desc"
              as="textarea"
              rows={3}
              placeholder="Optional description of this network segment"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
          </Form.Group>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={handleHide} disabled={saving}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={saving || !name.trim()}>
            {saving ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" />
                Saving…
              </>
            ) : (
              'Save Changes'
            )}
          </Button>
        </Modal.Footer>
      </form>
    </Modal>
  );
};
