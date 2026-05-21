import { Spinner } from '@components/common/Spinner/Spinner';
import { useState } from 'react';
import { Alert, Button, Form, Modal } from '@govtechsg/sgds-react';

interface CreateNetworkModalProps {
  show: boolean;
  onHide: () => void;
  onCreate: (name: string, description: string) => Promise<void>;
}

export const CreateNetworkModal = ({ show, onHide, onCreate }: CreateNetworkModalProps) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await onCreate(name.trim(), description.trim());
      setName('');
      setDescription('');
      onHide();
    } catch {
      setError('Failed to create network. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleHide = () => {
    if (saving) return;
    setName('');
    setDescription('');
    setError(null);
    onHide();
  };

  return (
    <Modal show={show} onHide={handleHide}>
      <Modal.Header closeButton>
        <Modal.Title>Create Network</Modal.Title>
      </Modal.Header>
      <form onSubmit={handleSubmit}>
        <Modal.Body>
          {error && <Alert variant="danger" className="py-2">{error}</Alert>}
          <Form.Group className="mb-3">
            <Form.Label className="fw-semibold" htmlFor="network-name">
              Name <span className="text-danger">*</span>
            </Form.Label>
            <Form.Control
              id="network-name"
              type="text"
              placeholder="e.g. Office LAN, OT Segment A"
              value={name}
              onChange={e => setName(e.target.value)}
              maxLength={255}
              required
              autoFocus
            />
          </Form.Group>
          <Form.Group className="mb-3">
            <Form.Label className="fw-semibold" htmlFor="network-desc">
              Description
            </Form.Label>
            <Form.Control
              id="network-desc"
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
                Creating…
              </>
            ) : (
              'Create Network'
            )}
          </Button>
        </Modal.Footer>
      </form>
    </Modal>
  );
};
