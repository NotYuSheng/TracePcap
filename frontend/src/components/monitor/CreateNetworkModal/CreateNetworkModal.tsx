import { Spinner } from '@components/common/Spinner/Spinner';
import { SideDrawer } from '@components/common/SideDrawer';
import { useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';

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
    <SideDrawer
      show={show}
      onHide={handleHide}
      title="New network"
      titleId="create-network-title"
      footer={
        <>
          <Button variant="secondary" onClick={handleHide} disabled={saving}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="create-network-form"
            variant="primary"
            disabled={saving || !name.trim()}
          >
            {saving ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" />
                Creating…
              </>
            ) : (
              'Create network'
            )}
          </Button>
        </>
      }
    >
      <form id="create-network-form" onSubmit={handleSubmit}>
        <div>
          {error && (
            <Alert variant="danger" className="py-2">
              {error}
            </Alert>
          )}
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
        </div>
      </form>
    </SideDrawer>
  );
};
