import { useState } from 'react';
import { Modal } from '@govtechsg/sgds-react';

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
          {error && <div className="alert alert-danger py-2">{error}</div>}
          <div className="mb-3">
            <label className="form-label fw-semibold" htmlFor="network-name">
              Name <span className="text-danger">*</span>
            </label>
            <input
              id="network-name"
              type="text"
              className="form-control"
              placeholder="e.g. Office LAN, OT Segment A"
              value={name}
              onChange={e => setName(e.target.value)}
              maxLength={255}
              required
              autoFocus
            />
          </div>
          <div className="mb-3">
            <label className="form-label fw-semibold" htmlFor="network-desc">
              Description
            </label>
            <textarea
              id="network-desc"
              className="form-control"
              rows={3}
              placeholder="Optional description of this network segment"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
          </div>
        </Modal.Body>
        <Modal.Footer>
          <button type="button" className="btn btn-secondary" onClick={handleHide} disabled={saving}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={saving || !name.trim()}>
            {saving ? (
              <>
                <span className="spinner-border spinner-border-sm me-2" />
                Creating…
              </>
            ) : (
              'Create Network'
            )}
          </button>
        </Modal.Footer>
      </form>
    </Modal>
  );
};
