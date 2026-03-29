import { useState, useEffect } from 'react';
import { Modal } from '@govtechsg/sgds-react';
import { apiClient } from '@/services/api/client';

interface SignaturesModalProps {
  show: boolean;
  onHide: () => void;
}

export function SignaturesModal({ show, onHide }: SignaturesModalProps) {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!show) return;
    setLoading(true);
    setError(null);
    setSaved(false);
    apiClient
      .get<{ content: string }>('/signatures')
      .then(r => setContent(r.data.content))
      .catch(() => setError('Failed to load signatures file.'))
      .finally(() => setLoading(false));
  }, [show]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const res = await apiClient.put<{ status?: string; error?: string }>('/signatures', {
        content,
      });
      if (res.data.error) {
        setError(res.data.error);
      } else {
        setSaved(true);
      }
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error?: string } } };
      setError(axiosErr?.response?.data?.error ?? 'Failed to save signatures file.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal show={show} onHide={onHide} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>
          <i className="bi bi-shield-check me-2"></i>Custom Detection Rules
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <p className="text-muted small mb-3">
          Edit <code>signatures.yml</code> to define custom detection rules. Matched rules appear as
          risk flags alongside nDPI's built-in detections. Changes take effect on the next file
          analysis — no restart required.
        </p>

        {loading ? (
          <div className="text-center py-4 text-muted">
            <div className="spinner-border spinner-border-sm me-2" role="status" />
            Loading…
          </div>
        ) : (
          <textarea
            className="form-control font-monospace"
            rows={20}
            value={content}
            onChange={e => {
              setContent(e.target.value);
              setSaved(false);
            }}
            spellCheck={false}
            style={{ fontSize: '0.82rem', resize: 'vertical' }}
          />
        )}

        {error && <div className="alert alert-danger mt-2 py-2 small mb-0">{error}</div>}
        {saved && (
          <div className="alert alert-success mt-2 py-2 small mb-0">
            <i className="bi bi-check-circle me-1"></i>Saved — rules will apply on the next
            analysis.
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <button type="button" className="btn btn-outline-secondary" onClick={onHide}>
          Close
        </button>
        <button
          type="button"
          className="btn btn-primary"
          onClick={handleSave}
          disabled={loading || saving}
        >
          {saving ? (
            <>
              <span className="spinner-border spinner-border-sm me-1" role="status" />
              Saving…
            </>
          ) : (
            <>
              <i className="bi bi-floppy me-1"></i>Save
            </>
          )}
        </button>
      </Modal.Footer>
    </Modal>
  );
}
