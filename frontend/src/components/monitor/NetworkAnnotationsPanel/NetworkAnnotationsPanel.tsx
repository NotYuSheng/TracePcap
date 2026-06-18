import { useState } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import type { NetworkAnnotation } from '@/features/insights/types/insights.types';

interface NetworkAnnotationsPanelProps {
  annotations: NetworkAnnotation[];
  onAdd: (body: string) => Promise<void>;
  onUpdate: (annotationId: string, body: string) => Promise<void>;
  onDelete: (annotationId: string) => Promise<void>;
}

function AnnotationRow({
  annotation,
  onUpdate,
  onDelete,
}: {
  annotation: NetworkAnnotation;
  onUpdate: (id: string, body: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(annotation.body);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleSave = async () => {
    if (!draft.trim()) return;
    setSaving(true);
    try {
      await onUpdate(annotation.id, draft.trim());
      setEditing(false);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await onDelete(annotation.id);
    } finally {
      setDeleting(false);
    }
  };

  if (editing) {
    return (
      <div className="border rounded p-2 mb-2 bg-light">
        <textarea
          className="form-control form-control-sm mb-2"
          rows={3}
          value={draft}
          onChange={e => setDraft(e.target.value)}
          autoFocus
        />
        <div className="d-flex gap-2">
          <Button size="sm" variant="primary" onClick={handleSave} disabled={saving || !draft.trim()}>
            {saving ? <Spinner animation="border" size="sm" className="me-1" /> : null}
            Save
          </Button>
          <Button size="sm" variant="outline-secondary" onClick={() => { setEditing(false); setDraft(annotation.body); }} disabled={saving}>
            Cancel
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="d-flex justify-content-between align-items-start border rounded p-2 mb-2 bg-light">
      <div style={{ flex: 1 }}>
        <div className="small" style={{ whiteSpace: 'pre-wrap' }}>{annotation.body}</div>
        <div className="text-muted mt-1" style={{ fontSize: '0.7rem' }}>
          {new Date(annotation.createdAt).toLocaleString()}
          {annotation.updatedAt !== annotation.createdAt && ' (edited)'}
        </div>
      </div>
      <div className="d-flex gap-1 ms-2 flex-shrink-0">
        <Button size="sm" variant="outline-secondary" onClick={() => setEditing(true)}>
          <i className="bi bi-pencil" />
        </Button>
        <Button size="sm" variant="outline-danger" onClick={handleDelete} disabled={deleting}>
          {deleting ? <Spinner animation="border" size="sm" /> : <i className="bi bi-trash" />}
        </Button>
      </div>
    </div>
  );
}

export const NetworkAnnotationsPanel = ({
  annotations,
  onAdd,
  onUpdate,
  onDelete,
}: NetworkAnnotationsPanelProps) => {
  const [body, setBody] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!body.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await onAdd(body.trim());
      setBody('');
    } catch {
      setError('Failed to save annotation. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      {annotations.length === 0 && (
        <p className="text-muted small mb-3">
          No annotations yet. Add analyst notes — they will be fed to the AI as context when
          generating insights.
        </p>
      )}

      {annotations.length > 0 && (
        <div className="mb-3">
          {annotations.map(a => (
            <AnnotationRow
              key={a.id}
              annotation={a}
              onUpdate={onUpdate}
              onDelete={onDelete}
            />
          ))}
        </div>
      )}

      <form onSubmit={handleAdd}>
        {error && <Alert variant="danger" className="py-2 small">{error}</Alert>}
        <textarea
          className="form-control form-control-sm mb-2"
          rows={3}
          placeholder="Write an analyst annotation… (e.g. 'New PLC installed on 192.168.1.45 during maintenance window')"
          value={body}
          onChange={e => setBody(e.target.value)}
        />
        <Button size="sm" type="submit" variant="outline-primary" disabled={saving || !body.trim()}>
          {saving ? <Spinner animation="border" size="sm" className="me-1" /> : null}
          Add Annotation
        </Button>
      </form>
    </div>
  );
};
