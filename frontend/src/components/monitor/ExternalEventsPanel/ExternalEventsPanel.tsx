import { useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { NetworkExternalEvent } from '@/features/insights/types/insights.types';

interface ExternalEventsPanelProps {
  events: NetworkExternalEvent[];
  onAdd: (eventTime: string, title: string, description?: string) => Promise<void>;
  onDelete: (eventId: string) => Promise<void>;
}

export const ExternalEventsPanel = ({ events, onAdd, onDelete }: ExternalEventsPanelProps) => {
  const [showForm, setShowForm] = useState(false);
  const [eventTime, setEventTime] = useState('');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const openForm = async () => {
    // Pre-fill with server time so the datetime reflects the deployment timezone
    try {
      const res = await apiClient.get<{ now: string }>(API_ENDPOINTS.SYSTEM_TIME);
      setEventTime(res.data.now);
    } catch {
      // Fallback to local time formatted for datetime-local input
      const now = new Date();
      const pad = (n: number) => String(n).padStart(2, '0');
      setEventTime(
        `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}:${pad(now.getMinutes())}`
      );
    }
    setShowForm(true);
  };

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !eventTime) return;
    setSaving(true);
    setError(null);
    try {
      await onAdd(eventTime, title.trim(), description.trim() || undefined);
      setEventTime('');
      setTitle('');
      setDescription('');
      setShowForm(false);
    } catch {
      setError('Failed to add event. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    setDeletingId(id);
    try {
      await onDelete(id);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div>
      {events.length === 0 && !showForm && (
        <p className="text-muted small mb-3">
          No external events recorded. Add real-world events (maintenance windows, incidents, etc.)
          to give the AI context when generating insights.
        </p>
      )}

      {events.length > 0 && (
        <div className="table-responsive mb-3">
          <table className="table table-sm mb-0">
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {events.map(ev => (
                <tr key={ev.id}>
                  <td className="text-nowrap small text-muted">
                    {new Date(ev.eventTime).toLocaleString()}
                  </td>
                  <td>
                    <div className="small fw-semibold">{ev.title}</div>
                    {ev.description && (
                      <div className="text-muted" style={{ fontSize: '0.75rem' }}>{ev.description}</div>
                    )}
                  </td>
                  <td>
                    <Button
                      size="sm"
                      variant="outline-danger"
                      onClick={() => handleDelete(ev.id)}
                      disabled={deletingId === ev.id}
                    >
                      {deletingId === ev.id
                        ? <Spinner animation="border" size="sm" />
                        : <i className="bi bi-trash" />
                      }
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showForm ? (
        <form onSubmit={handleAdd} className="border rounded p-3 bg-light">
          {error && <Alert variant="danger" className="py-2 small">{error}</Alert>}
          <div className="row g-2">
            <div className="col-sm-4">
              <Form.Label className="small fw-semibold">
                Date &amp; Time <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
                size="sm"
                type="datetime-local"
                value={eventTime}
                onChange={e => setEventTime(e.target.value)}
                required
              />
            </div>
            <div className="col-sm-8">
              <Form.Label className="small fw-semibold">
                Title <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="e.g. Water festival begins, Planned maintenance window"
                value={title}
                onChange={e => setTitle(e.target.value)}
                required
              />
            </div>
            <div className="col-12">
              <Form.Label className="small fw-semibold">Description (optional)</Form.Label>
              <Form.Control
                as="textarea"
                size="sm"
                rows={2}
                placeholder="Additional context…"
                value={description}
                onChange={e => setDescription(e.target.value)}
              />
            </div>
          </div>
          <div className="d-flex gap-2 mt-3">
            <Button size="sm" type="submit" variant="primary" disabled={saving || !title.trim() || !eventTime}>
              {saving ? <Spinner animation="border" size="sm" className="me-1" /> : null}
              Add Event
            </Button>
            <Button size="sm" variant="secondary" onClick={() => { setShowForm(false); setTitle(''); setDescription(''); }} disabled={saving}>
              Cancel
            </Button>
          </div>
        </form>
      ) : (
        <Button size="sm" variant="outline-primary" onClick={openForm}>
          <i className="bi bi-plus-lg me-1" />Add Event
        </Button>
      )}
    </div>
  );
};
