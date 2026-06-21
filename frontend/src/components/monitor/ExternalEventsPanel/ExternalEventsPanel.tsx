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
  onUpdate: (eventId: string, eventTime: string, title: string, description?: string) => Promise<void>;
  onDelete: (eventId: string) => Promise<void>;
}

/** Convert an ISO/Date-parseable string to a value for an <input type="datetime-local">. */
const toInputValue = (value: string): string => {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

export const ExternalEventsPanel = ({ events, onAdd, onUpdate, onDelete }: ExternalEventsPanelProps) => {
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [eventTime, setEventTime] = useState('');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const resetForm = () => {
    setEditingId(null);
    setEventTime('');
    setTitle('');
    setDescription('');
    setError(null);
    setShowForm(false);
  };

  const openAddForm = async () => {
    setEditingId(null);
    setTitle('');
    setDescription('');
    setError(null);
    // Pre-fill with server time so the datetime reflects the deployment timezone
    try {
      const res = await apiClient.get<{ now: string }>(API_ENDPOINTS.SYSTEM_TIME);
      setEventTime(res.data.now);
    } catch {
      setEventTime(toInputValue(new Date().toISOString()));
    }
    setShowForm(true);
  };

  const openEditForm = (ev: NetworkExternalEvent) => {
    setEditingId(ev.id);
    setEventTime(toInputValue(ev.eventTime));
    setTitle(ev.title);
    setDescription(ev.description ?? '');
    setError(null);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !eventTime) return;
    setSaving(true);
    setError(null);
    try {
      if (editingId) {
        await onUpdate(editingId, eventTime, title.trim(), description.trim() || undefined);
      } else {
        await onAdd(eventTime, title.trim(), description.trim() || undefined);
      }
      resetForm();
    } catch {
      setError(`Failed to ${editingId ? 'update' : 'add'} event. Please try again.`);
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
          No external events recorded. Add real-world events (maintenance windows, incidents,
          policy changes, etc.) to give the AI context when generating insights.
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
                    {new Date(ev.eventTime).toLocaleString('en-GB')}
                  </td>
                  <td>
                    <div className="small fw-semibold">{ev.title}</div>
                    {ev.description && (
                      <div className="text-muted" style={{ fontSize: '0.75rem' }}>{ev.description}</div>
                    )}
                  </td>
                  <td>
                    <div className="d-flex gap-1 justify-content-end">
                      <Button
                        size="sm"
                        variant="outline-secondary"
                        title="Edit event"
                        onClick={() => openEditForm(ev)}
                        disabled={deletingId === ev.id}
                      >
                        <i className="bi bi-pencil" />
                      </Button>
                      <Button
                        size="sm"
                        variant="outline-danger"
                        title="Delete event"
                        onClick={() => handleDelete(ev.id)}
                        disabled={deletingId === ev.id}
                      >
                        {deletingId === ev.id
                          ? <Spinner animation="border" size="sm" />
                          : <i className="bi bi-trash" />
                        }
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showForm ? (
        <form onSubmit={handleSubmit} className="border rounded p-3 bg-light">
          {error && <Alert variant="danger" className="py-2 small">{error}</Alert>}
          <p className="text-muted small mb-3">
            Record a real-world event that could explain a change in the network's behaviour
            (e.g. an audit notice, a policy rollout, a maintenance window, or an incident).
            The AI uses these to correlate observed traffic shifts with known activity.
          </p>
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
              <Form.Text className="text-muted" style={{ fontSize: '0.7rem' }}>
                When the event actually happened (not when you logged it).
              </Form.Text>
            </div>
            <div className="col-sm-8">
              <Form.Label className="small fw-semibold">
                Title <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="e.g. Audit notice issued to staff — policy violations flagged for remediation"
                value={title}
                onChange={e => setTitle(e.target.value)}
                required
              />
              <Form.Text className="text-muted" style={{ fontSize: '0.7rem' }}>
                A short, scannable summary of what happened.
              </Form.Text>
            </div>
            <div className="col-12">
              <Form.Label className="small fw-semibold">Description (optional)</Form.Label>
              <Form.Control
                as="textarea"
                size="sm"
                rows={2}
                placeholder="Additional context — who/what was affected, expected impact, follow-up actions…"
                value={description}
                onChange={e => setDescription(e.target.value)}
              />
            </div>
          </div>
          <div className="d-flex gap-2 mt-3">
            <Button size="sm" type="submit" variant="primary" disabled={saving || !title.trim() || !eventTime}>
              {saving ? <Spinner animation="border" size="sm" className="me-1" /> : null}
              {editingId ? 'Save Changes' : 'Add Event'}
            </Button>
            <Button size="sm" variant="secondary" onClick={resetForm} disabled={saving}>
              Cancel
            </Button>
          </div>
        </form>
      ) : (
        <Button size="sm" variant="outline-primary" onClick={openAddForm}>
          <i className="bi bi-plus-lg me-1" />Add Event
        </Button>
      )}
    </div>
  );
};
