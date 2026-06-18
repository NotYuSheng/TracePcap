import { Spinner } from '@components/common/Spinner/Spinner';
import { useState } from 'react';
import { Badge, Button, Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import type {
  BaselineDefinition,
  BaselineEntryType,
} from '@/features/monitor/types/monitor.types';

const ENTRY_TYPES: BaselineEntryType[] = [
  'DEVICE',
  'IP_MAC_BINDING',
  'GATEWAY',
  'PROTOCOL',
  'APP',
  'VPN_FINGERPRINT',
];

const ENTRY_TYPE_LABELS: Record<BaselineEntryType, string> = {
  DEVICE: 'Device (MAC)',
  IP_MAC_BINDING: 'IP ↔ MAC Binding',
  GATEWAY: 'Gateway IP',
  PROTOCOL: 'Protocol',
  APP: 'Application',
  VPN_FINGERPRINT: 'VPN Fingerprint',
};

// Per-type field config: what to label/placeholder the key and value fields,
// and whether the value field is used at all.
const FIELD_CONFIG: Record<BaselineEntryType, {
  keyLabel: string;
  keyPlaceholder: string;
  valueLabel?: string;
  valuePlaceholder?: string;
}> = {
  DEVICE: {
    keyLabel: 'MAC Address',
    keyPlaceholder: 'e.g. aa:bb:cc:dd:ee:ff',
    valueLabel: 'Expected IP (optional)',
    valuePlaceholder: 'e.g. 192.168.1.10',
  },
  IP_MAC_BINDING: {
    keyLabel: 'IP Address',
    keyPlaceholder: 'e.g. 192.168.1.1',
    valueLabel: 'Expected MAC',
    valuePlaceholder: 'e.g. aa:bb:cc:dd:ee:ff',
  },
  GATEWAY: {
    keyLabel: 'Gateway IP',
    keyPlaceholder: 'e.g. 192.168.1.1',
  },
  PROTOCOL: {
    keyLabel: 'Protocol Name',
    keyPlaceholder: 'e.g. HTTP, DNS, TLS',
  },
  APP: {
    keyLabel: 'Application Name',
    keyPlaceholder: 'e.g. Zoom, Teams, Spotify',
  },
  VPN_FINGERPRINT: {
    keyLabel: 'VPN Risk String',
    keyPlaceholder: 'e.g. VPN, OpenVPN, WireGuard',
  },
};

interface BaselineDefinitionPanelProps {
  networkId: string;
  definitions: BaselineDefinition[];
  onAdd: (
    entryType: BaselineEntryType,
    entityKey: string,
    entityValue?: string,
    notes?: string,
  ) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}

export const BaselineDefinitionPanel = ({
  definitions,
  onAdd,
  onDelete,
}: BaselineDefinitionPanelProps) => {
  const [showForm, setShowForm] = useState(false);
  const [entryType, setEntryType] = useState<BaselineEntryType>('DEVICE');
  const [entityKey, setEntityKey] = useState('');
  const [entityValue, setEntityValue] = useState('');
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!entityKey.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await onAdd(entryType, entityKey.trim(), entityValue.trim() || undefined, notes.trim() || undefined);
      setEntityKey('');
      setEntityValue('');
      setNotes('');
      setShowForm(false);
    } catch {
      setError('Failed to add entry. Please try again.');
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
      {definitions.length === 0 && !showForm && (
        <div className="text-muted small mb-3">
          No manual baseline entries yet. Add expected devices, protocols, or services for this
          network.
        </div>
      )}

      {definitions.length > 0 && (
        <div className="table-responsive mb-3">
          <table className="table table-sm mb-0">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Notes</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {definitions.map(def => (
                <tr key={def.id}>
                  <td>
                    <Badge bg="light" text="dark" className="border">
                      {ENTRY_TYPE_LABELS[def.entryType] ?? def.entryType}
                    </Badge>
                  </td>
                  <td>
                    <code>{def.entityKey}</code>
                    {def.entityValue && (
                      <span className="text-muted ms-2">
                        → <code>{def.entityValue}</code>
                      </span>
                    )}
                  </td>
                  <td>
                    <small className="text-muted">{def.notes ?? '—'}</small>
                  </td>
                  <td>
                    <Button
                      size="sm"
                      variant="outline-danger"
                      onClick={() => handleDelete(def.id)}
                      disabled={deletingId === def.id}
                    >
                      {deletingId === def.id ? (
                        <Spinner animation="border" size="sm" />
                      ) : (
                        <i className="bi bi-trash"></i>
                      )}
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
            <div className="col-sm-3">
              <Form.Label className="small fw-semibold">Type</Form.Label>
              <Form.Select
                size="sm"
                value={entryType}
                onChange={e => {
                  setEntryType(e.target.value as BaselineEntryType);
                  setEntityKey('');
                  setEntityValue('');
                }}
              >
                {ENTRY_TYPES.map(t => (
                  <option key={t} value={t}>{ENTRY_TYPE_LABELS[t]}</option>
                ))}
              </Form.Select>
            </div>
            <div className={FIELD_CONFIG[entryType].valueLabel ? 'col-sm-3' : 'col-sm-5'}>
              <Form.Label className="small fw-semibold">
                {FIELD_CONFIG[entryType].keyLabel} <span className="text-danger">*</span>
              </Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder={FIELD_CONFIG[entryType].keyPlaceholder}
                value={entityKey}
                onChange={e => setEntityKey(e.target.value)}
                required
              />
            </div>
            {FIELD_CONFIG[entryType].valueLabel && (
              <div className="col-sm-3">
                <Form.Label className="small fw-semibold">
                  {FIELD_CONFIG[entryType].valueLabel}
                </Form.Label>
                <Form.Control
                  size="sm"
                  type="text"
                  placeholder={FIELD_CONFIG[entryType].valuePlaceholder}
                  value={entityValue}
                  onChange={e => setEntityValue(e.target.value)}
                />
              </div>
            )}
            <div className={FIELD_CONFIG[entryType].valueLabel ? 'col-sm-3' : 'col-sm-4'}>
              <Form.Label className="small fw-semibold">Notes</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="Optional"
                value={notes}
                onChange={e => setNotes(e.target.value)}
              />
            </div>
          </div>
          <div className="d-flex gap-2 mt-3">
            <Button size="sm" type="submit" variant="primary" disabled={saving || !entityKey.trim()}>
              {saving ? <Spinner animation="border" size="sm" className="me-1" /> : null}
              Add Entry
            </Button>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => setShowForm(false)}
              disabled={saving}
            >
              Cancel
            </Button>
          </div>
        </form>
      ) : (
        <Button
          size="sm"
          variant="outline-primary"
          onClick={() => setShowForm(true)}
        >
          <i className="bi bi-plus-lg me-1"></i>Add Entry
        </Button>
      )}
    </div>
  );
};
