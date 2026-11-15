import { useEffect, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { settingsService, type SystemSetting } from '@/features/settings';

interface EditSystemSettingModalProps {
  setting: SystemSetting | null;
  onHide: () => void;
  /** Called with the updated list once a change is saved. */
  onSaved: () => void;
}

function apiMessage(err: unknown): string | null {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? null;
}

/**
 * Changes one editable policy setting (#915 phase 5). The server validates, checks the permission
 * and records the change in the audit log; its message is shown as is when it refuses.
 */
export function EditSystemSettingModal({ setting, onHide, onSaved }: EditSystemSettingModalProps) {
  const [value, setValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (setting) {
      setValue(setting.value ?? '');
      setError(null);
    }
  }, [setting]);

  if (!setting) return null;

  const run = async (action: () => Promise<unknown>) => {
    setSaving(true);
    setError(null);
    try {
      await action();
      onSaved();
      onHide();
    } catch (err) {
      setError(apiMessage(err) ?? "Couldn't save the change. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  const inputId = `edit-setting-${setting.key}`;
  const unchanged = value.trim() === (setting.value ?? '');

  return (
    <Modal show onHide={() => !saving && onHide()}>
      <Modal.Header closeButton>
        <Modal.Title>{setting.label}</Modal.Title>
      </Modal.Header>
      <form
        onSubmit={e => {
          e.preventDefault();
          if (!unchanged) run(() => settingsService.setSystemSetting(setting.key, value));
        }}
      >
        <Modal.Body>
          {error && (
            <Alert variant="danger" className="py-2">
              {error}
            </Alert>
          )}
          {setting.description && <p className="small text-muted">{setting.description}</p>}
          <Form.Group className="mb-3">
            <Form.Label htmlFor={inputId}>Value</Form.Label>
            <Form.Control
              id={inputId}
              value={value}
              inputMode="decimal"
              onChange={e => setValue(e.target.value)}
              disabled={saving}
              autoFocus
            />
            <Form.Text muted>
              The deployment sets <span className="font-monospace">{setting.deployValue}</span> (
              <span className="font-monospace">{setting.key}</span>).
              {setting.takesEffect && <> Takes effect: {setting.takesEffect}</>}
            </Form.Text>
          </Form.Group>
          <p className="small mb-0">
            Applies to everyone using this install, and is recorded in the audit log.
          </p>
        </Modal.Body>
        <Modal.Footer>
          {setting.overridden && (
            <Button
              type="button"
              variant="link"
              className="me-auto"
              disabled={saving}
              onClick={() => run(() => settingsService.resetSystemSetting(setting.key))}
            >
              Reset to the deployment's value
            </Button>
          )}
          <Button type="button" variant="secondary" onClick={onHide} disabled={saving}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={saving || unchanged || value.trim() === ''}>
            {saving ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" />
                Saving…
              </>
            ) : (
              'Save'
            )}
          </Button>
        </Modal.Footer>
      </form>
    </Modal>
  );
}
