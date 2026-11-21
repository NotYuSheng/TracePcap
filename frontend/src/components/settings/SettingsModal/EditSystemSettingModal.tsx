import { useEffect, useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { SideDrawer } from '@components/common/SideDrawer';
import { Spinner } from '@components/common/Spinner/Spinner';
import { settingsService, type SystemSetting } from '@/features/settings';
import { LlmTestPanel } from './LlmTestPanel';

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
      // A secret is never sent to the page: its field starts empty, for a new value.
      setValue(setting.secret ? '' : (setting.value ?? ''));
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
  const unchanged = !setting.secret && value.trim() === (setting.value ?? '');
  // The LLM connection's own fields can be tested with the typed value before saving it.
  const candidate =
    setting.key === 'LLM_API_BASE_URL'
      ? { baseUrl: value }
      : setting.key === 'LLM_API_KEY'
        ? { apiKey: value }
        : setting.key === 'LLM_MODEL'
          ? { model: value }
          : null;

  return (
    <SideDrawer
      show
      onHide={() => !saving && onHide()}
      title={setting.label}
      titleId="edit-setting-title"
      footer={
        <>
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
          <Button type="button" variant="outline-secondary" onClick={onHide} disabled={saving}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="edit-setting-form"
            variant="primary"
            disabled={saving || unchanged || value.trim() === ''}
          >
            {saving ? (
              <>
                <Spinner animation="border" size="sm" className="me-2" />
                Saving…
              </>
            ) : (
              'Save'
            )}
          </Button>
        </>
      }
    >
      <form
        id="edit-setting-form"
        onSubmit={e => {
          e.preventDefault();
          if (!unchanged) run(() => settingsService.setSystemSetting(setting.key, value));
        }}
      >
        {error && (
          <Alert variant="danger" className="py-2">
            {error}
          </Alert>
        )}
        {setting.description && <p className="small text-muted">{setting.description}</p>}
        <Form.Group className="mb-3">
          <Form.Label htmlFor={inputId}>Value</Form.Label>
          {setting.type === 'CHOICE' ? (
            <Form.Select
              id={inputId}
              value={value}
              onChange={e => setValue(e.target.value)}
              disabled={saving}
            >
              {(setting.choices ?? []).map(c => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Form.Select>
          ) : (
            <Form.Control
              id={inputId}
              value={value}
              type={setting.secret ? 'password' : setting.type === 'URL' ? 'url' : 'text'}
              autoComplete={setting.secret ? 'new-password' : 'off'}
              placeholder={
                setting.secret
                  ? setting.set
                    ? 'Enter a new key to replace the current one'
                    : 'Enter the key'
                  : undefined
              }
              inputMode={
                setting.type === 'INT' || setting.type === 'RATIO' || setting.type === 'DECIMAL'
                  ? 'decimal'
                  : undefined
              }
              onChange={e => setValue(e.target.value)}
              disabled={saving}
              autoFocus
            />
          )}
          <Form.Text muted>
            {setting.secret ? (
              <>A secret: it's never shown again once saved. </>
            ) : (
              <>
                The deployment sets{' '}
                <span className="font-monospace">{setting.deployValue}</span>{' '}
              </>
            )}
            (<span className="font-monospace">{setting.key}</span>).
            {setting.takesEffect && <> Takes effect: {setting.takesEffect}</>}
          </Form.Text>
        </Form.Group>
        {candidate && value.trim() !== '' && (
          <div className="mb-3">
            <LlmTestPanel candidate={candidate} label="Test this value" />
          </div>
        )}
        <p className="small mb-0">
          Applies to everyone using this install, and is recorded in the audit log
          {setting.secret ? ' (that it changed, not the key)' : ''}.
        </p>
      </form>
    </SideDrawer>
  );
}
