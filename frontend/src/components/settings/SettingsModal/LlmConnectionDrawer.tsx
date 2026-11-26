import { useEffect, useRef, useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { SideDrawer } from '@components/common/SideDrawer';
import { Spinner } from '@components/common/Spinner/Spinner';
import { settingsService, type LlmModelList, type SystemSetting } from '@/features/settings';
import { LlmTestPanel } from './LlmTestPanel';
import { contextLabel } from './llmConnection';

/** Wait this long after typing before asking the server for its models. */
const LIST_DELAY_MS = 600;
const OTHER = '__other__';
/** The saved model, when the server doesn't offer it. */
const UNLISTED = '__unlisted__';

function apiMessage(err: unknown): string | null {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? null;
}

/**
 * The LLM connection as one form: the server's URL, its key and the model, where the model is
 * picked from what the server at that URL offers. Test the values before saving them; each change
 * is saved and audited as its own setting.
 */
export function LlmConnectionDrawer({
  settings,
  onHide,
  onSaved,
}: {
  settings: SystemSetting[];
  onHide: () => void;
  onSaved: () => void;
}) {
  const byKey = (k: string) => settings.find(s => s.key === k);
  const urlSetting = byKey('LLM_API_BASE_URL');
  const keySetting = byKey('LLM_API_KEY');
  const modelSetting = byKey('LLM_MODEL');

  const [baseUrl, setBaseUrl] = useState(urlSetting?.value ?? '');
  // A secret is never sent to the page: blank keeps the current key.
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState(modelSetting?.value ?? '');
  const [typing, setTyping] = useState(false);
  const [list, setList] = useState<LlmModelList | null>(null);
  const [listing, setListing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const asked = useRef(0);

  const urlChanged = baseUrl.trim() !== (urlSetting?.value ?? '');
  const candidate = {
    baseUrl: urlChanged ? baseUrl.trim() : undefined,
    apiKey: apiKey.trim() || undefined,
  };

  // Ask the server at the typed URL (with the typed key) for its models, once typing pauses.
  useEffect(() => {
    const id = ++asked.current;
    if (!baseUrl.trim()) {
      // Also drops the answer to a request still on its way for the old URL.
      setList(null);
      setListing(false);
      return;
    }
    const timer = setTimeout(() => {
      setListing(true);
      settingsService
        .listLlmModels(candidate)
        .then(r => id === asked.current && setList(r))
        .catch(err =>
          id === asked.current &&
          setList({ ok: false, baseUrl, models: [], detail: apiMessage(err) ?? "Couldn't list the models." })
        )
        .finally(() => id === asked.current && setListing(false));
    }, LIST_DELAY_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- candidate is derived from these
  }, [baseUrl, apiKey]);

  const models = list?.models ?? [];
  const picking = models.length > 0 && !typing;
  const offered = models.some(m => m.id === model);

  const changes: Record<string, string> = {};
  if (urlSetting?.editable && urlChanged && baseUrl.trim()) changes.LLM_API_BASE_URL = baseUrl.trim();
  if (keySetting?.editable && apiKey.trim()) changes.LLM_API_KEY = apiKey.trim();
  if (modelSetting?.editable && model.trim() && model.trim() !== (modelSetting?.value ?? ''))
    changes.LLM_MODEL = model.trim();
  const changed = Object.keys(changes).length > 0;
  // A URL and a model are needed for any call; a blank one is never saved.
  const incomplete = !baseUrl.trim() || !model.trim();
  // Changed in the app, and so resettable to the deployment's values.
  const overridden = [urlSetting, keySetting, modelSetting].filter(
    (s): s is SystemSetting => !!s?.editable && !!s.overridden
  );

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
  // All together or none, so the connection is never left half changed.
  const save = () => run(() => settingsService.setSystemSettings(changes));
  const reset = () =>
    run(async () => {
      for (const s of overridden) await settingsService.resetSystemSetting(s.key);
    });

  const locked = (s?: SystemSetting) =>
    s && !s.editable ? <Form.Text muted>{s.lockedReason ?? "You can't change this here."}</Form.Text> : null;

  return (
    <SideDrawer
      show
      onHide={() => !saving && onHide()}
      title="LLM connection"
      titleId="llm-connection-title"
      footer={
        <>
          {overridden.length > 0 && (
            <Button type="button" variant="link" className="me-auto" disabled={saving} onClick={reset}>
              Reset to the deployment's values
            </Button>
          )}
          <Button type="button" variant="outline-secondary" onClick={onHide} disabled={saving}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="llm-connection-form"
            variant="primary"
            disabled={saving || !changed || incomplete}
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
        id="llm-connection-form"
        onSubmit={e => {
          e.preventDefault();
          if (changed && !incomplete) save();
        }}
      >
        {error && (
          <Alert variant="danger" className="py-2">
            {error}
          </Alert>
        )}
        <p className="small text-muted">
          The server Story, Insights and the chat send captures' details to. Enter its URL and key,
          pick one of its models, and test before saving.
        </p>
        <Form.Group className="mb-3">
          <Form.Label htmlFor="llm-base-url">Server URL</Form.Label>
          <Form.Control
            id="llm-base-url"
            type="url"
            value={baseUrl}
            placeholder="http://host:1234/v1"
            autoComplete="off"
            onChange={e => setBaseUrl(e.target.value)}
            disabled={saving || !urlSetting?.editable}
          />
          {locked(urlSetting) ?? <Form.Text muted>The API's base URL; it usually ends in /v1.</Form.Text>}
        </Form.Group>
        <Form.Group className="mb-3">
          <Form.Label htmlFor="llm-api-key">API key</Form.Label>
          <Form.Control
            id="llm-api-key"
            type="password"
            value={apiKey}
            autoComplete="new-password"
            placeholder={keySetting?.set ? 'Leave blank to keep the current key' : 'Blank if the server needs none'}
            onChange={e => setApiKey(e.target.value)}
            disabled={saving || !keySetting?.editable}
          />
          {locked(keySetting)}
        </Form.Group>
        <Form.Group className="mb-3">
          <Form.Label htmlFor="llm-model">Model</Form.Label>
          {picking ? (
            <Form.Select
              id="llm-model"
              value={offered ? model : UNLISTED}
              onChange={e =>
                e.target.value === OTHER
                  ? setTyping(true)
                  : e.target.value !== UNLISTED && setModel(e.target.value)
              }
              disabled={saving || !modelSetting?.editable}
            >
              {!offered && (
                <option value={UNLISTED}>{model ? `${model} (not on this server)` : 'Pick a model'}</option>
              )}
              {models.map(m => (
                <option key={m.id} value={m.id}>
                  {m.id}
                  {m.contextLength ? ` · ${contextLabel(m.contextLength)}` : ''}
                </option>
              ))}
              <option value={OTHER}>Type another name…</option>
            </Form.Select>
          ) : (
            <Form.Control
              id="llm-model"
              value={model}
              autoComplete="off"
              onChange={e => setModel(e.target.value)}
              disabled={saving || !modelSetting?.editable}
            />
          )}
          {locked(modelSetting) ?? (
            <Form.Text muted aria-live="polite">
              {listing ? (
                <>
                  <Spinner animation="border" size="sm" className="me-1" />
                  Asking the server for its models…
                </>
              ) : list && !list.ok ? (
                <span className="text-danger">{list.detail}</span>
              ) : list && models.length === 0 ? (
                list.detail
              ) : picking ? (
                `The server offers ${models.length} model${models.length === 1 ? '' : 's'}.`
              ) : models.length > 0 ? (
                <Button variant="link" size="sm" className="p-0" onClick={() => setTyping(false)}>
                  Pick from the server's models
                </Button>
              ) : null}
            </Form.Text>
          )}
        </Form.Group>
        <div className="mb-3">
          <LlmTestPanel
            // Only what differs from the saved values: testing those needs no permission.
            candidate={{
              ...candidate,
              model: model.trim() && model.trim() !== (modelSetting?.value ?? '') ? model.trim() : undefined,
            }}
            label="Test these values"
          />
        </div>
        <p className="small mb-0">
          Applies to everyone using this install, and each change is recorded in the audit log (that
          the key changed, not the key).
        </p>
      </form>
    </SideDrawer>
  );
}
