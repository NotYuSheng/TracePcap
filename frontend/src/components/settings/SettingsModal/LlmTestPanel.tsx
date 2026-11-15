import { useState } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { settingsService, type LlmTestResult } from '@/features/settings';

function apiMessage(err: unknown): string | null {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? null;
}

const ICON: Record<string, string> = {
  OK: 'bi-check-circle-fill text-success',
  FAIL: 'bi-x-circle-fill text-danger',
  SKIPPED: 'bi-dash-circle text-muted',
};

/**
 * Tests the LLM connection: reach the server, key accepted, model available, model replies. Blank
 * candidate fields use the current settings. When the server lists its models, they can be picked.
 */
export function LlmTestPanel({
  candidate,
  onPickModel,
  label = 'Test connection',
}: {
  /** Values to test before saving; omitted fields use the current settings. */
  candidate?: { baseUrl?: string; apiKey?: string; model?: string };
  /** Offered when the server lists models; null hides the picker. */
  onPickModel?: ((model: string) => void) | null;
  label?: string;
}) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<LlmTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setRunning(true);
    setError(null);
    try {
      setResult(await settingsService.testLlm(candidate ?? {}));
    } catch (err) {
      setResult(null);
      setError(apiMessage(err) ?? "Couldn't run the test.");
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="llm-test">
      <Button size="sm" variant="outline-primary" onClick={run} disabled={running}>
        {running ? (
          <>
            <Spinner animation="border" size="sm" className="me-2" />
            Testing…
          </>
        ) : (
          <>
            <i className="bi bi-plug me-1" aria-hidden="true" />
            {label}
          </>
        )}
      </Button>
      {error && <p className="small text-danger mt-2 mb-0">{error}</p>}
      {result && (
        <div className="mt-2" role="status" aria-live="polite">
          <p className={`small fw-semibold mb-1 ${result.ok ? 'text-success' : 'text-danger'}`}>
            {result.ok ? 'Connected.' : 'Not working.'}{' '}
            <span className="fw-normal text-muted">
              {result.model} at <span className="font-monospace">{result.baseUrl}</span>
            </span>
          </p>
          <ul className="list-unstyled small mb-2">
            {result.steps.map(s => (
              <li key={s.key} className="d-flex gap-2 align-items-baseline">
                <i className={`bi ${ICON[s.status]}`} aria-hidden="true" />
                <span>
                  <b>{s.label}</b>
                  <span className="visually-hidden"> {s.status.toLowerCase()}</span>: {s.detail}
                </span>
              </li>
            ))}
          </ul>
          {onPickModel && result.models.length > 0 && (
            <div className="small">
              <span className="text-muted me-1">The server's models:</span>
              {result.models.map(m => (
                <Button
                  key={m}
                  size="sm"
                  variant={m === result.model ? 'primary' : 'outline-secondary'}
                  className="me-1 mb-1 py-0"
                  onClick={() => onPickModel(m)}
                  disabled={m === result.model}
                >
                  {m}
                </Button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
