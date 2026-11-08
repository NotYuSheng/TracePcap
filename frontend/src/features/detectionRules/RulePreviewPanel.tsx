import { useEffect, useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import {
  detectionRulesService,
  errorMessage,
  type DetectionRuleInput,
  type RulePreview,
} from './detectionRulesService';

interface RulePreviewPanelProps {
  draft: DetectionRuleInput;
  /** A capture to test against by default (the one the rule belongs to, or is being viewed). */
  defaultFileId?: string;
  /** False while the form has problems: there's nothing valid to test. */
  canTest: boolean;
}

/**
 * "Test against a capture" (#925 phase 4): what the rule as it stands would match in one capture,
 * before saving. Nothing is stored.
 */
export function RulePreviewPanel({ draft, defaultFileId, canTest }: RulePreviewPanelProps) {
  const [files, setFiles] = useState<{ fileId: string; fileName: string }[]>([]);
  const [fileId, setFileId] = useState(defaultFileId ?? '');
  const [result, setResult] = useState<RulePreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiClient
      .get<{ data: { fileId: string; fileName: string; status: string }[] }>(
        API_ENDPOINTS.FILES_LIST,
        {
          params: { page: 1, pageSize: 50 },
        }
      )
      .then(r => {
        const done = r.data.data.filter(f => f.status?.toLowerCase() === 'completed');
        setFiles(done);
        setFileId(current => current || done[0]?.fileId || '');
      })
      .catch(() => setFiles([]));
  }, []);

  const test = async () => {
    if (!fileId) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await detectionRulesService.preview(draft, fileId));
    } catch (e) {
      setError(errorMessage(e, "Couldn't test the rule."));
    } finally {
      setBusy(false);
    }
  };

  const options =
    files.some(f => f.fileId === defaultFileId) || !defaultFileId
      ? files
      : [{ fileId: defaultFileId, fileName: 'This capture' }, ...files];

  return (
    <div className="border rounded p-2 mt-3" data-testid="rule-preview-panel">
      <div className="d-flex flex-wrap align-items-center gap-2">
        <Form.Label htmlFor="rule-preview-file" className="small mb-0 fw-semibold">
          Test against a capture
        </Form.Label>
        <Form.Select
          id="rule-preview-file"
          size="sm"
          style={{ width: 'auto', maxWidth: 320 }}
          value={fileId}
          onChange={e => {
            setFileId(e.target.value);
            setResult(null);
          }}
          disabled={busy || options.length === 0}
        >
          {options.length === 0 && <option value="">No analysed captures</option>}
          {options.map(f => (
            <option key={f.fileId} value={f.fileId}>
              {f.fileName}
            </option>
          ))}
        </Form.Select>
        <Button
          size="sm"
          variant="outline-primary"
          onClick={test}
          disabled={!canTest || !fileId || busy}
        >
          {busy ? <Spinner animation="border" size="sm" /> : 'Test'}
        </Button>
      </div>
      {!canTest && (
        <div className="small text-muted mt-1">Fix the form first; then you can test it.</div>
      )}
      {error && <div className="small text-danger mt-1">{error}</div>}
      {result && (
        <div className="small mt-2" data-testid="rule-preview-result">
          {result.packetsDeleted ? (
            <span className="text-muted">
              Can't test this rule here: it looks inside packets, and retention deleted this
              capture's packets.
            </span>
          ) : (
            <>
              <strong>
                Would match {result.matches} of {result.conversations} conversation
                {result.conversations === 1 ? '' : 's'}
              </strong>{' '}
              in {result.fileName}. Nothing has been saved.
              {result.sample.length > 0 && (
                <ul className="mb-0 mt-1 font-monospace">
                  {result.sample.map(s => (
                    <li key={s.conversationId}>
                      {s.srcIp}
                      {s.srcPort != null ? `:${s.srcPort}` : ''} → {s.dstIp}
                      {s.dstPort != null ? `:${s.dstPort}` : ''} {s.protocol ?? ''}
                      {s.appName ? ` ${s.appName}` : ''}
                      {s.hostname ? ` ${s.hostname}` : ''}
                    </li>
                  ))}
                  {result.matches != null && result.matches > result.sample.length && (
                    <li className="text-muted">
                      …and {result.matches - result.sample.length} more
                    </li>
                  )}
                </ul>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
