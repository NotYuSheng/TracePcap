import { useEffect, useMemo, useState } from 'react';
import { Button, Col, Form, Modal, Row } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import {
  detectionRulesService,
  errorMessage,
  fieldErrors,
  toInput,
  type DetectionRule,
  type DetectionRuleInput,
  type RuleMatch,
  type Severity,
} from '@/features/detectionRules/detectionRulesService';

interface RuleEditorModalProps {
  show: boolean;
  /** The rule to edit, or null to create one. */
  rule: DetectionRule | null;
  /** View only: the caller may not change rules. */
  readOnly?: boolean;
  /** Create the rule for this capture only (#925 phase 3), instead of a global rule. */
  fileId?: string;
  onHide: () => void;
  onSaved: () => void;
}

const EMPTY: DetectionRuleInput = {
  name: '',
  description: '',
  severity: 'medium',
  enabled: true,
  match: {},
  payloadContains: [],
  payloadRegex: [],
  matchAll: false,
};

const MATCH_FIELDS: {
  key: keyof RuleMatch;
  label: string;
  placeholder: string;
  numeric?: boolean;
}[] = [
  { key: 'ip', label: 'IP address', placeholder: '203.0.113.42' },
  { key: 'cidr', label: 'CIDR range', placeholder: '10.0.0.0/8' },
  { key: 'srcPort', label: 'Source port', placeholder: '67', numeric: true },
  { key: 'dstPort', label: 'Destination port', placeholder: '4444', numeric: true },
  { key: 'hostname', label: 'Hostname (SNI)', placeholder: '*.evil.com' },
  { key: 'app', label: 'App (nDPI)', placeholder: 'TOR' },
  { key: 'protocol', label: 'Protocol', placeholder: 'TCP' },
  { key: 'ja3', label: 'JA3 hash', placeholder: '32 hex characters' },
];

/** Checks that need no server: they show as you type. The server checks everything again. */
function localErrors(r: DetectionRuleInput): Record<string, string> {
  const e: Record<string, string> = {};
  if (!r.name.trim()) e.name = 'Give the rule a name.';
  const hasMatch = Object.values(r.match).some(
    v => v !== null && v !== undefined && String(v).trim() !== ''
  );
  if (!hasMatch && r.payloadContains.length === 0 && r.payloadRegex.length === 0) {
    e.match = 'Add at least one match field or payload pattern, or the rule never fires.';
  }
  for (const k of ['srcPort', 'dstPort'] as const) {
    const v = r.match[k];
    if (v !== null && v !== undefined && (!Number.isInteger(v) || v < 0 || v > 65535)) {
      e[`match.${k}`] = 'A port is 0 to 65535.';
    }
  }
  if (r.match.ja3 && !/^[0-9a-fA-F]{32}$/.test(r.match.ja3.trim()))
    e['match.ja3'] = 'A JA3 hash is 32 hex characters.';
  r.payloadContains.forEach((p, i) => {
    const v = (p.hex ?? p.ascii ?? '').trim();
    if (!v) e[`payloadContains[${i}]`] = 'Enter the bytes to look for.';
    else if (p.hex !== undefined && p.hex !== null) {
      const h = v
        .toLowerCase()
        .replace(/^0x/, '')
        .replace(/[\s:-]/g, '');
      if (!/^([0-9a-f]{2})+$/.test(h))
        e[`payloadContains[${i}].hex`] = 'Hex bytes are pairs of 0-9 and a-f, such as 48 54 54 50.';
    }
  });
  r.payloadRegex.forEach((p, i) => {
    if (!p.pattern.trim()) e[`payloadRegex[${i}].pattern`] = 'Enter a pattern.';
  });
  return e;
}

/** The form editor for one detection rule (#925 phase 1). Server errors show next to their field. */
export function RuleEditorModal({
  show,
  rule,
  readOnly = false,
  fileId,
  onHide,
  onSaved,
}: RuleEditorModalProps) {
  const [draft, setDraft] = useState<DetectionRuleInput>(EMPTY);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    if (show) {
      setDraft(rule ? toInput(rule) : EMPTY);
      setServerErrors({});
      setError(null);
      setTouched(false);
    }
  }, [show, rule]);

  const local = useMemo(() => localErrors(draft), [draft]);
  const captureScope = rule ? rule.scope === 'CAPTURE' : !!fileId;
  // Local errors show once the user has typed; server errors until the field is changed again.
  const errors = { ...(touched ? local : {}), ...serverErrors };
  const err = (key: string) => errors[key];

  const update = (patch: Partial<DetectionRuleInput>, clear: string[] = []) => {
    setTouched(true);
    setDraft(d => ({ ...d, ...patch }));
    if (clear.length)
      setServerErrors(s =>
        Object.fromEntries(Object.entries(s).filter(([k]) => !clear.some(c => k.startsWith(c))))
      );
  };
  const setMatch = (key: keyof RuleMatch, raw: string, numeric?: boolean) => {
    const value = raw.trim() === '' ? null : numeric ? Number(raw) : raw;
    update({ match: { ...draft.match, [key]: value } }, [`match.${key}`, 'match']);
  };

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (Object.keys(local).length) return;
    setSaving(true);
    setError(null);
    try {
      if (rule) await detectionRulesService.update(rule.id, draft);
      else if (fileId) await detectionRulesService.createForCapture(fileId, draft);
      else await detectionRulesService.create(draft);
      onSaved();
      onHide();
    } catch (ex) {
      const fields = fieldErrors(ex);
      if (fields) setServerErrors(fields);
      setError(errorMessage(ex, "Couldn't save the rule. Please try again."));
    } finally {
      setSaving(false);
    }
  };

  const payloadCount = draft.payloadContains.length + draft.payloadRegex.length;

  return (
    <Modal show={show} onHide={() => !saving && onHide()} size="lg" scrollable>
      <Modal.Header closeButton>
        <Modal.Title>
          {rule
            ? `${readOnly ? 'Rule' : 'Edit rule'}: ${rule.name}`
            : captureScope
              ? 'New rule for this capture'
              : 'New detection rule'}
        </Modal.Title>
      </Modal.Header>
      <form onSubmit={save} noValidate>
        <Modal.Body>
          {error && (
            <Alert variant="danger" className="py-2">
              {error}
            </Alert>
          )}
          <p className="small text-muted">
            {captureScope
              ? 'A capture rule flags matching conversations in this capture only, straight away, wherever the capture is viewed.'
              : 'A global rule flags every conversation it matches, in every capture analysed from now on.'}{' '}
            It fires when <strong>every</strong> field you fill in matches.
          </p>

          <Row className="g-2 mb-2">
            <Col md={8}>
              <Form.Label htmlFor="rule-name">Name</Form.Label>
              <Form.Control
                id="rule-name"
                value={draft.name}
                onChange={e => update({ name: e.target.value }, ['name'])}
                isInvalid={!!err('name')}
                placeholder="c2_beacon"
                disabled={saving || readOnly}
              />
              <Form.Control.Feedback type="invalid">{err('name')}</Form.Control.Feedback>
              <Form.Text muted>Shown on every conversation the rule matches.</Form.Text>
            </Col>
            <Col md={4}>
              <Form.Label htmlFor="rule-severity">Severity</Form.Label>
              <Form.Select
                id="rule-severity"
                value={draft.severity}
                onChange={e => update({ severity: e.target.value as Severity }, ['severity'])}
                isInvalid={!!err('severity')}
                disabled={saving || readOnly}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </Form.Select>
            </Col>
          </Row>
          <Form.Group className="mb-2">
            <Form.Label htmlFor="rule-description">Description</Form.Label>
            <Form.Control
              id="rule-description"
              as="textarea"
              rows={2}
              value={draft.description ?? ''}
              onChange={e => update({ description: e.target.value })}
              disabled={saving || readOnly}
            />
          </Form.Group>
          <Form.Check
            type="switch"
            id="rule-enabled"
            className="mb-3"
            label="Enabled"
            checked={draft.enabled}
            onChange={e => update({ enabled: e.target.checked })}
            disabled={saving || readOnly}
          />

          <h6 className="mb-1">Match</h6>
          {err('match') && (
            <div className="text-danger small mb-1" data-testid="rule-match-error">
              {err('match')}
            </div>
          )}
          <Row className="g-2 mb-3">
            {MATCH_FIELDS.map(f => (
              <Col md={6} key={f.key}>
                <Form.Label htmlFor={`rule-match-${f.key}`} className="small mb-0">
                  {f.label}
                </Form.Label>
                <Form.Control
                  id={`rule-match-${f.key}`}
                  size="sm"
                  type={f.numeric ? 'number' : 'text'}
                  placeholder={f.placeholder}
                  value={draft.match[f.key] ?? ''}
                  onChange={e => setMatch(f.key, e.target.value, f.numeric)}
                  isInvalid={!!err(`match.${f.key}`)}
                  disabled={saving || readOnly}
                />
                <Form.Control.Feedback type="invalid">
                  {err(`match.${f.key}`)}
                </Form.Control.Feedback>
              </Col>
            ))}
          </Row>

          <h6 className="mb-1">Payload</h6>
          <p className="small text-muted mb-2">
            Look inside the packets' payloads: bytes or text they contain, or a regular expression.
          </p>
          {draft.payloadContains.map((p, i) => {
            const isHex = p.hex !== undefined && p.hex !== null;
            const key = `payloadContains[${i}]`;
            const msg = err(`${key}.hex`) ?? err(key);
            return (
              <Row className="g-2 mb-1 align-items-start" key={`pc-${i}`}>
                <Col xs={3}>
                  <Form.Select
                    size="sm"
                    aria-label={`Payload pattern ${i + 1} type`}
                    value={isHex ? 'hex' : 'ascii'}
                    onChange={e => {
                      const v = (p.hex ?? p.ascii ?? '') as string;
                      const next = [...draft.payloadContains];
                      next[i] = e.target.value === 'hex' ? { hex: v } : { ascii: v };
                      update({ payloadContains: next }, [key]);
                    }}
                    disabled={saving || readOnly}
                  >
                    <option value="ascii">Contains text</option>
                    <option value="hex">Contains hex</option>
                  </Form.Select>
                </Col>
                <Col>
                  <Form.Control
                    size="sm"
                    aria-label={`Payload pattern ${i + 1}`}
                    className={isHex ? 'font-monospace' : undefined}
                    value={(p.hex ?? p.ascii ?? '') as string}
                    onChange={e => {
                      const next = [...draft.payloadContains];
                      next[i] = isHex ? { hex: e.target.value } : { ascii: e.target.value };
                      update({ payloadContains: next }, [key]);
                    }}
                    isInvalid={!!msg}
                    disabled={saving || readOnly}
                  />
                  <Form.Control.Feedback type="invalid">{msg}</Form.Control.Feedback>
                </Col>
                <Col xs="auto">
                  <Button
                    size="sm"
                    variant="outline-danger"
                    aria-label={`Remove payload pattern ${i + 1}`}
                    onClick={() =>
                      update({ payloadContains: draft.payloadContains.filter((_, j) => j !== i) }, [
                        'payloadContains',
                      ])
                    }
                    disabled={saving || readOnly}
                  >
                    <i className="bi bi-x" aria-hidden="true" />
                  </Button>
                </Col>
              </Row>
            );
          })}
          {draft.payloadRegex.map((p, i) => {
            const key = `payloadRegex[${i}].pattern`;
            return (
              <Row className="g-2 mb-1 align-items-start" key={`re-${i}`}>
                <Col xs={3} className="small pt-1">
                  Matches regex
                </Col>
                <Col>
                  <Form.Control
                    size="sm"
                    className="font-monospace"
                    aria-label={`Regex ${i + 1}`}
                    value={p.pattern}
                    onChange={e => {
                      const next = [...draft.payloadRegex];
                      next[i] = { ...p, pattern: e.target.value };
                      update({ payloadRegex: next }, [key]);
                    }}
                    isInvalid={!!err(key)}
                    disabled={saving || readOnly}
                  />
                  <Form.Control.Feedback type="invalid">{err(key)}</Form.Control.Feedback>
                  <Form.Check
                    id={`rule-regex-ci-${i}`}
                    className="small"
                    label="Ignore case"
                    checked={p.caseInsensitive}
                    onChange={e => {
                      const next = [...draft.payloadRegex];
                      next[i] = { ...p, caseInsensitive: e.target.checked };
                      update({ payloadRegex: next });
                    }}
                    disabled={saving || readOnly}
                  />
                </Col>
                <Col xs="auto">
                  <Button
                    size="sm"
                    variant="outline-danger"
                    aria-label={`Remove regex ${i + 1}`}
                    onClick={() =>
                      update({ payloadRegex: draft.payloadRegex.filter((_, j) => j !== i) }, [
                        'payloadRegex',
                      ])
                    }
                    disabled={saving || readOnly}
                  >
                    <i className="bi bi-x" aria-hidden="true" />
                  </Button>
                </Col>
              </Row>
            );
          })}
          <div className="d-flex gap-2 mt-1 mb-2">
            <Button
              size="sm"
              variant="outline-secondary"
              onClick={() =>
                update({ payloadContains: [...draft.payloadContains, { ascii: '' }] }, ['match'])
              }
              disabled={saving || readOnly}
            >
              <i className="bi bi-plus me-1" aria-hidden="true" />
              Bytes or text
            </Button>
            <Button
              size="sm"
              variant="outline-secondary"
              onClick={() =>
                update(
                  {
                    payloadRegex: [...draft.payloadRegex, { pattern: '', caseInsensitive: false }],
                  },
                  ['match']
                )
              }
              disabled={saving || readOnly}
            >
              <i className="bi bi-plus me-1" aria-hidden="true" />
              Regex
            </Button>
          </div>
          {payloadCount > 1 && (
            <Form.Check
              id="rule-match-all"
              className="small"
              label="Require every payload pattern (otherwise any one is enough)"
              checked={draft.matchAll}
              onChange={e => update({ matchAll: e.target.checked })}
              disabled={saving || readOnly}
            />
          )}

          {rule?.deviceType && (
            <Alert variant="info" className="py-2 small mt-3 mb-0">
              This rule also sets the device type of matched hosts to{' '}
              <strong>{rule.deviceType}</strong>. That's kept as it was, but can't be edited here:
              device types are moving to classification signals (#926).
            </Alert>
          )}
        </Modal.Body>
        <Modal.Footer>
          {rule && (
            <span className="small text-muted me-auto">
              Version {rule.version} · last changed by {rule.updatedBy}
            </span>
          )}
          <Button type="button" variant="secondary" onClick={onHide} disabled={saving}>
            {readOnly ? 'Close' : 'Cancel'}
          </Button>
          <Button
            type="submit"
            variant="primary"
            hidden={readOnly}
            disabled={readOnly || saving || (touched && Object.keys(local).length > 0)}
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
        </Modal.Footer>
      </form>
    </Modal>
  );
}
