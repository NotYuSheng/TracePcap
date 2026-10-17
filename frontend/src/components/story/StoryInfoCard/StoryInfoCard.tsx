import { useState } from 'react';
import { Button, Card, Form } from '@govtechsg/sgds-react';

interface StoryInfoCardProps {
  additionalContext?: string;
  onAdditionalContextChange?: (value: string) => void;
  maxFindings?: number;
  onMaxFindingsChange?: (value: number) => void;
  totalFindings?: number;
  maxRiskMatrix?: number;
  onMaxRiskMatrixChange?: (value: number) => void;
  totalRiskMatrix?: number;
}

const DEFAULT_MAX_FINDINGS = 20;
const DEFAULT_MAX_RISK_MATRIX = 15;

/** The four pipeline stages, 1–3 deterministic (ground truth), 4 the LLM narrating on top. */
const PIPELINE_STAGES = [
  { icon: 'bi-cpu', title: 'Deterministic analysis', sub: 'Suricata · nDPI · host & identity', llm: false },
  { icon: 'bi-diagram-3', title: 'Knowledge board', sub: 'entities · relationships · findings', llm: false },
  { icon: 'bi-clipboard2-check', title: 'Confirmed answers', sub: 'victim · C2 · malware · user', llm: false },
  { icon: 'bi-robot', title: 'LLM: investigate & narrate', sub: 'names the answers, cannot override', llm: true },
];

/** Dependency-free, theme-aware pipeline diagram: stages as boxes joined by arrows (stacks on mobile). */
function PipelineDiagram() {
  return (
    <div>
      <div className="d-flex flex-column flex-md-row align-items-stretch">
        {PIPELINE_STAGES.map((s, i) => (
          <div key={s.title} className="d-flex flex-column flex-md-row align-items-stretch flex-fill">
            <div
              className={`border rounded p-2 flex-fill text-center ${s.llm ? 'border-info' : 'border-success'}`}
              style={{ minWidth: 0 }}
            >
              <i className={`bi ${s.icon} ${s.llm ? 'text-info' : 'text-success'}`} aria-hidden="true" />
              <div className="fw-semibold" style={{ fontSize: '0.78rem' }}>{s.title}</div>
              <div className="text-muted" style={{ fontSize: '0.68rem' }}>{s.sub}</div>
            </div>
            {i < PIPELINE_STAGES.length - 1 && (
              <div className="d-flex align-items-center justify-content-center text-muted px-1 py-1">
                <i className="bi bi-arrow-down d-md-none" aria-hidden="true" />
                <i className="bi bi-arrow-right d-none d-md-inline" aria-hidden="true" />
              </div>
            )}
          </div>
        ))}
      </div>
      <div className="text-muted mt-1" style={{ fontSize: '0.68rem' }}>
        <span className="text-success">■</span> deterministic ground truth &nbsp;·&nbsp;
        <span className="text-info">■</span> LLM narrates on top
      </div>
    </div>
  );
}

function CapControl({
  label,
  value,
  defaultValue,
  presets,
  total,
  onChange,
}: {
  label: string;
  value: number;
  defaultValue: number;
  presets: number[];
  total?: number;
  onChange: (n: number) => void;
}) {
  const [customInput, setCustomInput] = useState('');
  const applyCustom = () => {
    const n = parseInt(customInput, 10);
    if (!isNaN(n) && n > 0) onChange(n);
    setCustomInput('');
  };

  return (
    <div className="d-flex align-items-center gap-2 flex-wrap">
      <span className="text-muted small fw-semibold" style={{ minWidth: 140 }}>{label}:</span>
      {presets.map(p => (
        <Button
          key={p}
          type="button"
          size="sm"
          variant={value === p ? 'info' : 'outline-secondary'}
          style={{ minWidth: 44 }}
          onClick={() => onChange(p)}
        >
          {p}
        </Button>
      ))}
      <Button
        type="button"
        size="sm"
        variant={total !== undefined && value >= total ? 'info' : 'outline-secondary'}
        style={{ minWidth: 44 }}
        onClick={() => onChange(total ?? 999999)}
      >
        {total !== undefined ? `All ${total}` : 'All'}
      </Button>
      {value !== defaultValue && !presets.includes(value) && (total === undefined || value < total) && (
        <Button
          type="button"
          size="sm"
          variant="info"
          style={{ minWidth: 44 }}
        >
          {value}
        </Button>
      )}
      <div className="input-group input-group-sm" style={{ width: 110 }}>
        <Form.Control
          type="number"
          size="sm"
          placeholder="Custom…"
          min={1}
          value={customInput}
          onChange={e => setCustomInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && applyCustom()}
          onBlur={applyCustom}
        />
      </div>
    </div>
  );
}

export const StoryInfoCard = ({
  additionalContext,
  onAdditionalContextChange,
  maxFindings = DEFAULT_MAX_FINDINGS,
  onMaxFindingsChange,
  totalFindings,
  maxRiskMatrix = DEFAULT_MAX_RISK_MATRIX,
  onMaxRiskMatrixChange,
  totalRiskMatrix,
}: StoryInfoCardProps) => {
  const [collapsed, setCollapsed] = useState(true);

  return (
    <Card style={{ overflow: 'hidden' }}>
      <Card.Header
        className="d-flex align-items-center justify-content-between"
        style={{
          cursor: 'pointer',
          userSelect: 'none',
          borderBottom: collapsed ? 'none' : undefined,
        }}
        // A clickable div is invisible to keyboard users: no focus, no Enter/Space (#723).
        // CLAUDE.md requires role="button" *plus* tabIndex and key handling when an element
        // cannot be a native <button> — Card.Header renders a div, so this is that case.
        role="button"
        tabIndex={0}
        aria-expanded={!collapsed}
        aria-label={`How stories are generated — ${collapsed ? 'expand' : 'collapse'}`}
        onClick={() => setCollapsed(c => !c)}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault(); // Space would otherwise scroll the page
            setCollapsed(c => !c);
          }
        }}
      >
        <h6 className="mb-0">
          <i className="bi bi-info-circle me-2"></i>
          How Stories Are Generated &amp; Limitations
        </h6>
        <i className={`bi bi-chevron-${collapsed ? 'down' : 'up'} text-muted`}></i>
      </Card.Header>
      {!collapsed && (
        <Card.Body>
          <p className="text-muted small mb-2">
            The story is built in stages. Deterministic analysis runs first and produces the ground
            truth; the LLM only investigates and narrates <em>on top of</em> those findings — it does
            not detect, and is instructed never to contradict them.
          </p>

          <PipelineDiagram />

          <p className="text-muted small mb-2 mt-3">
            The following data is sent to the configured LLM (for both the investigation and the
            narrative) to ground it in what was already established deterministically:
          </p>
          <ul className="small text-muted mb-3">
            <li>
              <strong>Confirmed findings</strong> — the deterministic answers to the standard
              investigation questions (victim, C2, malware, signed-in user), each with its confidence
              grade. Sent as authoritative ground truth the model must name and must not contradict.
            </li>
            <li>File metadata, traffic summary, protocol breakdown, category distribution</li>
            <li>
              <strong>Deterministic findings (full dataset)</strong> — pre-computed by 8 detectors
              covering: nDPI risk flags, beacon/C2 patterns, TLS anomalies, volume anomalies,
              fan-out/scanning, long sessions, unknown application traffic, and port-protocol
              mismatches
            </li>
            <li>
              <strong>Full-dataset aggregates</strong> — top external ASNs, protocol risk matrix,
              TLS counts, beacon candidates
            </li>
          </ul>
          <p className="text-muted small mb-2">
            <strong>Not sent to the LLM:</strong>
          </p>
          <ul className="small text-muted mb-3">
            <li>Packet payloads and HTTP bodies</li>
            <li>DNS query names and TLS SNI</li>
            <li>Raw conversation lists (replaced by structured findings)</li>
          </ul>

          {(onMaxFindingsChange || onMaxRiskMatrixChange) && (
            <div className="mt-3 pt-3 border-top">
              <Form.Label className="small fw-semibold mb-2">
                Prompt limits{' '}
                <span className="text-muted fw-normal">
                  (reduce if generation fails due to context length)
                </span>
              </Form.Label>
              <div className="d-flex flex-column gap-2">
                {onMaxFindingsChange && (
                  <CapControl
                    label="Max findings"
                    value={maxFindings}
                    defaultValue={DEFAULT_MAX_FINDINGS}
                    presets={[5, 10, 20, 50]}
                    total={totalFindings}
                    onChange={onMaxFindingsChange}
                  />
                )}
                {onMaxRiskMatrixChange && (
                  <CapControl
                    label="Max risk matrix rows"
                    value={maxRiskMatrix}
                    defaultValue={DEFAULT_MAX_RISK_MATRIX}
                    presets={[5, 10, 15, 30]}
                    total={totalRiskMatrix}
                    onChange={onMaxRiskMatrixChange}
                  />
                )}
              </div>
            </div>
          )}

          {onAdditionalContextChange !== undefined && (
            <div className="mt-3 pt-3 border-top">
              <Form.Label className="small fw-semibold mb-1">
                Additional context <span className="text-muted fw-normal">(optional)</span>
              </Form.Label>
              <Form.Control
                as="textarea"
                size="sm"
                rows={3}
                placeholder={
                  'Help the LLM produce a more relevant story by providing context it cannot see, e.g.:\n' +
                  '• Known actors or devices involved\n' +
                  '• Suspected incident type (e.g. data exfiltration, C2, lateral movement)\n' +
                  '• Purpose of the capture session or environment details\n' +
                  '• Specific IPs, ports, or time ranges to focus on'
                }
                value={additionalContext}
                onChange={e => onAdditionalContextChange(e.target.value)}
              />
            </div>
          )}
        </Card.Body>
      )}
    </Card>
  );
};
