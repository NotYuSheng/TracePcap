import { useState } from 'react';

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
        <button
          key={p}
          type="button"
          className={`btn btn-sm ${value === p ? 'btn-info' : 'btn-outline-secondary'}`}
          style={{ minWidth: 44 }}
          onClick={() => onChange(p)}
        >
          {p}
        </button>
      ))}
      <button
        type="button"
        className={`btn btn-sm ${total !== undefined && value >= total ? 'btn-info' : 'btn-outline-secondary'}`}
        style={{ minWidth: 44 }}
        onClick={() => onChange(total ?? 999999)}
      >
        {total !== undefined ? `All ${total}` : 'All'}
      </button>
      {value !== defaultValue && !presets.includes(value) && (total === undefined || value < total) && (
        <button
          type="button"
          className="btn btn-sm btn-info"
          style={{ minWidth: 44 }}
        >
          {value}
        </button>
      )}
      <div className="input-group input-group-sm" style={{ width: 110 }}>
        <input
          type="number"
          className="form-control form-control-sm"
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
    <div className="card">
      <div
        className="card-header d-flex align-items-center justify-content-between"
        style={{ cursor: 'pointer', userSelect: 'none' }}
        onClick={() => setCollapsed(c => !c)}
      >
        <h6 className="mb-0">
          <i className="bi bi-info-circle me-2"></i>
          How Stories Are Generated &amp; Limitations
        </h6>
        <i className={`bi bi-chevron-${collapsed ? 'down' : 'up'} text-muted`}></i>
      </div>
      {!collapsed && (
        <div className="card-body">
          <p className="text-muted small mb-2">
            The following data is sent to the configured LLM to generate the narrative:
          </p>
          <ul className="small text-muted mb-3">
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
              <label className="form-label small fw-semibold mb-2">
                Prompt limits{' '}
                <span className="text-muted fw-normal">
                  (reduce if generation fails due to context length)
                </span>
              </label>
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
              <label className="form-label small fw-semibold mb-1">
                Additional context <span className="text-muted fw-normal">(optional)</span>
              </label>
              <textarea
                className="form-control form-control-sm"
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
        </div>
      )}
    </div>
  );
};
