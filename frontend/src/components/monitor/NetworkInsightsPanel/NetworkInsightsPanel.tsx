import { useState } from 'react';
import { Badge, Button } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import type { NetworkInsight, InsightAudience, InsightFocus, InsightOptions } from '@/features/insights/types/insights.types';

interface NetworkInsightsPanelProps {
  insight: NetworkInsight | null;
  llmAvailable: boolean;
  onGenerate: (options: InsightOptions) => Promise<void>;
}

const SEVERITY_VARIANT: Record<string, string> = {
  HIGH: 'danger',
  MEDIUM: 'warning',
  LOW: 'info',
};

const AUDIENCE_OPTIONS: { value: InsightAudience; label: string; desc: string }[] = [
  { value: 'TECHNICAL',  label: 'Technical',  desc: 'IPs, MACs, protocol names verbatim — for active investigators' },
  { value: 'EXECUTIVE',  label: 'Executive',  desc: 'Plain English, business impact — no jargon' },
  { value: 'OT',         label: 'OT / ICS',   desc: 'Framed around operational & industrial impact' },
];

const FOCUS_OPTIONS: { value: InsightFocus; label: string; desc: string }[] = [
  { value: 'SECURITY',    label: 'Security',    desc: 'Suspicious patterns, ARP spoofing, lateral movement leads' },
  { value: 'OPERATIONAL', label: 'Operational', desc: 'Expected vs unexpected from a network ops perspective' },
  { value: 'COMPLIANCE',  label: 'Compliance',  desc: 'Baseline deviations, reviewed vs unreviewed events' },
];

const AUDIENCE_LABELS: Record<string, string> = { TECHNICAL: 'Technical', EXECUTIVE: 'Executive', OT: 'OT / ICS' };
const FOCUS_LABELS:    Record<string, string> = { SECURITY: 'Security', OPERATIONAL: 'Operational', COMPLIANCE: 'Compliance' };

export const NetworkInsightsPanel = ({
  insight,
  llmAvailable,
  onGenerate,
}: NetworkInsightsPanelProps) => {
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showOptions, setShowOptions] = useState(false);
  const [audience, setAudience] = useState<InsightAudience>('TECHNICAL');
  const [focus, setFocus]       = useState<InsightFocus>('SECURITY');

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    try {
      await onGenerate({ audience, focus });
    } catch {
      setError('Failed to generate insights. Check that the LLM server is reachable.');
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div>
      {!llmAvailable && (
        <Alert variant="warning" className="py-2 small mb-3">
          <i className="bi bi-exclamation-triangle me-1" />
          No LLM server configured. Set <code>LLM_BASE_URL</code> in your environment to enable
          AI-generated insights.
        </Alert>
      )}

      {/* Controls row */}
      <div className="d-flex align-items-center justify-content-between mb-3 gap-2 flex-wrap">
        <button
          type="button"
          className="btn btn-link btn-sm p-0 text-muted d-flex align-items-center gap-1"
          style={{ fontSize: '0.82rem', textDecoration: 'none' }}
          onClick={() => setShowOptions(v => !v)}
        >
          <i className={`bi bi-gear${showOptions ? '-fill' : ''}`} />
          Options
          {(audience !== 'TECHNICAL' || focus !== 'SECURITY') && (
            <span className="badge bg-primary ms-1" style={{ fontSize: '0.6rem' }}>custom</span>
          )}
          <i className={`bi bi-chevron-${showOptions ? 'up' : 'down'} ms-1`} style={{ fontSize: '0.7rem' }} />
        </button>

        <Button
          size="sm"
          variant={insight ? 'outline-secondary' : 'primary'}
          onClick={handleGenerate}
          disabled={generating || !llmAvailable}
        >
          {generating ? (
            <><Spinner animation="border" size="sm" className="me-1" />Generating…</>
          ) : (
            <><i className="bi bi-stars me-1" />{insight ? 'Regenerate' : 'Generate Insights'}</>
          )}
        </Button>
      </div>

      {/* Options panel */}
      {showOptions && (
        <div className="border rounded p-3 mb-3 bg-light" style={{ fontSize: '0.85rem' }}>
          <div className="row g-3">
            <div className="col-sm-6">
              <div className="fw-semibold mb-2 text-muted" style={{ fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Audience
              </div>
              <div className="d-flex flex-column gap-1">
                {AUDIENCE_OPTIONS.map(opt => (
                  <label
                    key={opt.value}
                    className={`d-flex align-items-start gap-2 p-2 rounded border ${audience === opt.value ? 'border-primary bg-white' : 'border-transparent'}`}
                    style={{ cursor: 'pointer' }}
                  >
                    <input
                      type="radio"
                      name="insight-audience"
                      className="mt-1 flex-shrink-0"
                      checked={audience === opt.value}
                      onChange={() => setAudience(opt.value)}
                    />
                    <div>
                      <div className="fw-semibold">{opt.label}</div>
                      <div className="text-muted" style={{ fontSize: '0.75rem' }}>{opt.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>
            <div className="col-sm-6">
              <div className="fw-semibold mb-2 text-muted" style={{ fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Focus
              </div>
              <div className="d-flex flex-column gap-1">
                {FOCUS_OPTIONS.map(opt => (
                  <label
                    key={opt.value}
                    className={`d-flex align-items-start gap-2 p-2 rounded border ${focus === opt.value ? 'border-primary bg-white' : 'border-transparent'}`}
                    style={{ cursor: 'pointer' }}
                  >
                    <input
                      type="radio"
                      name="insight-focus"
                      className="mt-1 flex-shrink-0"
                      checked={focus === opt.value}
                      onChange={() => setFocus(opt.value)}
                    />
                    <div>
                      <div className="fw-semibold">{opt.label}</div>
                      <div className="text-muted" style={{ fontSize: '0.75rem' }}>{opt.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {error && <Alert variant="danger" className="py-2 small mb-3">{error}</Alert>}

      {!insight && !generating && (
        <div className="text-center text-muted py-4">
          <i className="bi bi-lightbulb display-6 d-block mb-2 text-muted" />
          <p className="mb-1">No insights generated yet.</p>
          <small>
            Click <strong>Generate Insights</strong> to have the AI analyse this network's changes,
            node roles, and external events.
          </small>
        </div>
      )}

      {insight?.status === 'FAILED' && (
        <Alert variant="danger" className="small">
          <strong>Generation failed:</strong> {insight.errorMessage ?? 'Unknown error'}
        </Alert>
      )}

      {insight?.status === 'COMPLETED' && (
        <div>
          {/* Summary */}
          {insight.summary && (
            <div className="p-3 rounded bg-light mb-4 border-start border-primary border-3">
              <p className="mb-0 small">{insight.summary}</p>
            </div>
          )}

          {/* Narrative sections */}
          {insight.narrativeSections && insight.narrativeSections.length > 0 && (
            <div className="mb-4">
              {insight.narrativeSections.map((section, i) => (
                <div key={i} className="mb-3">
                  <h6 className="fw-semibold mb-1">{section.title}</h6>
                  <p className="small text-muted mb-0" style={{ whiteSpace: 'pre-wrap' }}>
                    {section.content}
                  </p>
                </div>
              ))}
            </div>
          )}

          {/* Anomalies */}
          {insight.anomalies && insight.anomalies.length > 0 && (
            <div className="mb-4">
              <h6 className="border-bottom pb-1 mb-2">
                <i className="bi bi-exclamation-diamond me-1" />Anomalies
              </h6>
              {insight.anomalies.map((a, i) => (
                <div key={i} className="d-flex align-items-start gap-2 mb-2">
                  <Badge
                    bg={SEVERITY_VARIANT[a.severity] ?? 'secondary'}
                    text={a.severity === 'MEDIUM' ? 'dark' : undefined}
                    className="flex-shrink-0 mt-1"
                    style={{ fontSize: '0.65rem' }}
                  >
                    {a.severity}
                  </Badge>
                  <div>
                    <div className="small fw-semibold">{a.title}</div>
                    <div className="text-muted" style={{ fontSize: '0.8rem' }}>{a.description}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Correlations */}
          {insight.correlations && insight.correlations.length > 0 && (
            <div className="mb-4">
              <h6 className="border-bottom pb-1 mb-2">
                <i className="bi bi-link-45deg me-1" />Event Correlations
              </h6>
              <div className="border rounded overflow-hidden">
                <table className="table table-sm table-hover align-middle mb-0">
                  <thead className="table-light">
                    <tr>
                      <th className="text-muted fw-normal">External Event</th>
                      <th className="text-muted fw-normal">Network Change</th>
                      <th className="text-muted fw-normal">Explanation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {insight.correlations.map((c, i) => (
                      <tr key={i}>
                        <td className="small">{c.externalEvent}</td>
                        <td className="small">{c.networkChange}</td>
                        <td className="small text-muted">{c.explanation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Recommendations */}
          {insight.recommendations && insight.recommendations.length > 0 && (
            <div className="mb-4">
              <h6 className="border-bottom pb-1 mb-2">
                <i className="bi bi-check2-square me-1" />Recommendations
              </h6>
              <ol className="ps-4 mb-0">
                {insight.recommendations.map((r, i) => (
                  <li key={i} className="small mb-1">{r}</li>
                ))}
              </ol>
            </div>
          )}

          {/* Footer */}
          <div className="text-muted border-top pt-2 mt-2 d-flex flex-wrap gap-2 align-items-center" style={{ fontSize: '0.7rem' }}>
            <span>Generated {new Date(insight.generatedAt).toLocaleString('en-GB')}</span>
            {insight.modelUsed && <span>· {insight.modelUsed}</span>}
            {insight.audience && (
              <span className="badge bg-light text-muted border" style={{ fontSize: '0.65rem', fontWeight: 400 }}>
                {AUDIENCE_LABELS[insight.audience] ?? insight.audience}
              </span>
            )}
            {insight.focus && (
              <span className="badge bg-light text-muted border" style={{ fontSize: '0.65rem', fontWeight: 400 }}>
                {FOCUS_LABELS[insight.focus] ?? insight.focus}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
