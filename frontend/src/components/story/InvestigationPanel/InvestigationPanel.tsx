import { useState } from 'react';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import type { InvestigationStep } from '@/types';

interface InvestigationPanelProps {
  steps: InvestigationStep[];
}

function InfoPopover() {
  const popover = (
    <Popover id="info-investigation" style={{ maxWidth: '340px' }}>
      <Popover.Header>Investigation — How it works</Popover.Header>
      <Popover.Body className="small">
        <p className="mb-2">Before writing the narrative, the LLM analyses the deterministic findings and traffic timeline, then generates hypotheses and targeted queries to retrieve real conversation evidence from the database.</p>
        <p className="mb-2">Each query returns the top 10 matching conversations by volume. The LLM uses this evidence to confirm or refute its hypotheses in the final narrative.</p>
        <p className="mb-0"><strong>Limitations:</strong> Query generation is LLM-driven and may not cover every finding. Queries cap at 5 per generation.</p>
      </Popover.Body>
    </Popover>
  );
  return (
    <OverlayTrigger trigger="click" placement="right" overlay={popover} rootClose>
      <button type="button" className="btn btn-link p-0 text-muted ms-2" style={{ lineHeight: 1 }} aria-label="About Investigation">
        <i className="bi bi-info-circle" style={{ fontSize: '0.9rem' }}></i>
      </button>
    </OverlayTrigger>
  );
}

const confidenceBadge: Record<string, string> = {
  HIGH: 'bg-danger',
  MEDIUM: 'bg-warning text-dark',
  LOW: 'bg-secondary',
};

function formatBytes(bytes: number): string {
  if (bytes > 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function QueryResultTable({ step }: { step: InvestigationStep }) {
  const [expanded, setExpanded] = useState(false);

  const hasResults = step.conversations.length > 0;

  return (
    <div className="border rounded mb-2">
      <button
        className="btn btn-link w-100 text-start text-decoration-none p-3 d-flex align-items-center justify-content-between"
        onClick={() => setExpanded(e => !e)}
        type="button"
      >
        <div className="d-flex align-items-center gap-2 flex-wrap">
          <span className="badge bg-secondary font-monospace">{step.query.id}</span>
          <span className="fw-semibold small">{step.query.label}</span>
          {step.hypothesis && (
            <span className={`badge ${confidenceBadge[step.hypothesis.confidence] ?? 'bg-secondary'}`}>
              {step.hypothesis.confidence}
            </span>
          )}
        </div>
        <div className="d-flex align-items-center gap-2 text-muted small flex-shrink-0 ms-2">
          <span>{step.conversationCount} conversation{step.conversationCount !== 1 ? 's' : ''}</span>
          <i className={`bi bi-chevron-${expanded ? 'up' : 'down'}`}></i>
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3">
          {step.hypothesis && (
            <p className="text-muted small mb-2 fst-italic">
              <i className="bi bi-lightbulb me-1"></i>
              {step.hypothesis.hypothesis}
            </p>
          )}

          {!hasResults && (
            <p className="text-muted small mb-0">No matching conversations found.</p>
          )}

          {hasResults && (
            <>
              <div className="table-responsive">
                <table className="table table-sm table-hover mb-0" style={{ fontSize: '0.78rem' }}>
                  <thead className="table-light">
                    <tr>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Port</th>
                      <th>Proto</th>
                      <th>App</th>
                      <th>Bytes</th>
                      <th>Start</th>
                      <th>Risks</th>
                    </tr>
                  </thead>
                  <tbody>
                    {step.conversations.map((conv, i) => (
                      <tr key={i}>
                        <td className="font-monospace">{conv.srcIp}</td>
                        <td className="font-monospace">{conv.dstIp}</td>
                        <td>{conv.dstPort}</td>
                        <td>{conv.protocol}</td>
                        <td>{conv.appName ?? '-'}</td>
                        <td>{conv.totalBytes != null ? formatBytes(conv.totalBytes) : '-'}</td>
                        <td className="text-muted">{conv.startTime ? conv.startTime.substring(11, 19) : '-'}</td>
                        <td>
                          {conv.flowRisks && conv.flowRisks.length > 0
                            ? conv.flowRisks.map(r => (
                                <span key={r} className="badge bg-danger me-1" style={{ fontSize: '0.65rem' }}>{r}</span>
                              ))
                            : <span className="text-muted">-</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {step.conversationCount > step.conversations.length && (
                <p className="text-muted small mt-1 mb-0">
                  Showing top {step.conversations.length} of {step.conversationCount.toLocaleString()} total matches.
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

export const InvestigationPanel = ({ steps }: InvestigationPanelProps) => {
  const hypothesisCount = steps.filter(s => s.hypothesis != null).length;
  const withEvidenceCount = steps.filter(s => s.conversationCount > 0).length;

  return (
    <div className="card">
      <div className="card-header d-flex align-items-center justify-content-between">
        <h6 className="mb-0 d-flex align-items-center">
          <i className="bi bi-search me-2"></i>
          LLM Investigation
          <InfoPopover />
        </h6>
        <div className="d-flex gap-2">
          <span className="badge bg-primary">{steps.length} quer{steps.length !== 1 ? 'ies' : 'y'}</span>
          <span className="badge bg-secondary">{hypothesisCount} hypothesis{hypothesisCount !== 1 ? 'es' : ''}</span>
          <span className="badge bg-success">{withEvidenceCount} with evidence</span>
        </div>
      </div>
      <div className="card-body">
        <p className="text-muted small mb-3">
          The LLM analysed the findings and timeline, then issued {steps.length} targeted quer{steps.length !== 1 ? 'ies' : 'y'} to retrieve real conversation evidence before writing the narrative.
        </p>
        {steps.map(step => (
          <QueryResultTable key={step.query.id} step={step} />
        ))}
      </div>
    </div>
  );
};
