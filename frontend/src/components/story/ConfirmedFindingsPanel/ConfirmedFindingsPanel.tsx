import { Button, Card, OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import type { Answer } from '@/types';

interface ConfirmedFindingsPanelProps {
  answers: Answer[];
  loading?: boolean;
}

/** Click-toggled help behind the header's info icon — app convention (no native title tooltip). */
function InvestigationSummaryInfoPopover() {
  const popover = (
    <Popover id="info-investigation-summary" style={{ maxWidth: '340px' }}>
      <Popover.Header>Investigation Summary — How it works</Popover.Header>
      <Popover.Body className="small">
        <p className="mb-2">
          These are deterministic answers to the standard investigation questions — who the victim
          is, the C2, the malware, the signed-in user — reached by checks over the extracted evidence
          (IDS signatures, protocol parsing, identity resolution), <strong>not</strong> by the LLM.
          They are the ground truth the narrative is built on.
        </p>
        <p className="mb-0">
          Each answer is labelled with how directly it is known:{' '}
          <strong>Measured</strong> (the traffic exhibited it), <strong>Reported</strong> (a party
          asserted it on the wire), or <strong>Inferred</strong> (a tool judged it) — so it is never
          presented as certain.
        </p>
      </Popover.Body>
    </Popover>
  );
  return (
    <OverlayTrigger trigger="click" placement="right" overlay={popover} rootClose>
      <Button
        type="button"
        variant="link"
        className="p-0 text-muted ms-2"
        style={{ lineHeight: 1 }}
        aria-label="About Investigation Summary"
      >
        <i className="bi bi-info-circle" style={{ fontSize: '0.9rem' }} aria-hidden="true"></i>
      </Button>
    </OverlayTrigger>
  );
}

/** Friendly label + icon per standard-question key; unknown keys fall back to the raw key. */
const QUESTION_META: Record<string, { label: string; icon: string }> = {
  victim: { label: 'Victim host', icon: 'bi-pc-display' },
  c2: { label: 'Command & control', icon: 'bi-broadcast-pin' },
  malware: { label: 'Malware', icon: 'bi-bug' },
  'signed-in-user': { label: 'Signed-in user', icon: 'bi-person-badge' },
  'data-transfer': { label: 'Bulk transfer', icon: 'bi-arrow-up-right-circle' },
};

/** Grade → chip colour: MEASURED strongest, INFERRED weakest. */
const GRADE_STYLE: Record<string, { bg: string; label: string; tip: string }> = {
  MEASURED: { bg: '#198754', label: 'Measured', tip: 'The traffic itself exhibited it — strongest.' },
  REPORTED: { bg: '#b35900', label: 'Reported', tip: 'A party asserted it on the wire — testimony.' },
  INFERRED: { bg: '#6c757d', label: 'Inferred', tip: 'A tool judged it (IDS, classifier) — a guess with error modes.' },
};

/**
 * Surfaces the deterministic standard-question answers (#813) — victim, C2, malware, signed-in
 * user — as a first-class panel, so an analyst sees the confirmed conclusions directly rather than
 * only through the LLM narrative. This is the same data that feeds the narrative's ground-truth
 * block. Renders nothing when there are no answers (a capture with no such findings).
 */
export const ConfirmedFindingsPanel = ({ answers, loading = false }: ConfirmedFindingsPanelProps) => {
  return (
    <Card>
      <Card.Body>
        <h5 className="mb-1 d-flex align-items-center">
          <i className="bi bi-clipboard2-check me-2" aria-hidden="true" />
          Investigation Summary
          <InvestigationSummaryInfoPopover />
        </h5>
        <p className="text-muted small mb-3">
          Deterministic answers to the standard questions, drawn from the evidence — each labelled
          with how directly it is known (measured, reported, or inferred), not asserted as certain.
        </p>

        {loading ? (
          <div className="text-muted small d-flex align-items-center gap-2 py-2">
            <span className="spinner-border spinner-border-sm" role="status" aria-hidden="true" />
            Deriving answers…
          </div>
        ) : answers.length === 0 ? (
          <div className="text-center text-muted py-4">
            <i className="bi bi-clipboard-x d-block mb-2" style={{ fontSize: '1.6rem' }} aria-hidden="true" />
            <div className="small">
              No deterministic answers for this capture — nothing matched the standard questions
              (victim, C2, malware, signed-in user). The narrative below still summarises the traffic.
            </div>
          </div>
        ) : (
        <div className="d-flex flex-column gap-2">
          {answers.map((a, i) => {
            const meta = QUESTION_META[a.question] ?? { label: a.question, icon: 'bi-dot' };
            const grade = GRADE_STYLE[a.grade] ?? { bg: '#6c757d', label: a.grade, tip: '' };
            return (
              <div key={`${a.question}-${i}`} className="border rounded p-2 d-flex align-items-start gap-2">
                <i className={`bi ${meta.icon} text-muted mt-1`} aria-hidden="true" />
                <div className="flex-grow-1 min-w-0">
                  <div className="d-flex align-items-center gap-2 flex-wrap">
                    <span className="fw-semibold" style={{ fontSize: '0.8rem' }}>{meta.label}</span>
                    <span
                      title={grade.tip}
                      style={{
                        fontSize: 9,
                        fontWeight: 600,
                        color: '#fff',
                        background: grade.bg,
                        borderRadius: 3,
                        padding: '1px 5px',
                        cursor: grade.tip ? 'help' : undefined,
                      }}
                    >
                      {grade.label}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.82rem' }}>{a.headline}</div>
                  {a.basis.length > 0 && (
                    <ul className="mb-0 mt-1 ps-3 text-muted" style={{ fontSize: '0.72rem' }}>
                      {a.basis.map((b, j) => (
                        <li key={j}>{b}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            );
          })}
        </div>
        )}
      </Card.Body>
    </Card>
  );
};
