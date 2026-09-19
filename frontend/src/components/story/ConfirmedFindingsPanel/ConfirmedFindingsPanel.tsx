import { Card } from '@govtechsg/sgds-react';
import type { Answer } from '@/types';

interface ConfirmedFindingsPanelProps {
  answers: Answer[];
}

/** Friendly label + icon per standard-question key; unknown keys fall back to the raw key. */
const QUESTION_META: Record<string, { label: string; icon: string }> = {
  victim: { label: 'Victim host', icon: 'bi-pc-display' },
  c2: { label: 'Command & control', icon: 'bi-broadcast-pin' },
  malware: { label: 'Malware', icon: 'bi-bug' },
  'signed-in-user': { label: 'Signed-in user', icon: 'bi-person-badge' },
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
export const ConfirmedFindingsPanel = ({ answers }: ConfirmedFindingsPanelProps) => {
  if (answers.length === 0) return null;

  return (
    <Card>
      <Card.Body>
        <h5 className="mb-1 d-flex align-items-center">
          <i className="bi bi-clipboard2-check me-2" aria-hidden="true" />
          Investigation Summary
        </h5>
        <p className="text-muted small mb-3">
          Deterministic answers to the standard questions, drawn from the evidence — each labelled
          with how directly it is known (measured, reported, or inferred), not asserted as certain.
        </p>

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
      </Card.Body>
    </Card>
  );
};
