import { Link } from 'react-router-dom';
import { Modal } from '@govtechsg/sgds-react';
import type { Answer } from '@/types';

/** Grade → chip colour and wording, as on the answer itself. */
const GRADE: Record<string, { bg: string; label: string }> = {
  MEASURED: { bg: '#198754', label: 'Measured' },
  REPORTED: { bg: '#b35900', label: 'Reported' },
  INFERRED: { bg: '#6c757d', label: 'Inferred' },
};

/** At most this many conversation links per step; the rest are counted. */
const LINKS_SHOWN = 3;

interface DerivationModalProps {
  answer: Answer;
  label: string;
  show: boolean;
  onHide: () => void;
  /** The capture, so a step can link to its conversations; links are left out without it. */
  fileId?: string;
}

/**
 * How a deterministic answer was reached, step by step (#1293): what each check found, the rule
 * that took it to the next claim, how directly each is known, and the conversations it rests on.
 * The steps come from the checks themselves, so they are what the code did, not a summary of it.
 */
export function DerivationModal({ answer, label, show, onHide, fileId }: DerivationModalProps) {
  const steps = answer.derivation ?? [];
  return (
    <Modal show={show} onHide={onHide} size="lg" centered>
      <Modal.Header closeButton>
        <Modal.Title as="h5">How we got here: {label}</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <p className="text-muted small">
          Deterministic checks over the capture, no LLM. Each step is what was found, and the rule
          that took it to the next claim; steps without a rule are context.
        </p>
        <ol className="ps-3 mb-3">
          {steps.map((s, i) => {
            const g = GRADE[s.grade] ?? { bg: '#6c757d', label: s.grade };
            const links = fileId ? s.conversations.slice(0, LINKS_SHOWN) : [];
            const more = fileId ? s.conversations.length - links.length : 0;
            return (
              <li key={i} className="mb-3" data-testid="derivation-step">
                <div className="d-flex align-items-start gap-2">
                  <span style={{ overflowWrap: 'anywhere' }}>{s.found}</span>
                  <span
                    className="flex-shrink-0"
                    style={{ fontSize: 9, fontWeight: 600, color: '#fff', background: g.bg, borderRadius: 3, padding: '1px 5px', marginTop: 3 }}
                  >
                    {g.label}
                  </span>
                </div>
                {s.rule && (
                  <div className="text-muted small mt-1">
                    <i className="bi bi-arrow-return-right me-1" aria-hidden="true" />
                    <strong>Rule:</strong> {s.rule}
                  </div>
                )}
                {links.length > 0 && (
                  <div className="small mt-1 d-flex flex-wrap gap-2">
                    {links.map((id, j) => (
                      <Link key={`${id}-${j}`} to={`/analysis/${fileId}/conversations?highlight=${encodeURIComponent(id)}`} onClick={onHide}>
                        Conversation {j + 1} <i className="bi bi-arrow-right-short" aria-hidden="true" />
                      </Link>
                    ))}
                    {more > 0 && <span className="text-muted">and {more} more</span>}
                  </div>
                )}
              </li>
            );
          })}
        </ol>
        <div className="border-top pt-2 small">
          <strong>Answer:</strong> {answer.headline}
        </div>
      </Modal.Body>
    </Modal>
  );
}
