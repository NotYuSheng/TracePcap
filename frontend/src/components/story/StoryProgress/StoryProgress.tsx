import { Card } from '@govtechsg/sgds-react';

interface StoryProgressProps {
  elapsedSeconds: number;
  timeoutLabel: string;
}

/**
 * Typical local-model story generation time. The bar is paced against this and eased toward — but
 * never reaching — 100%, so it can't claim "done" before the real story arrives (this view unmounts
 * at that point). It's an *estimated* progression: TracePcap generates the story in one synchronous
 * call with no per-phase feed, so steps advance on elapsed time, not a server-reported percentage.
 */
const ESTIMATED_TOTAL_SEC = 255;
const CEILING = 96;

/** The real phases of story generation, each with the progress % at which it is considered done. */
const STEPS: { label: string; completeAt: number }[] = [
  { label: 'Running deterministic analysis — findings, aggregates, timeline', completeAt: 6 },
  { label: 'Investigating the capture — the model runs evidence queries (slowest step)', completeAt: 55 },
  { label: 'Writing the narrative from the confirmed findings', completeAt: 92 },
  { label: 'Finalising the story', completeAt: 100 },
];

export function StoryProgress({ elapsedSeconds, timeoutLabel }: StoryProgressProps) {
  const pct = Math.min(CEILING, Math.round((elapsedSeconds / ESTIMATED_TOTAL_SEC) * CEILING));
  const minutes = Math.floor(elapsedSeconds / 60);
  const seconds = elapsedSeconds % 60;
  const elapsed = minutes > 0 ? `${minutes}m ${seconds.toString().padStart(2, '0')}s` : `${seconds}s`;

  const stepState = (index: number): 'completed' | 'active' | 'pending' => {
    const startAt = index === 0 ? 0 : STEPS[index - 1].completeAt;
    if (pct >= STEPS[index].completeAt) return 'completed';
    if (pct >= startAt) return 'active';
    return 'pending';
  };

  return (
    <div className="row justify-content-center py-4">
      <div className="col-lg-8">
        <Card>
          <Card.Body className="p-4 p-md-5">
            <div className="text-center mb-4">
              <i className="bi bi-journal-text text-primary" style={{ fontSize: '2.5rem' }} aria-hidden="true" />
              <h4 className="mt-3 mb-1">Generating the network traffic story</h4>
              <p className="text-muted mb-0">
                Deterministic analysis has run; the model is now investigating the capture and writing the narrative.
              </p>
            </div>

            <div className="mb-4">
              {STEPS.map((step, i) => {
                const state = stepState(i);
                return (
                  <div key={i} className="d-flex align-items-center mb-3" style={{ opacity: state === 'pending' ? 0.55 : 1 }}>
                    <span className="me-2 d-inline-flex align-items-center justify-content-center" style={{ width: 24 }}>
                      {state === 'completed' ? (
                        <i className="bi bi-check-circle-fill text-success" aria-hidden="true" />
                      ) : state === 'active' ? (
                        <span className="spinner-border spinner-border-sm text-primary" role="status" aria-hidden="true" />
                      ) : (
                        <span
                          className="d-inline-flex align-items-center justify-content-center border rounded-circle text-muted"
                          style={{ width: 20, height: 20, fontSize: '0.7rem' }}
                        >
                          {i + 1}
                        </span>
                      )}
                    </span>
                    <span className={state === 'completed' ? 'text-muted' : ''} style={{ fontSize: '0.9rem' }}>
                      {step.label}
                    </span>
                  </div>
                );
              })}
            </div>

            <div className="progress mb-3" style={{ height: 22 }}>
              <div
                className="progress-bar progress-bar-striped progress-bar-animated"
                role="progressbar"
                style={{ width: `${pct}%` }}
                aria-valuenow={pct}
                aria-valuemin={0}
                aria-valuemax={100}
              >
                {pct}%
              </div>
            </div>

            <div className="text-center">
              <small className="text-muted">
                Elapsed <strong>{elapsed}</strong> · usually ~4 min on a local model · times out at {timeoutLabel}
              </small>
            </div>
          </Card.Body>
        </Card>
      </div>
    </div>
  );
}
