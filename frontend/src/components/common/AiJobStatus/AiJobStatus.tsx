import { Button } from '@govtechsg/sgds-react';
import type { AiJob } from '@/features/aiJobs/aiJobs.types';
import { clock, placeInLine, runningFor, shortDuration } from '@/features/aiJobs/aiJobText';
import { useNow } from '@/features/aiJobs/useNow';
import './AiJobStatus.css';

interface Props {
  job: AiJob;
  /** What it's doing, e.g. "Rewriting the story". */
  doing: string;
  /** What happens when it's done, e.g. "The new story replaces this one when it's ready." */
  whenDone: string;
  onCancel?: () => void;
  cancelling?: boolean;
}

/**
 * A background AI job, shown where it was asked for: waiting (its place in line, Cancel) or
 * running (how long so far, how long it usually takes). The page around it stays usable.
 */
export function AiJobStatus({ job, doing, whenDone, onCancel, cancelling }: Props) {
  const now = useNow();
  const waiting = job.status === 'WAITING';
  const elapsed = runningFor(job, now);
  const typical = job.typicalMs ?? null;
  const share = typical ? Math.min(0.95, elapsed / typical) : null;

  return (
    <div className="ai-job-status" role="status" data-testid="ai-job-status">
      <i className={`bi ${waiting ? 'bi-hourglass-split' : 'bi-stars'} ai-job-status-icon`} aria-hidden="true" />
      <div className="ai-job-status-text">
        {waiting ? (
          <>
            <strong>Waiting for the model</strong>
            <span className="text-muted"> · {placeInLine(job.position)} · asked {clock(job.createdAt)}</span>
            <div className="text-muted small">
              It starts as soon as the model is free. You can leave this page or reload it. {whenDone}
            </div>
          </>
        ) : (
          <>
            <strong>{doing} in the background</strong>
            <span className="text-muted">
              {' '}· started {clock(job.startedAt)} · {shortDuration(elapsed)} so far
              {typical ? `, usually about ${shortDuration(typical)}` : ''}
            </span>
            <div className="text-muted small">You can leave this page or reload it. {whenDone}</div>
            {share !== null && (
              <div className="ai-job-status-bar" aria-hidden="true">
                <i style={{ width: `${Math.round(share * 100)}%` }} />
              </div>
            )}
          </>
        )}
      </div>
      {waiting && onCancel && (
        <Button size="sm" variant="outline-secondary" onClick={onCancel} disabled={cancelling}>
          Cancel
        </Button>
      )}
    </div>
  );
}
