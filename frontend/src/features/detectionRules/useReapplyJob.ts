import { useCallback, useEffect, useRef, useState } from 'react';
import { detectionRulesService, errorMessage, type ReapplyJob } from './detectionRulesService';

const POLL_MS = 1500;

export interface ReapplyJobState {
  job: ReapplyJob | null;
  error: string | null;
  /** Starts Re-apply for one capture, or (no argument) every out-of-date one. */
  start: (fileId?: string) => Promise<void>;
  /** Follow a job that was already running (e.g. found on load). */
  follow: (job: ReapplyJob) => void;
}

/**
 * Starts and follows a Re-apply job (#925 phase 2): polls while it runs and calls
 * {@code onFinished} once when it stops.
 */
export function useReapplyJob(onFinished?: (job: ReapplyJob) => void): ReapplyJobState {
  const [job, setJob] = useState<ReapplyJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const finished = useRef(onFinished);
  useEffect(() => {
    finished.current = onFinished;
  }, [onFinished]);

  const start = useCallback(async (fileId?: string) => {
    setError(null);
    try {
      setJob(await detectionRulesService.startReapply(fileId));
    } catch (e) {
      setError(errorMessage(e, "Couldn't start Re-apply."));
    }
  }, []);

  const id = job?.id;
  const running = job?.status === 'RUNNING';
  useEffect(() => {
    if (!id || !running) return;
    let active = true;
    const timer = setInterval(() => {
      detectionRulesService
        .getJob(id)
        .then(j => {
          if (!active) return;
          setJob(j);
          if (j.status !== 'RUNNING') finished.current?.(j);
        })
        .catch(() => undefined);
    }, POLL_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [id, running]);

  return { job, error, start, follow: setJob };
}
