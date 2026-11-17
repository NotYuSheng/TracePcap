import { useCallback, useEffect, useRef, useState } from 'react';
import { aiJobsService } from './aiJobsService';
import { isActive, type AiJob } from './aiJobs.types';

const POLL_MS = 3000;

interface Handlers<R> {
  onDone?: (result: R, job: AiJob) => void;
  onFailed?: (job: AiJob) => void;
}

/**
 * Follows the background job of one kind for one thing (a capture's story, a network's insights).
 * On mount it picks up a job already waiting or running, so a reload, or coming back to the page,
 * shows it again; while one is active it checks every 3 s and calls onDone / onFailed when it ends.
 */
export function useAiJob<R = unknown>(
  kind: string,
  subjectId: string | null | undefined,
  handlers: Handlers<R>,
  /** For jobs about something finer: one host (IP:10.0.0.5), subnet or conversation. */
  subjectKey?: string | null
) {
  const [tracked, setJob] = useState<AiJob | null>(null);
  // A job followed for another capture, host or network (the page moved on) isn't this one's.
  const job =
    tracked &&
    tracked.kind === kind &&
    (tracked.subjectId ?? null) === (subjectId ?? null) &&
    (tracked.subjectKey ?? null) === (subjectKey ?? null)
      ? tracked
      : null;
  const handlersRef = useRef(handlers);
  useEffect(() => {
    handlersRef.current = handlers;
  });

  useEffect(() => {
    if (!subjectId && !subjectKey) return;
    let alive = true;
    aiJobsService
      .list({ kind, ...(subjectId && { subjectId }), ...(subjectKey && { subjectKey }) })
      .then(list => {
        const active = list.find(j => isActive(j));
        if (alive && active) setJob(active);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [kind, subjectId, subjectKey]);

  useEffect(() => {
    if (!isActive(job)) return;
    const timer = setTimeout(async () => {
      try {
        const next = await aiJobsService.get(job.id);
        setJob(next);
        if (next.status === 'DONE') handlersRef.current.onDone?.(next.result as R, next);
        else if (next.status === 'FAILED') handlersRef.current.onFailed?.(next);
      } catch (err) {
        const status = (err as { response?: { status?: number } })?.response?.status;
        // Gone (the backend restarted): stop following it. Anything else: look again shortly.
        setJob(status === 404 ? null : { ...job });
      }
    }, POLL_MS);
    return () => clearTimeout(timer);
  }, [job]);

  const start = useCallback(async (create: () => Promise<AiJob>) => {
    const created = await create();
    setJob(created);
    // An answer that needed no model time (e.g. explanations already worked out) is DONE at once.
    if (created.status === 'DONE') handlersRef.current.onDone?.(created.result as R, created);
    else if (created.status === 'FAILED') handlersRef.current.onFailed?.(created);
    return created;
  }, []);

  const cancel = useCallback(async () => {
    if (!job) return;
    setJob(await aiJobsService.cancel(job.id));
  }, [job]);

  return { job, active: isActive(job), start, cancel };
}
