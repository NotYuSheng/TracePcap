import { useCallback, useEffect, useState } from 'react';
import { Button, ProgressBar } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import {
  detectionRulesService,
  type ReapplyJob,
  type RuleSyncStatus,
} from './detectionRulesService';
import { useReapplyJob } from './useReapplyJob';

interface RuleSyncBannerProps {
  /** One capture; omit for the whole install. */
  fileId?: string;
  /** Whether the caller may re-apply (the global rules permission). */
  canReapply: boolean;
  /** Why not, when they can't. */
  reason?: string | null;
  /** Bumped by the parent after a rule edit, to re-check the status. */
  refreshKey?: number;
  /** Called after a Re-apply finishes, so the page can reload what it shows. */
  onReapplied?: () => void;
}

/**
 * What re-scoring the rules' device-type votes changed (#925): never silent, but nothing to clear
 * either. Analyst labels are never changed; the ones the new evidence contradicts are flagged.
 */
function ReclassifiedList({ job }: { job: ReapplyJob }) {
  const changed = job.reclassifiedCount ?? 0;
  const stale = job.staleLabelsCount ?? 0;
  if (changed === 0 && stale === 0) return null;
  const rows = job.reclassified ?? [];
  return (
    <div className="w-100 mt-1" data-testid="reapply-reclassified">
      {changed > 0 && (
        <div>
          <i className="bi bi-arrow-left-right me-1" aria-hidden="true" />
          {changed} host{changed === 1 ? '' : 's'} changed device type, from the rules' new votes:
        </div>
      )}
      {rows.length > 0 && (
        <ul className="mb-1 ps-4">
          {rows.map(r => (
            <li key={`${r.fileId}-${r.ip}`}>
              <span className="font-monospace">{r.ip}</span>: {r.from} → <strong>{r.to}</strong>
              {r.rules.length > 0 && <span className="text-muted"> (rule {r.rules.join(', ')})</span>}
            </li>
          ))}
          {changed > rows.length && <li className="text-muted">and {changed - rows.length} more</li>}
        </ul>
      )}
      {stale > 0 && (
        <div>
          <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />
          {stale} analyst label{stale === 1 ? '' : 's'} now disagree{stale === 1 ? 's' : ''} with the
          evidence and {stale === 1 ? 'is' : 'are'} marked stale. Labels aren't changed; review them on the host.
        </div>
      )}
    </div>
  );
}

function jobLine(job: ReapplyJob): string {
  if (job.status === 'RUNNING')
    return `Re-applying rules: ${job.done + job.failed} of ${job.total} captures…`;
  if (job.status === 'INTERRUPTED')
    return 'The last Re-apply was interrupted by a restart. Start it again to finish.';
  const failed = job.failed ? ` ${job.failed} failed${job.error ? ` (${job.error})` : ''}.` : '';
  return `Re-applied to ${job.done} capture${job.done === 1 ? '' : 's'}.${failed}`;
}

/**
 * Whether matches are up to date with the rules (#925 phase 2), and Re-apply. Editing a rule
 * doesn't change past captures' matches by itself; this says which captures are out of date, and
 * re-checks them on request.
 */
export function RuleSyncBanner({
  fileId,
  canReapply,
  reason,
  refreshKey = 0,
  onReapplied,
}: RuleSyncBannerProps) {
  const [status, setStatus] = useState<RuleSyncStatus | null>(null);
  const [reload, setReload] = useState(0);
  const onFinished = useCallback(() => {
    setReload(n => n + 1);
    onReapplied?.();
  }, [onReapplied]);
  const { job, error, start, follow } = useReapplyJob(onFinished);

  useEffect(() => {
    const load = fileId ? detectionRulesService.fileStatus(fileId) : detectionRulesService.status();
    load.then(setStatus).catch(() => setStatus(null));
  }, [fileId, refreshKey, reload]);

  // Pick up a job that's already running (started elsewhere, or before a page reload).
  useEffect(() => {
    detectionRulesService
      .recentJobs()
      .then(jobs => {
        const running = jobs.find(
          j => j.status === 'RUNNING' && (!fileId || !j.fileId || j.fileId === fileId)
        );
        if (running) follow(running);
      })
      .catch(() => undefined);
  }, [fileId, follow]);

  if (!status) return null;
  const running = job?.status === 'RUNNING';
  const stale = fileId ? status.staleRules.length : status.staleCaptures;
  const uncheckable = fileId ? status.uncheckableRules.length : status.uncheckableCaptures;
  if (!running && !job && stale === 0 && uncheckable === 0) return null;

  return (
    <div data-testid="rule-sync-banner">
      {running && job && (
        <Alert variant="info" className="py-2">
          <div className="small mb-1">{jobLine(job)}</div>
          <ProgressBar
            now={job.total ? ((job.done + job.failed) / job.total) * 100 : 0}
            style={{ height: 6 }}
          />
        </Alert>
      )}
      {!running && job && (
        <Alert
          variant={job.status === 'DONE' && !job.failed ? 'success' : 'warning'}
          className="py-2 small d-flex flex-wrap align-items-center gap-2"
        >
          <span className="me-auto">{jobLine(job)}</span>
          {fileId && job.status === 'DONE' && (
            <Button size="sm" variant="outline-primary" onClick={() => window.location.reload()}>
              Show updated matches
            </Button>
          )}
          <ReclassifiedList job={job} />
        </Alert>
      )}
      {error && (
        <Alert variant="danger" className="py-2 small">
          {error}
        </Alert>
      )}
      {!running && stale > 0 && (
        <Alert variant="warning" className="py-2 small d-flex flex-wrap align-items-center gap-2">
          <span className="me-auto">
            <i className="bi bi-arrow-repeat me-1" aria-hidden="true" />
            {fileId ? (
              <>
                {stale} detection rule{stale === 1 ? '' : 's'} changed or added since this capture
                was checked: <strong>{status.staleRules.join(', ')}</strong>. Its matches may be out
                of date.
              </>
            ) : (
              <>
                {stale} of {status.captures} capture{status.captures === 1 ? '' : 's'} haven't been
                checked against the current rules, so their matches may be out of date.
              </>
            )}
            {!canReapply && reason && <> You can't re-apply: {reason}</>}
          </span>
          <Button size="sm" variant="primary" onClick={() => start(fileId)} disabled={!canReapply}>
            {fileId
              ? 'Re-apply to this capture'
              : `Re-apply to ${stale} capture${stale === 1 ? '' : 's'}`}
          </Button>
        </Alert>
      )}
      {uncheckable > 0 && (
        <Alert variant="secondary" className="py-2 small">
          <i className="bi bi-exclamation-circle me-1" aria-hidden="true" />
          {fileId ? (
            <>
              Couldn't re-check <strong>{status.uncheckableRules.join(', ')}</strong>: these rules
              look inside packets, and retention deleted this capture's packets. Their matches
              aren't shown.
            </>
          ) : (
            <>
              {uncheckable} capture{uncheckable === 1 ? '' : 's'} couldn't be re-checked against
              rules that look inside packets, because retention deleted their packets. Those matches
              aren't shown.
            </>
          )}
        </Alert>
      )}
    </div>
  );
}
