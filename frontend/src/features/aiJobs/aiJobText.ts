import type { AiJob } from './aiJobs.types';

/** "next in line", "2nd in line", … */
export function placeInLine(position?: number | null): string {
  if (!position || position <= 1) return 'next in line';
  const n = position;
  const suffix = n % 100 >= 11 && n % 100 <= 13 ? 'th' : ({ 1: 'st', 2: 'nd', 3: 'rd' } as Record<number, string>)[n % 10] ?? 'th';
  return `${n}${suffix} in line`;
}

/** "45 s", "3 min", "1 h 5 min" */
export function shortDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  return `${Math.floor(m / 60)} h${m % 60 ? ` ${m % 60} min` : ''}`;
}

/** Milliseconds since the job started running (0 while it waits). */
export function runningFor(job: AiJob, now: number): number {
  return job.startedAt ? Math.max(0, now - new Date(job.startedAt).getTime()) : 0;
}

export function clock(iso?: string | null): string {
  if (!iso) return '';
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export const KIND_LABEL: Record<string, string> = { STORY: 'Story', INSIGHTS: 'Insights' };

/** Where the job's answer shows up. */
export function jobPath(job: AiJob): string | null {
  if (job.kind === 'STORY') return `/analysis/${job.subjectId}/story`;
  if (job.kind === 'INSIGHTS') return `/monitor/${job.subjectId}`;
  return null;
}
