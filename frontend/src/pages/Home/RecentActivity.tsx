import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { meService, type AuditLogEntry } from '@/features/me/meService';
import { kindOf, summarize } from '@/features/me/auditDiff';
import { parseDateTime } from '@/utils/dateUtils';
import { Spinner } from '@components/common/Spinner/Spinner';

/** How many events the feed shows. */
const SHOWN = 6;
/** Lines of people's changes, at most, so captures keep a place in the feed. */
const MAX_CHANGE_LINES = 3;
/** Captures fetched: enough to name the ones edited and to catch any about to be deleted. */
const FILES_FETCHED = 25;
/** Audit entries fetched, grouped into change lines. */
const AUDIT_FETCHED = 30;
/** Warn about a capture's deletion when it is this close. */
const EXPIRY_WARN_MS = 3 * 3600_000;

export interface ActivityFile {
  fileId: string;
  fileName: string;
  uploadedAt: string | number[];
  status: string;
  source?: string;
  packetCount?: number | null;
}

export type Tone = 'done' | 'busy' | 'failed' | 'warn' | 'change';

export interface ActivityEvent {
  key: string;
  at: number;
  tone: Tone;
  text: string;
  link?: { label: string; to: string };
  meta?: string;
  /** Shown instead of "N h ago" (e.g. a deletion that is still to come). */
  whenText?: string;
}

export function ago(ms: number, now: number): string {
  const mins = Math.max(0, Math.floor((now - ms) / 60000));
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  return `${days} d ago`;
}

function inWords(ms: number): string {
  const mins = Math.max(1, Math.round(ms / 60000));
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'}`;
  const hours = Math.round(mins / 60);
  return `${hours} hour${hours === 1 ? '' : 's'}`;
}

/**
 * What happened recently, newest first: captures analysed (or failing), captures about to be
 * deleted, and changes people made (from the audit log).
 */
export function buildActivity(
  files: ActivityFile[],
  audit: AuditLogEntry[],
  retentionHours: number | null,
  now: number
): ActivityEvent[] {
  const events: ActivityEvent[] = [];
  for (const f of files) {
    const at = parseDateTime(f.uploadedAt);
    const to = `/analysis/${f.fileId}`;
    const status = f.status.toUpperCase();
    if (status === 'COMPLETED') {
      events.push({
        key: `f-${f.fileId}`,
        at,
        tone: 'done',
        text: f.source === 'MONITOR' ? 'Snapshot analysed:' : 'Analysed',
        link: { label: f.fileName, to },
        meta: f.packetCount != null ? `${f.packetCount.toLocaleString()} packets` : undefined,
      });
      if (retentionHours && f.source !== 'MONITOR') {
        const left = at + retentionHours * 3600_000 - now;
        if (left > 0 && left <= EXPIRY_WARN_MS) {
          events.push({
            key: `x-${f.fileId}`,
            // Sorted as if it happened now: it needs attention now.
            at: now,
            tone: 'warn',
            text: `Deleted in ${inWords(left)}:`,
            link: { label: f.fileName, to },
            meta: 'Add it to a monitored network to keep it',
            whenText: '',
          });
        }
      }
    } else if (status === 'FAILED') {
      events.push({
        key: `f-${f.fileId}`,
        at,
        tone: 'failed',
        text: 'Analysis failed:',
        link: { label: f.fileName, to },
      });
    } else {
      events.push({
        key: `f-${f.fileId}`,
        at,
        tone: 'busy',
        text: 'Analysing',
        link: { label: f.fileName, to },
      });
    }
  }
  // A run of changes to the same thing by the same person reads as one line, so a busy editing
  // session doesn't push every capture out of the feed. At most three such lines.
  const names = new Map(files.map(f => [f.fileId, f.fileName]));
  const groups: AuditLogEntry[][] = [];
  for (const e of audit) {
    const last = groups[groups.length - 1]?.[0];
    if (
      last &&
      last.targetType === e.targetType &&
      last.targetId === e.targetId &&
      last.actor === e.actor
    ) {
      groups[groups.length - 1].push(e);
    } else {
      groups.push([e]);
    }
  }
  for (const g of groups.slice(0, MAX_CHANGE_LINES)) {
    const latest = g[0];
    const n = g.length;
    const at = new Date(latest.at).getTime();
    if (latest.targetType === 'network-map' && latest.targetId) {
      events.push({
        key: `a-${latest.id}`,
        at,
        tone: 'change',
        text: 'Edited the network map of',
        link: {
          label: names.get(latest.targetId) ?? 'a capture',
          to: `/analysis/${latest.targetId}/network-diagram`,
        },
        meta: `${n === 1 ? summarize(latest) : `${n} changes, latest: ${summarize(latest)}`} · by ${latest.actor}`,
      });
    } else {
      events.push({
        key: `a-${latest.id}`,
        at,
        tone: 'change',
        text:
          n === 1
            ? summarize(latest)
            : `${summarize(latest)}, and ${n - 1} more change${n === 2 ? '' : 's'}`,
        meta: `${kindOf(latest.targetType)} · by ${latest.actor}`,
      });
    }
  }
  return events.sort((a, b) => b.at - a.at).slice(0, SHOWN);
}

export function RecentActivity({ retentionHours }: { retentionHours: number | null }) {
  const [events, setEvents] = useState<ActivityEvent[] | null>(null);
  const [now] = useState(() => Date.now());

  useEffect(() => {
    let alive = true;
    const files = apiClient
      .get<{ data?: ActivityFile[] }>(API_ENDPOINTS.FILES_LIST, {
        params: { sort: 'uploadedAt,desc', page: 1, pageSize: FILES_FETCHED },
      })
      .then(r => r.data.data ?? [])
      .catch(() => [] as ActivityFile[]);
    // The audit log may be closed to this user; the feed then shows captures only.
    const audit = meService
      .getAuditLog(1, AUDIT_FETCHED)
      .then(r => r.data)
      .catch(() => [] as AuditLogEntry[]);
    Promise.all([files, audit]).then(([f, a]) => {
      if (alive) setEvents(buildActivity(f, a, retentionHours, now));
    });
    return () => {
      alive = false;
    };
  }, [retentionHours, now]);

  return (
    <section aria-labelledby="home-activity" className="home-section">
      <div className="home-section-head">
        <h2 id="home-activity">Recent activity</h2>
        <Link to="/settings?tab=audit" className="ms-auto small">
          All changes
        </Link>
      </div>
      <div className="home-card home-activity">
        {events == null && (
          <div className="text-muted small py-3">
            <Spinner animation="border" size="sm" className="me-2" />
            Loading…
          </div>
        )}
        {events?.length === 0 && <p className="text-muted small py-3 mb-0">Nothing yet.</p>}
        {events && events.length > 0 && (
          <ul className="home-events">
            {events.map(e => (
              <li key={e.key} className="home-event">
                <span className={`home-dot home-dot-${e.tone}`} aria-hidden="true" />
                <div className="home-event-body">
                  <div>
                    {e.text}{' '}
                    {e.link && (
                      <Link to={e.link.to} className="fw-semibold">
                        {e.link.label}
                      </Link>
                    )}
                  </div>
                  {e.meta && <div className="home-event-meta">{e.meta}</div>}
                </div>
                <time className="home-event-when" dateTime={new Date(e.at).toISOString()}>
                  {e.whenText ?? ago(e.at, now)}
                </time>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
