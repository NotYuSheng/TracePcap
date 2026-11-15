import { useMemo, useState } from 'react';
import { Form } from '@govtechsg/sgds-react';
import { Pagination } from '@components/common/Pagination/Pagination';
import { ChangeEventBadge } from '@/components/monitor/ChangeEventBadge/ChangeEventBadge';
import { changeKind, changeSummary, describeEvent } from '@/features/monitor/utils/describeChange';
import type { ChangeEvent, NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import './ChangeList.css';

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, WARNING: 1, INFO: 2 };

interface ChangeListProps {
  events: ChangeEvent[];
  snapshots: NetworkSnapshot[];
  onPatch: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
  pageSize?: number;
  /** For a narrow column: compact rows. */
  compact?: boolean;
  /** Offer the "Unreviewed only" filter (pointless when the list is already unreviewed only). */
  reviewFilter?: boolean;
}

/**
 * A capture's changes, most severe first: a one-line summary by kind, a search box once there are
 * more than a page, and pages instead of one long scroll.
 */
export function ChangeList({
  events,
  snapshots,
  onPatch,
  pageSize = 8,
  compact = false,
  reviewFilter = true,
}: ChangeListProps) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<'ALL' | 'CRITICAL' | 'WARNING' | 'INFO'>('ALL');
  const [kind, setKind] = useState('ALL');
  const [reviewed, setReviewed] = useState<'ALL' | 'UNREVIEWED' | 'REVIEWED'>('ALL');
  const [page, setPage] = useState(1);
  const kinds = useMemo(() => [...new Set(events.map(changeKind))].sort(), [events]);
  const severityCount = (s: string) => events.filter(e => e.severity === s).length;

  const sorted = useMemo(
    () =>
      [...events].sort(
        (a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3) || b.detectedAt.localeCompare(a.detectedAt)
      ),
    [events]
  );
  const q = query.trim().toLowerCase();
  const shown = sorted.filter(
    e =>
      (severity === 'ALL' || e.severity === severity) &&
      (kind === 'ALL' || changeKind(e) === kind) &&
      (reviewed === 'ALL' || (reviewed === 'REVIEWED') === e.reviewed) &&
      (!q || describeEvent(e).toLowerCase().includes(q))
  );
  const reset = () => setPage(1);
  const pages = Math.max(1, Math.ceil(shown.length / pageSize));
  const current = Math.min(page, pages);
  const slice = shown.slice((current - 1) * pageSize, current * pageSize);
  // Filters once there's enough to filter; a handful of changes reads fine as it is.
  const filterable = events.length > 3;

  return (
    <div className={`change-list${compact ? ' change-list-compact' : ''}`}>
      {events.length > 1 && <p className="change-list-summary">{changeSummary(events)}</p>}
      {filterable && (
        <div className="change-list-tools">
          <div className="change-list-severity" role="group" aria-label="Severity">
            {(['ALL', 'CRITICAL', 'WARNING', 'INFO'] as const).map(sv => {
              const n = sv === 'ALL' ? events.length : severityCount(sv);
              if (sv !== 'ALL' && n === 0) return null;
              return (
                <button
                  key={sv}
                  type="button"
                  className={`change-list-chip${severity === sv ? ' active' : ''}`}
                  aria-pressed={severity === sv}
                  onClick={() => {
                    setSeverity(sv);
                    reset();
                  }}
                >
                  {sv === 'ALL' ? 'All' : sv.charAt(0) + sv.slice(1).toLowerCase()}
                  <span className="change-list-chip-count">{n}</span>
                </button>
              );
            })}
          </div>
          {kinds.length > 1 && (
            <Form.Select
              size="sm"
              aria-label="Kind of change"
              value={kind}
              onChange={e => {
                setKind(e.target.value);
                reset();
              }}
            >
              <option value="ALL">Every kind</option>
              {kinds.map(k => (
                <option key={k} value={k}>
                  {k.charAt(0).toUpperCase() + k.slice(1)}
                </option>
              ))}
            </Form.Select>
          )}
          {reviewFilter && (
            <Form.Select
              size="sm"
              aria-label="Reviewed"
              value={reviewed}
              onChange={e => {
                setReviewed(e.target.value as typeof reviewed);
                reset();
              }}
            >
              <option value="ALL">Reviewed or not</option>
              <option value="UNREVIEWED">Unreviewed</option>
              <option value="REVIEWED">Reviewed</option>
            </Form.Select>
          )}
          <Form.Control
            size="sm"
            type="search"
            placeholder="Search: MAC, address, app…"
            aria-label="Search changes"
            value={query}
            onChange={e => {
              setQuery(e.target.value);
              reset();
            }}
          />
        </div>
      )}
      {slice.map(e => (
        <ChangeEventBadge key={e.id} event={e} snapshots={snapshots} onPatch={onPatch} compact={compact} />
      ))}
      {shown.length === 0 && <p className="change-list-empty">No changes match.</p>}
      {pages > 1 && (
        <div className="change-list-pages">
          <Pagination currentPage={current} totalPages={pages} totalItems={shown.length} pageSize={pageSize} onPageChange={setPage} compact />
        </div>
      )}
    </div>
  );
}
