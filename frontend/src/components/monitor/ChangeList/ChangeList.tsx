import { useMemo, useState } from 'react';
import { Form } from '@govtechsg/sgds-react';
import { Pagination } from '@components/common/Pagination/Pagination';
import { ChangeEventBadge } from '@/components/monitor/ChangeEventBadge/ChangeEventBadge';
import { changeSummary, describeEvent } from '@/features/monitor/utils/describeChange';
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
  const [unreviewedOnly, setUnreviewedOnly] = useState(false);
  const [page, setPage] = useState(1);

  const sorted = useMemo(
    () =>
      [...events].sort(
        (a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3) || b.detectedAt.localeCompare(a.detectedAt)
      ),
    [events]
  );
  const q = query.trim().toLowerCase();
  const shown = sorted.filter(
    e => (!unreviewedOnly || !e.reviewed) && (!q || describeEvent(e).toLowerCase().includes(q))
  );
  const pages = Math.max(1, Math.ceil(shown.length / pageSize));
  const current = Math.min(page, pages);
  const slice = shown.slice((current - 1) * pageSize, current * pageSize);
  const big = events.length > pageSize;

  return (
    <div className={`change-list${compact ? ' change-list-compact' : ''}`}>
      {events.length > 1 && <p className="change-list-summary">{changeSummary(events)}</p>}
      {big && (
        <div className="change-list-tools">
          <Form.Control
            size="sm"
            type="search"
            placeholder="Search changes: MAC, address, app…"
            aria-label="Search changes"
            value={query}
            onChange={e => {
              setQuery(e.target.value);
              setPage(1);
            }}
          />
          {reviewFilter && (
            <Form.Check
              id={`unreviewed-${events[0]?.toSnapshotId ?? 'all'}`}
              type="checkbox"
              label="Unreviewed only"
              checked={unreviewedOnly}
              onChange={e => {
                setUnreviewedOnly(e.target.checked);
                setPage(1);
              }}
            />
          )}
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
