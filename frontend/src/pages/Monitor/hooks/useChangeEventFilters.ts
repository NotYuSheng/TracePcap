import { useState } from 'react';
import type { ChangeEvent } from '@/features/monitor/types/monitor.types';

export type SeverityFilter = 'ALL' | 'CRITICAL' | 'WARNING' | 'INFO';
export const SEVERITY_FILTERS: SeverityFilter[] = ['ALL', 'CRITICAL', 'WARNING', 'INFO'];
export type ReviewedFilter = 'ALL' | 'UNREVIEWED' | 'REVIEWED';
const EVENT_PAGE_SIZE = 10;

/**
 * Severity / change-type / reviewed filtering + pagination for the Change Events
 * list. Each filter change resets to page 1. Returns the filtered + paged slices
 * along with the available change types derived from the data.
 */
export function useChangeEventFilters(changeEvents: ChangeEvent[]) {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');
  const [changeTypeFilter, setChangeTypeFilter] = useState<string>('ALL');
  const [reviewedFilter, setReviewedFilter] = useState<ReviewedFilter>('UNREVIEWED');
  const [eventPage, setEventPage] = useState(1);

  const changeTypes = ['ALL', ...Array.from(new Set(changeEvents.map(e => e.changeType)))];

  const filteredEvents = changeEvents.filter(e => {
    if (severityFilter !== 'ALL' && e.severity !== severityFilter) return false;
    if (changeTypeFilter !== 'ALL' && e.changeType !== changeTypeFilter) return false;
    if (reviewedFilter === 'UNREVIEWED' && e.reviewed) return false;
    if (reviewedFilter === 'REVIEWED' && !e.reviewed) return false;
    return true;
  });

  const totalEventPages = Math.max(1, Math.ceil(filteredEvents.length / EVENT_PAGE_SIZE));
  const pagedEvents = filteredEvents.slice((eventPage - 1) * EVENT_PAGE_SIZE, eventPage * EVENT_PAGE_SIZE);

  const selectSeverity = (f: SeverityFilter) => { setSeverityFilter(f); setEventPage(1); };
  const selectChangeType = (t: string) => { setChangeTypeFilter(t); setEventPage(1); };
  const selectReviewed = (r: ReviewedFilter) => { setReviewedFilter(r); setEventPage(1); };

  return {
    severityFilter,
    changeTypeFilter,
    reviewedFilter,
    eventPage,
    setEventPage,
    selectSeverity,
    selectChangeType,
    selectReviewed,
    changeTypes,
    filteredEvents,
    pagedEvents,
    totalEventPages,
    eventPageSize: EVENT_PAGE_SIZE,
  };
}
