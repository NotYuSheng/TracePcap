import { Fragment, useMemo, useState, type MouseEvent } from 'react';
import { Badge, Button, ButtonGroup, Form } from '@govtechsg/sgds-react';
import type { NetworkSnapshot, ChangeEvent } from '@/features/monitor/types/monitor.types';
import { Pagination } from '@/components/common/Pagination';
import { ScrollableTable } from '@/components/common/ScrollableTable';
import { SnapshotDetailModal } from '@/components/monitor/SnapshotDetailModal/SnapshotDetailModal';
import { parseDateTime } from '@/utils/dateUtils';

interface SnapshotTimelineProps {
  networkId: string;
  snapshots: NetworkSnapshot[];
  changeEvents: ChangeEvent[];
  onManage: () => void;
  onPatchChange: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
  onSnapshotUpdated: (updated: NetworkSnapshot) => void;
}

type SortDir = 'asc' | 'desc';
type ViewMode = 'file' | 'time';
// Fixed-length intervals are stored as seconds; 'month' is a calendar month (variable length).
type Granularity = number | 'month';

// Time-interval options for the "By Time" view, mirroring the Traffic Overview chart.
const GRANULARITY_OPTIONS: { label: string; value: Granularity }[] = [
  { label: '1m',  value: 60 },
  { label: '5m',  value: 300 },
  { label: '30m', value: 1800 },
  { label: '1h',  value: 3600 },
  { label: '1d',  value: 86400 },
  { label: '1mo', value: 'month' },
];

interface TimeBucket {
  key: string;
  start: number; // bucket start (ms); NaN for the "unknown capture time" group
  snaps: NetworkSnapshot[];
  packets: number;
  changes: number;
  critical: number;
}

// Start (ms) of the bucket a given timestamp falls into for the active granularity.
function bucketStartFor(ms: number, granularity: Granularity): number {
  if (granularity === 'month') {
    const d = new Date(ms);
    return new Date(d.getFullYear(), d.getMonth(), 1).getTime();
  }
  const bucketMs = granularity * 1000;
  return Math.floor(ms / bucketMs) * bucketMs;
}

function formatBucketLabel(startMs: number, granularity: Granularity): string {
  if (Number.isNaN(startMs)) return 'Unknown capture time';
  const start = new Date(startMs);
  if (granularity === 'month') {
    return start.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
  }
  if (granularity >= 86400) {
    return start.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  }
  const end = new Date(startMs + granularity * 1000);
  const timeOpts: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit' };
  const dateStr = start.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
  return `${dateStr}, ${start.toLocaleTimeString('en-GB', timeOpts)}–${end.toLocaleTimeString('en-GB', timeOpts)}`;
}

function formatCaptureDate(start: string | null): string {
  if (!start) return '—';
  const ms = parseDateTime(start as unknown as string | number[]);
  return new Date(ms).toLocaleString('en-GB');
}

function formatDuration(start: string | null, end: string | null): string {
  if (!start || !end) return '—';
  const startMs = parseDateTime(start as unknown as string | number[]);
  const endMs = parseDateTime(end as unknown as string | number[]);
  const secs = Math.floor((endMs - startMs) / 1000);
  const mins = Math.floor(secs / 60);
  const hrs = Math.floor(mins / 60);
  if (hrs > 0) return `${hrs}h ${mins % 60}m`;
  if (mins > 0) return `${mins}m ${secs % 60}s`;
  return `${secs}s`;
}

function getStartMs(snap: NetworkSnapshot): number {
  if (!snap.startTime) return 0;
  return parseDateTime(snap.startTime as unknown as string | number[]);
}

export const SnapshotTimeline = ({
  networkId,
  snapshots,
  changeEvents,
  onManage,
  onPatchChange,
  onSnapshotUpdated,
}: SnapshotTimelineProps) => {
  const [detailSnap, setDetailSnap] = useState<NetworkSnapshot | null>(null);
  const [detailInitialTab, setDetailInitialTab] = useState<'diagram' | 'changes' | 'context' | 'insights'>('diagram');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [viewMode, setViewMode] = useState<ViewMode>('file');
  const [granularity, setGranularity] = useState<Granularity>(3600);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleSort = () => {
    setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
    setPage(1);
  };

  const changeMode = (mode: ViewMode) => {
    setViewMode(mode);
    setPage(1);
    setExpanded(new Set());
  };

  const changeGranularity = (value: Granularity) => {
    setGranularity(value);
    setPage(1);
    setExpanded(new Set());
  };

  const toggleExpand = (key: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const sorted = [...snapshots].sort((a, b) => {
    const diff = getStartMs(a) - getStartMs(b);
    return sortDir === 'asc' ? diff : -diff;
  });

  // Group snapshots into time buckets for the "By Time" view (purely client-side).
  const buckets = useMemo<TimeBucket[]>(() => {
    const map = new Map<number, NetworkSnapshot[]>();
    const noTime: NetworkSnapshot[] = [];
    for (const snap of snapshots) {
      if (!snap.startTime) {
        noTime.push(snap);
        continue;
      }
      const start = bucketStartFor(getStartMs(snap), granularity);
      const arr = map.get(start) ?? [];
      arr.push(snap);
      map.set(start, arr);
    }
    const toBucket = (start: number, snaps: NetworkSnapshot[]): TimeBucket => ({
      key: Number.isNaN(start) ? 'unknown' : String(start),
      start,
      snaps: [...snaps].sort((a, b) => getStartMs(a) - getStartMs(b)),
      packets: snaps.reduce((s, x) => s + (x.packetCount ?? 0), 0),
      changes: snaps.reduce((s, x) => s + x.changeCount, 0),
      critical: snaps.reduce((s, x) => s + x.criticalCount, 0),
    });
    const list = [...map.entries()]
      .map(([start, snaps]) => toBucket(start, snaps))
      .sort((a, b) => (sortDir === 'asc' ? a.start - b.start : b.start - a.start));
    if (noTime.length) list.push(toBucket(NaN, noTime));
    return list;
  }, [snapshots, granularity, sortDir]);

  const totalItems = viewMode === 'file' ? sorted.length : buckets.length;
  const totalPages = Math.ceil(totalItems / pageSize);
  const paginated = sorted.slice((page - 1) * pageSize, page * pageSize);
  const paginatedBuckets = buckets.slice((page - 1) * pageSize, page * pageSize);

  // Shared "Changes" cell for both views — always the same Badge pill so the By PCAP
  // rows, the By Time bucket aggregate, and the nested per-PCAP rows look identical.
  // Pass onClick to make it clickable (per-PCAP rows jump to the changes tab).
  const renderChangesPill = (
    changeCount: number,
    criticalCount: number,
    onClick?: (e: MouseEvent<HTMLElement>) => void,
  ) => {
    if (changeCount === 0) {
      return <Badge bg="light" text="muted" className="border fw-normal">No changes</Badge>;
    }
    const variant = criticalCount > 0 ? 'danger' : 'warning';
    const label = criticalCount > 0
      ? `${criticalCount} critical${changeCount > criticalCount ? `, ${changeCount - criticalCount} more` : ''}`
      : `${changeCount} change${changeCount !== 1 ? 's' : ''}`;
    return (
      <Badge
        bg={variant}
        text={variant === 'warning' ? 'dark' : undefined}
        className="fw-normal"
        style={onClick ? { cursor: 'pointer' } : undefined}
        onClick={onClick}
      >
        {label}
      </Badge>
    );
  };

  const renderSnapshotRow = (snap: NetworkSnapshot) => (
    <tr
      key={snap.id}
      style={{ cursor: 'pointer' }}
      onClick={() => { setDetailInitialTab('diagram'); setDetailSnap(snap); }}
    >
      <td>
        <small className="text-muted">{formatCaptureDate(snap.startTime)}</small>
      </td>
      <td>
        <span className="fw-medium text-break">{snap.fileName}</span>
      </td>
      <td>
        <small className="text-muted">{formatDuration(snap.startTime, snap.endTime)}</small>
      </td>
      <td>
        <small className="text-muted">{snap.packetCount != null ? snap.packetCount.toLocaleString() : '—'}</small>
      </td>
      <td>
        {renderChangesPill(snap.changeCount, snap.criticalCount, e => {
          e.stopPropagation();
          setDetailInitialTab('changes');
          setDetailSnap(snap);
        })}
      </td>
    </tr>
  );

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
        <h6 className="mb-0 text-muted fw-normal">
          {snapshots.length} snapshot{snapshots.length !== 1 ? 's' : ''}
        </h6>
        <div className="d-flex align-items-center gap-2 flex-wrap">
          {viewMode === 'time' && (
            <div className="d-flex align-items-center gap-1">
              <label className="text-muted small mb-0">Interval:</label>
              <Form.Select
                size="sm"
                style={{ width: 'auto' }}
                value={String(granularity)}
                onChange={e => {
                  const v = e.target.value;
                  changeGranularity(v === 'month' ? 'month' : Number(v));
                }}
              >
                {GRANULARITY_OPTIONS.map(({ label, value }) => (
                  <option key={String(value)} value={String(value)}>{label}</option>
                ))}
              </Form.Select>
            </div>
          )}
          <ButtonGroup size="sm">
            <Button
              variant={viewMode === 'file' ? 'primary' : 'outline-primary'}
              onClick={() => changeMode('file')}
              title="One row per PCAP file"
            >
              By PCAP
            </Button>
            <Button
              variant={viewMode === 'time' ? 'primary' : 'outline-primary'}
              onClick={() => changeMode('time')}
              title="Group captures into time intervals"
            >
              By Time
            </Button>
          </ButtonGroup>
          <Button size="sm" variant="outline-secondary" onClick={onManage}>
            <i className="bi bi-collection me-1"></i>Manage PCAPs
          </Button>
        </div>
      </div>

      {snapshots.length === 0 ? (
        <div className="text-muted text-center py-4">
          No PCAPs added yet. Click "Manage PCAPs" to get started.
        </div>
      ) : (
        <>
          <div className="border rounded overflow-hidden">
          <ScrollableTable maxHeight="50vh">
            {viewMode === 'file' ? (
              <table className="table table-hover align-middle mb-0">
                <thead>
                  <tr>
                    <th className="text-muted fw-normal" style={{ cursor: 'pointer', whiteSpace: 'nowrap' }} onClick={toggleSort}>
                      Captured{' '}
                      <i className={`bi bi-arrow-${sortDir === 'asc' ? 'up' : 'down'} ms-1`}></i>
                    </th>
                    <th className="text-muted fw-normal">File</th>
                    <th className="text-muted fw-normal">Duration</th>
                    <th className="text-muted fw-normal">Packets</th>
                    <th className="text-muted fw-normal">Changes</th>
                  </tr>
                </thead>
                <tbody>
                  {paginated.map(renderSnapshotRow)}
                </tbody>
              </table>
            ) : (
              <table className="table table-hover align-middle mb-0">
                <thead>
                  <tr>
                    <th className="text-muted fw-normal" style={{ cursor: 'pointer', whiteSpace: 'nowrap' }} onClick={toggleSort}>
                      Period{' '}
                      <i className={`bi bi-arrow-${sortDir === 'asc' ? 'up' : 'down'} ms-1`}></i>
                    </th>
                    <th className="text-muted fw-normal">Captures</th>
                    <th className="text-muted fw-normal">Packets</th>
                    <th className="text-muted fw-normal">Changes</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedBuckets.map(b => {
                    const isOpen = expanded.has(b.key);
                    return (
                      <Fragment key={b.key}>
                        <tr style={{ cursor: 'pointer' }} onClick={() => toggleExpand(b.key)}>
                          <td className="fw-medium" style={{ whiteSpace: 'nowrap' }}>
                            <i className={`bi bi-chevron-${isOpen ? 'down' : 'right'} me-2 text-muted`}></i>
                            {formatBucketLabel(b.start, granularity)}
                          </td>
                          <td>
                            <small className="text-muted">{b.snaps.length}</small>
                          </td>
                          <td>
                            <small className="text-muted">{b.packets.toLocaleString()}</small>
                          </td>
                          <td>{renderChangesPill(b.changes, b.critical)}</td>
                        </tr>
                        {isOpen && (
                          <tr>
                            <td colSpan={4} className="p-0 bg-light">
                              <table className="table table-sm table-hover align-middle mb-0">
                                <tbody>
                                  {b.snaps.map(renderSnapshotRow)}
                                </tbody>
                              </table>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            )}
          </ScrollableTable>
          <div className="border-top px-3 py-2">
            <Pagination
              currentPage={page}
              totalPages={totalPages}
              totalItems={totalItems}
              pageSize={pageSize}
              onPageChange={setPage}
              showPageSizeSelector
              onPageSizeChange={size => { setPageSize(size); setPage(1); }}
            />
          </div>
          </div>
        </>
      )}

      {/* Snapshot Detail modal */}
      {detailSnap && (
        <SnapshotDetailModal
          snapshot={detailSnap}
          networkId={networkId}
          changeEvents={changeEvents}
          snapshots={snapshots}
          initialTab={detailInitialTab}
          onPatchChange={onPatchChange}
          onSnapshotUpdated={updated => {
            setDetailSnap(updated);
            onSnapshotUpdated(updated);
          }}
          onHide={() => setDetailSnap(null)}
        />
      )}
    </div>
  );
};
