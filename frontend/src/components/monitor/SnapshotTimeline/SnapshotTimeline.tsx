import { Spinner } from '@components/common/Spinner/Spinner';
import { Fragment, useMemo, useState } from 'react';
import { Badge, Button, ButtonGroup, Form, Modal } from '@govtechsg/sgds-react';
import type { NetworkSnapshot, ChangeEvent } from '@/features/monitor/types/monitor.types';
import { Pagination } from '@/components/common/Pagination';
import { ScrollableTable } from '@/components/common/ScrollableTable';
import { SnapshotDetailModal } from '@/components/monitor/SnapshotDetailModal/SnapshotDetailModal';
import { parseDateTime } from '@/utils/dateUtils';

interface SnapshotTimelineProps {
  networkId: string;
  snapshots: NetworkSnapshot[];
  changeEvents: ChangeEvent[];
  onRemove: (snapshotId: string) => Promise<void>;
  onAddSnapshot: () => void;
  onPatchChange: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
  onSnapshotUpdated: (updated: NetworkSnapshot) => void;
}

type SortDir = 'asc' | 'desc';
type ViewMode = 'file' | 'time';

// Time-interval options for the "By Time" view, mirroring the Traffic Overview chart.
const GRANULARITY_OPTIONS: { label: string; seconds: number }[] = [
  { label: '1m',  seconds: 60 },
  { label: '5m',  seconds: 300 },
  { label: '30m', seconds: 1800 },
  { label: '1h',  seconds: 3600 },
  { label: '1d',  seconds: 86400 },
];

interface TimeBucket {
  key: string;
  start: number; // bucket start (ms); NaN for the "unknown capture time" group
  snaps: NetworkSnapshot[];
  packets: number;
  changes: number;
  critical: number;
}

function formatBucketLabel(startMs: number, granularitySec: number): string {
  if (Number.isNaN(startMs)) return 'Unknown capture time';
  const start = new Date(startMs);
  if (granularitySec >= 86400) {
    return start.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  }
  const end = new Date(startMs + granularitySec * 1000);
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
  onRemove,
  onAddSnapshot,
  onPatchChange,
  onSnapshotUpdated,
}: SnapshotTimelineProps) => {
  const [removing, setRemoving] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);
  const [detailSnap, setDetailSnap] = useState<NetworkSnapshot | null>(null);
  const [detailInitialTab, setDetailInitialTab] = useState<'diagram' | 'changes' | 'context' | 'insights'>('diagram');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [viewMode, setViewMode] = useState<ViewMode>('file');
  const [granularity, setGranularity] = useState(3600);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const handleRemove = async (snapshotId: string) => {
    setRemoving(snapshotId);
    setConfirmRemove(null);
    try {
      await onRemove(snapshotId);
    } finally {
      setRemoving(null);
    }
  };

  const toggleSort = () => {
    setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
    setPage(1);
  };

  const changeMode = (mode: ViewMode) => {
    setViewMode(mode);
    setPage(1);
    setExpanded(new Set());
  };

  const changeGranularity = (secs: number) => {
    setGranularity(secs);
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
    const bucketMs = granularity * 1000;
    const map = new Map<number, NetworkSnapshot[]>();
    const noTime: NetworkSnapshot[] = [];
    for (const snap of snapshots) {
      if (!snap.startTime) {
        noTime.push(snap);
        continue;
      }
      const start = Math.floor(getStartMs(snap) / bucketMs) * bucketMs;
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
        {snap.changeCount === 0 ? (
          <Badge bg="light" text="muted" className="border">No changes</Badge>
        ) : snap.criticalCount > 0 ? (
          <Button
            type="button"
            variant="danger"
            size="sm"
            className="border-0 py-0 px-1"
            style={{ fontSize: '0.75em' }}
            onClick={e => { e.stopPropagation(); setDetailInitialTab('changes'); setDetailSnap(snap); }}
          >
            {snap.criticalCount} critical
            {snap.changeCount > snap.criticalCount &&
              `, ${snap.changeCount - snap.criticalCount} more`}
          </Button>
        ) : (
          <Button
            type="button"
            variant="warning"
            size="sm"
            className="border-0 py-0 px-1"
            style={{ fontSize: '0.75em' }}
            onClick={e => { e.stopPropagation(); setDetailInitialTab('changes'); setDetailSnap(snap); }}
          >
            {snap.changeCount} change{snap.changeCount !== 1 ? 's' : ''}
          </Button>
        )}
      </td>
      <td onClick={e => e.stopPropagation()}>
        <Button
          size="sm"
          variant="outline-danger"
          onClick={() => setConfirmRemove(snap.id)}
          disabled={removing !== null}
          title="Remove snapshot"
        >
          <i className="bi bi-trash"></i>
        </Button>
      </td>
    </tr>
  );

  const renderBucketBadge = (b: TimeBucket) => {
    if (b.changes === 0) return <Badge bg="light" text="muted" className="border">No changes</Badge>;
    if (b.critical > 0) {
      return (
        <Badge bg="danger">
          {b.critical} critical
          {b.changes > b.critical && `, ${b.changes - b.critical} more`}
        </Badge>
      );
    }
    return <Badge bg="warning" text="dark">{b.changes} change{b.changes !== 1 ? 's' : ''}</Badge>;
  };

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
        <h6 className="mb-0 text-muted fw-normal">
          {snapshots.length} snapshot{snapshots.length !== 1 ? 's' : ''}
        </h6>
        <div className="d-flex align-items-center gap-2 flex-wrap">
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
          {viewMode === 'time' && (
            <div className="d-flex align-items-center gap-1">
              <label className="text-muted small mb-0">Interval:</label>
              <Form.Select
                size="sm"
                style={{ width: 'auto' }}
                value={String(granularity)}
                onChange={e => changeGranularity(Number(e.target.value))}
              >
                {GRANULARITY_OPTIONS.map(({ label, seconds }) => (
                  <option key={seconds} value={String(seconds)}>{label}</option>
                ))}
              </Form.Select>
            </div>
          )}
          <Button size="sm" variant="outline-secondary" onClick={onAddSnapshot}>
            <i className="bi bi-plus-lg me-1"></i>Add PCAP
          </Button>
        </div>
      </div>

      {snapshots.length === 0 ? (
        <div className="text-muted text-center py-4">
          No PCAPs added yet. Click "Add PCAP" to get started.
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
                    <th></th>
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
                          <td>{renderBucketBadge(b)}</td>
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

      <Modal show={!!confirmRemove} onHide={() => setConfirmRemove(null)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Remove Snapshot</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="mb-0">
            Are you sure you want to remove{' '}
            <strong>{snapshots.find(s => s.id === confirmRemove)?.fileName}</strong>?{' '}
            The original PCAP file will not be deleted.
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button
            variant="outline-secondary"
            onClick={() => setConfirmRemove(null)}
            disabled={removing !== null}
          >
            Cancel
          </Button>
          <Button
            variant="outline-danger"
            onClick={() => confirmRemove && handleRemove(confirmRemove)}
            disabled={removing !== null}
          >
            {removing ? <Spinner animation="border" size="sm" className="me-1" /> : null}
            Remove
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};
