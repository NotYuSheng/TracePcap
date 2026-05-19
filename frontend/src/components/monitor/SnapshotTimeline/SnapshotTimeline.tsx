import { Spinner } from '@components/common/Spinner/Spinner';
import { useState } from 'react';
import { Badge, Button, Card, Modal } from '@govtechsg/sgds-react';
import type { NetworkSnapshot, ChangeEvent } from '@/features/monitor/types/monitor.types';
import { Pagination } from '@/components/common/Pagination';
import { ScrollableTable } from '@/components/common/ScrollableTable';
import { ChangeEventBadge } from '@/components/monitor/ChangeEventBadge/ChangeEventBadge';
import { parseDateTime } from '@/utils/dateUtils';

interface SnapshotTimelineProps {
  snapshots: NetworkSnapshot[];
  changeEvents: ChangeEvent[];
  onRemove: (snapshotId: string) => Promise<void>;
  onAddSnapshot: () => void;
  onSelectSnapshot: (snapshotId: string) => void;
  onPatchChange: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
}

type SortDir = 'asc' | 'desc';

function formatCaptureDate(start: string | null): string {
  if (!start) return '—';
  const ms = parseDateTime(start as unknown as string | number[]);
  return new Date(ms).toLocaleString();
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
  snapshots,
  changeEvents,
  onRemove,
  onAddSnapshot,
  onSelectSnapshot,
  onPatchChange,
}: SnapshotTimelineProps) => {
  const [removing, setRemoving] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);
  const [changesSnap, setChangesSnap] = useState<NetworkSnapshot | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

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

  const sorted = [...snapshots].sort((a, b) => {
    const diff = getStartMs(a) - getStartMs(b);
    return sortDir === 'asc' ? diff : -diff;
  });

  const totalPages = Math.ceil(sorted.length / pageSize);
  const paginated = sorted.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h6 className="mb-0 text-muted fw-normal">
          {snapshots.length} snapshot{snapshots.length !== 1 ? 's' : ''}
        </h6>
        <Button size="sm" variant="outline-secondary" onClick={onAddSnapshot}>
          <i className="bi bi-plus-lg me-1"></i>Add PCAP
        </Button>
      </div>

      {snapshots.length === 0 ? (
        <div className="text-muted text-center py-4">
          No PCAPs added yet. Click "Add PCAP" to get started.
        </div>
      ) : (
        <>
          <ScrollableTable>
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
                {paginated.map(snap => {
                  return (
                    <tr key={snap.id}>
                      <td>
                        <small className="text-muted">{formatCaptureDate(snap.startTime)}</small>
                      </td>
                      <td>
                        <Button
                          size="sm"
                          variant="link"
                          className="p-0 text-start text-break"
                          onClick={() => onSelectSnapshot(snap.id)}
                          title="View network diagram"
                        >
                          {snap.fileName}
                        </Button>
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
                            onClick={() => setChangesSnap(snap)}
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
                            onClick={() => setChangesSnap(snap)}
                          >
                            {snap.changeCount} change{snap.changeCount !== 1 ? 's' : ''}
                          </Button>
                        )}
                      </td>
                      <td>
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
                })}
              </tbody>
            </table>
          </ScrollableTable>

          <Card.Footer className="border-top pt-2 mt-2">
            <Pagination
              currentPage={page}
              totalPages={totalPages}
              totalItems={snapshots.length}
              pageSize={pageSize}
              onPageChange={setPage}
              showPageSizeSelector
              onPageSizeChange={size => { setPageSize(size); setPage(1); }}
            />
          </Card.Footer>
        </>
      )}

      {/* Changes detail modal */}
      <Modal show={!!changesSnap} onHide={() => setChangesSnap(null)} centered size="lg">
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="bi bi-activity me-2"></i>
            Changes — {changesSnap?.fileName}
          </Modal.Title>
        </Modal.Header>
        <Modal.Body style={{ maxHeight: '60vh', overflowY: 'auto' }}>
          {(() => {
            const events = changeEvents.filter(e => e.toSnapshotId === changesSnap?.id);
            if (events.length === 0) {
              return <p className="text-muted mb-0">No change events for this snapshot.</p>;
            }
            return events.map(event => (
              <ChangeEventBadge
                key={event.id}
                event={event}
                snapshots={snapshots}
                onPatch={onPatchChange}
              />
            ));
          })()}
        </Modal.Body>
      </Modal>

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
