import { useState, useEffect, useMemo } from 'react';
import { Badge, Button, Table } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Pagination } from '@components/common/Pagination';
import { RoleEditModal } from '@components/common/RoleEditModal';
import type { EntityType } from '@/features/notes/services/entityNotesService';
import { formatSnapTime, hashBadgeStyle } from '../format';
import type { IpSnapshotEntry } from '../types';

const HISTORY_PAGE_SIZE = 10;

interface SnapshotHistoryTableProps {
  entityType: EntityType;
  entityKey: string;
  ipSnapHistory: IpSnapshotEntry[];
  ipHistoryLoading: boolean;
  /** Called after a per-snapshot role is saved/dismissed so the parent can refetch. */
  onRoleChanged?: () => void;
}

/** Per-snapshot MAC/device/protocol/role history for an IP, with per-snapshot role editing (#369). */
export function SnapshotHistoryTable({
  entityType,
  entityKey,
  ipSnapHistory,
  ipHistoryLoading,
  onRoleChanged,
}: SnapshotHistoryTableProps) {
  const [editing, setEditing] = useState<{ fileId: string; name: string } | null>(null);
  // Sort by snapshot capture order (monotonic with date). Latest-first by default.
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);

  const sortedHistory = useMemo(() =>
    [...ipSnapHistory].sort((a, b) =>
      sortDir === 'desc'
        ? b.snap.snapshotOrder - a.snap.snapshotOrder
        : a.snap.snapshotOrder - b.snap.snapshotOrder
    ),
    [ipSnapHistory, sortDir]
  );
  const toggleSort = () => { setSortDir(d => (d === 'desc' ? 'asc' : 'desc')); setPage(1); };

  const totalPages = Math.max(1, Math.ceil(sortedHistory.length / HISTORY_PAGE_SIZE));
  // Derive the active page during render so a shrunken dataset can't slice out of
  // range for the one frame before the useEffect below clamps `page`.
  const activePage = Math.min(page, totalPages);
  const pagedHistory = sortedHistory.slice((activePage - 1) * HISTORY_PAGE_SIZE, activePage * HISTORY_PAGE_SIZE);

  // Clamp back into range if the data shrinks (e.g. the modal is reused for another entity).
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  // Chronological order (oldest→newest) for the "MAC changed vs previous snapshot" comparison,
  // which must stay correct regardless of the display sort direction.
  const prevMacBySnapId = useMemo(() => {
    const chronological = [...ipSnapHistory].sort((a, b) => a.snap.snapshotOrder - b.snap.snapshotOrder);
    const map = new Map<string, string | null | undefined>();
    chronological.forEach((entry, i) => {
      map.set(entry.snap.id, i > 0 ? chronological[i - 1].host?.mac : undefined);
    });
    return map;
  }, [ipSnapHistory]);

  return (
    <div className="mt-4">
      <h6 className="text-muted fw-semibold mb-2">
        <i className="bi bi-clock-history me-1" />Snapshot History
      </h6>
      {ipHistoryLoading && (
        <div className="text-muted small py-2">
          <Spinner size="sm" className="me-2" />Loading…
        </div>
      )}
      {!ipHistoryLoading && ipSnapHistory.length === 0 && (
        <p className="text-muted small fst-italic">Not seen in any snapshots.</p>
      )}
      {!ipHistoryLoading && ipSnapHistory.length > 0 && (
        <div className="rounded border overflow-hidden">
          <Table size="sm" hover responsive className="mb-0">
            <Table.Header className="table-light" style={{ fontSize: '0.8rem' }}>
              <Table.Row>
                <Table.HeaderCell className="text-muted fw-normal">#</Table.HeaderCell>
                <Table.HeaderCell
                  className="text-muted fw-normal user-select-none"
                  style={{ cursor: 'pointer' }}
                  onClick={toggleSort}
                  title="Sort by capture date"
                  aria-sort={sortDir === 'desc' ? 'descending' : 'ascending'}
                >
                  Snapshot
                  <i className={`bi ms-1 ${sortDir === 'desc' ? 'bi-sort-down' : 'bi-sort-up'}`} />
                </Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">{entityType === 'DEVICE' ? 'IP(s)' : 'MAC Address'}</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Device Type</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Role</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Protocols / Apps</Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {pagedHistory.map(({ snap, host, protocols, apps, roleLabel, roleOrigin, roleStale, macs, ips }) => (
                <Table.Row key={snap.id}>
                  <Table.DataCell><small className="text-muted">{snap.snapshotOrder + 1}</small></Table.DataCell>
                  <Table.DataCell>
                    <small className="text-muted d-block">{formatSnapTime(snap)}</small>
                    <small className="text-muted text-break" style={{ fontSize: '0.7rem' }}>{snap.fileName}</small>
                  </Table.DataCell>
                  {entityType === 'DEVICE' ? (
                    <Table.DataCell>
                      {ips.length === 0 ? (
                        <code style={{ fontSize: '0.75rem' }}>—</code>
                      ) : (
                        <div className="d-flex flex-column gap-1">
                          {ips.map(ip => <code key={ip} style={{ fontSize: '0.75rem' }}>{ip}</code>)}
                        </div>
                      )}
                      {ips.length > 1 && (
                        <Badge bg="danger" className="ms-1" style={{ fontSize: '0.6rem' }} title="This MAC claimed more than one IP in this snapshot — a device using multiple addresses (router/NAT, or spoofing)">
                          <i className="bi bi-diagram-3 me-1" />conflict — {ips.length} IPs
                        </Badge>
                      )}
                    </Table.DataCell>
                  ) : (
                    <Table.DataCell>
                      {macs.length === 0 ? (
                        <code style={{ fontSize: '0.75rem' }}>—</code>
                      ) : (
                        <div className="d-flex flex-column gap-1">
                          {macs.map(m => <code key={m} style={{ fontSize: '0.75rem' }}>{m}</code>)}
                        </div>
                      )}
                      {macs.length > 1 && (
                        <Badge bg="danger" className="ms-1" style={{ fontSize: '0.6rem' }} title="This IP was claimed by more than one MAC in this snapshot — possible overlapping networks">
                          <i className="bi bi-diagram-3 me-1" />conflict — {macs.length} MACs
                        </Badge>
                      )}
                      {host?.mac && prevMacBySnapId.get(snap.id) && host.mac !== prevMacBySnapId.get(snap.id) && (
                        <Badge bg="warning" text="dark" className="ms-1" style={{ fontSize: '0.65rem' }}>changed</Badge>
                      )}
                    </Table.DataCell>
                  )}
                  <Table.DataCell><small className="text-muted">{host?.deviceType ?? '—'}</small></Table.DataCell>
                  <Table.DataCell>
                    <div className="d-flex align-items-center gap-1">
                      {roleLabel ? <small>{roleLabel}</small> : <small className="text-muted">—</small>}
                      {roleLabel && roleOrigin === 'CARRIED_FORWARD' && (
                        <Badge bg="light" text="secondary" className="border" style={{ fontSize: '0.55rem', fontWeight: 400 }} title="Inherited from an earlier snapshot (carried forward), not set here">carried</Badge>
                      )}
                      {roleStale && (
                        <Badge bg="warning" text="dark" style={{ fontSize: '0.6rem' }} title="Label flagged stale in this snapshot"><i className="bi bi-exclamation-triangle" /></Badge>
                      )}
                      <Button variant="link" size="sm" className="p-0 ms-1 text-muted" style={{ fontSize: '0.75rem', lineHeight: 1 }} title="Edit role for this snapshot" onClick={() => setEditing({ fileId: snap.fileId, name: snap.fileName })}>
                        <i className="bi bi-pencil" />
                      </Button>
                    </div>
                  </Table.DataCell>
                  <Table.DataCell>
                    {protocols.length === 0 && apps.length === 0 ? (
                      <small className="text-muted">—</small>
                    ) : (
                      <div className="d-flex flex-wrap gap-1">
                        {protocols.map((p, i) => (
                          <Badge key={`proto-${p}-${i}`} style={{ fontSize: '0.65rem', fontWeight: 400, ...hashBadgeStyle(p) }}>{p}</Badge>
                        ))}
                        {apps.map((a, i) => (
                          <Badge key={`app-${a}-${i}`} style={{ fontSize: '0.65rem', fontWeight: 400, ...hashBadgeStyle(a) }}>{a}</Badge>
                        ))}
                      </div>
                    )}
                  </Table.DataCell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        </div>
      )}
      {!ipHistoryLoading && sortedHistory.length > HISTORY_PAGE_SIZE && (
        <div className="mt-2">
          <Pagination
            currentPage={activePage}
            totalPages={totalPages}
            totalItems={sortedHistory.length}
            pageSize={HISTORY_PAGE_SIZE}
            onPageChange={setPage}
          />
        </div>
      )}

      {editing && (
        <RoleEditModal
          entityType={entityType}
          entityKey={entityKey}
          fileId={editing.fileId}
          snapshotName={editing.name}
          onClose={() => setEditing(null)}
          onSaved={() => onRoleChanged?.()}
        />
      )}
    </div>
  );
}
