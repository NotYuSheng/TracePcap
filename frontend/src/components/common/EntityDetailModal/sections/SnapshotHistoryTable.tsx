import { Badge, Table } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { formatSnapTime, hashBadgeStyle } from '../format';
import type { IpSnapshotEntry } from '../types';

interface SnapshotHistoryTableProps {
  ipSnapHistory: IpSnapshotEntry[];
  ipHistoryLoading: boolean;
}

/** Per-snapshot MAC/device/protocol history for an IP (Monitor context). */
export function SnapshotHistoryTable({ ipSnapHistory, ipHistoryLoading }: SnapshotHistoryTableProps) {
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
                <Table.HeaderCell className="text-muted fw-normal">Snapshot</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">MAC Address</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Manufacturer</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Device Type</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Protocols / Apps</Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {ipSnapHistory.map(({ snap, host, protocols, apps }, idx) => (
                <Table.Row key={snap.id}>
                  <Table.DataCell><small className="text-muted">{snap.snapshotOrder + 1}</small></Table.DataCell>
                  <Table.DataCell>
                    <small className="text-muted d-block">{formatSnapTime(snap)}</small>
                    <small className="text-muted text-break" style={{ fontSize: '0.7rem' }}>{snap.fileName}</small>
                  </Table.DataCell>
                  <Table.DataCell>
                    <code style={{ fontSize: '0.75rem' }}>{host?.mac ?? '—'}</code>
                    {idx > 0 && host?.mac && ipSnapHistory[idx - 1].host?.mac &&
                      host.mac !== ipSnapHistory[idx - 1].host!.mac && (
                        <Badge bg="warning" text="dark" className="ms-1" style={{ fontSize: '0.65rem' }}>changed</Badge>
                      )}
                  </Table.DataCell>
                  <Table.DataCell><small className="text-muted">{host?.manufacturer ?? '—'}</small></Table.DataCell>
                  <Table.DataCell><small className="text-muted">{host?.deviceType ?? '—'}</small></Table.DataCell>
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
    </div>
  );
}
