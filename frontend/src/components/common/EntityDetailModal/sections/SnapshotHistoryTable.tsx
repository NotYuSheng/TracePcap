import { Badge } from '@govtechsg/sgds-react';
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
          <span className="spinner-border spinner-border-sm me-2" role="status" />Loading…
        </div>
      )}
      {!ipHistoryLoading && ipSnapHistory.length === 0 && (
        <p className="text-muted small fst-italic">Not seen in any snapshots.</p>
      )}
      {!ipHistoryLoading && ipSnapHistory.length > 0 && (
        <div className="table-responsive rounded border overflow-hidden">
          <table className="table table-sm table-hover mb-0">
            <thead className="table-light" style={{ fontSize: '0.8rem' }}>
              <tr>
                <th className="text-muted fw-normal">#</th>
                <th className="text-muted fw-normal">Snapshot</th>
                <th className="text-muted fw-normal">MAC Address</th>
                <th className="text-muted fw-normal">Manufacturer</th>
                <th className="text-muted fw-normal">Device Type</th>
                <th className="text-muted fw-normal">Protocols / Apps</th>
              </tr>
            </thead>
            <tbody>
              {ipSnapHistory.map(({ snap, host, protocols, apps }, idx) => (
                <tr key={snap.id}>
                  <td><small className="text-muted">{snap.snapshotOrder + 1}</small></td>
                  <td>
                    <small className="text-muted d-block">{formatSnapTime(snap)}</small>
                    <small className="text-muted text-break" style={{ fontSize: '0.7rem' }}>{snap.fileName}</small>
                  </td>
                  <td>
                    <code style={{ fontSize: '0.75rem' }}>{host?.mac ?? '—'}</code>
                    {idx > 0 && host?.mac && ipSnapHistory[idx - 1].host?.mac &&
                      host.mac !== ipSnapHistory[idx - 1].host!.mac && (
                        <Badge bg="warning" text="dark" className="ms-1" style={{ fontSize: '0.65rem' }}>changed</Badge>
                      )}
                  </td>
                  <td><small className="text-muted">{host?.manufacturer ?? '—'}</small></td>
                  <td><small className="text-muted">{host?.deviceType ?? '—'}</small></td>
                  <td>
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
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
