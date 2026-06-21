import { formatBytes, formatNumber } from '../format';
import type { EntityStats } from '../types';

interface EntityStatsSectionProps {
  stats: EntityStats | null;
  statsLoading: boolean;
  statsError: string | null;
  onSelectPeer: (ip: string) => void;
}

/** Aggregate stats + top-peer table for APPLICATION/PROTOCOL entities. */
export function EntityStatsSection({ stats, statsLoading, statsError, onSelectPeer }: EntityStatsSectionProps) {
  return (
    <>
      {statsLoading && (
        <div className="text-center py-4">
          <div className="spinner-border spinner-border-sm text-primary" role="status" />
          <p className="text-muted mt-2 small">Loading stats…</p>
        </div>
      )}
      {statsError && (
        <div className="alert alert-warning py-2 small">{statsError}</div>
      )}
      {!statsLoading && !statsError && stats && (
        <>
          <div className="row g-3 mb-4">
            <div className="col-4 text-center">
              <div className="fw-bold fs-5">{formatNumber(stats.conversationCount)}</div>
              <small className="text-muted">Conversations</small>
            </div>
            <div className="col-4 text-center">
              <div className="fw-bold fs-5">{formatNumber(stats.packetCount)}</div>
              <small className="text-muted">Packets</small>
            </div>
            <div className="col-4 text-center">
              <div className="fw-bold fs-5">{formatBytes(stats.totalBytes)}</div>
              <small className="text-muted">Total bytes</small>
            </div>
          </div>

          {stats.topPeers.length > 0 && (
            <>
              <h6 className="border-bottom pb-1 mb-2">
                Top IPs{stats.topPeers.length === 10 ? ' (top 10)' : ''}
              </h6>
              <div className="table-responsive rounded border overflow-hidden">
                <table className="table table-sm table-hover mb-0">
                  <thead className="table-light" style={{ fontSize: '0.8rem' }}>
                    <tr>
                      <th>IP Address</th>
                      <th className="text-end">Bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.topPeers.map(peer => (
                      <tr
                        key={peer.ip}
                        style={{ cursor: 'pointer' }}
                        role="button"
                        tabIndex={0}
                        onClick={() => onSelectPeer(peer.ip)}
                        onKeyDown={e => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            onSelectPeer(peer.ip);
                          }
                        }}
                        title="View IP details"
                      >
                        <td className="font-monospace small">{peer.ip}</td>
                        <td className="text-end small">{formatBytes(peer.bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </>
  );
}
