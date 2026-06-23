import { Row, Col, Table } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
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
          <Spinner size="sm" className="text-primary" />
          <p className="text-muted mt-2 small">Loading stats…</p>
        </div>
      )}
      {statsError && (
        <Alert variant="warning" className="py-2 small">{statsError}</Alert>
      )}
      {!statsLoading && !statsError && stats && (
        <>
          <Row className="g-3 mb-4">
            <Col xs={4} className="text-center">
              <div className="fw-bold fs-5">{formatNumber(stats.conversationCount)}</div>
              <small className="text-muted">Conversations</small>
            </Col>
            <Col xs={4} className="text-center">
              <div className="fw-bold fs-5">{formatNumber(stats.packetCount)}</div>
              <small className="text-muted">Packets</small>
            </Col>
            <Col xs={4} className="text-center">
              <div className="fw-bold fs-5">{formatBytes(stats.totalBytes)}</div>
              <small className="text-muted">Total bytes</small>
            </Col>
          </Row>

          {stats.topPeers.length > 0 && (
            <>
              <h6 className="border-bottom pb-1 mb-2">
                Top IPs{stats.topPeers.length === 10 ? ' (top 10)' : ''}
              </h6>
              <div className="rounded border overflow-hidden">
                <Table size="sm" hover responsive className="mb-0">
                  <Table.Header className="table-light" style={{ fontSize: '0.8rem' }}>
                    <Table.Row>
                      <Table.HeaderCell>IP Address</Table.HeaderCell>
                      <Table.HeaderCell className="text-end">Bytes</Table.HeaderCell>
                    </Table.Row>
                  </Table.Header>
                  <Table.Body>
                    {stats.topPeers.map(peer => (
                      <Table.Row
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
                        <Table.DataCell className="font-monospace small">{peer.ip}</Table.DataCell>
                        <Table.DataCell className="text-end small">{formatBytes(peer.bytes)}</Table.DataCell>
                      </Table.Row>
                    ))}
                  </Table.Body>
                </Table>
              </div>
            </>
          )}
        </>
      )}
    </>
  );
}
