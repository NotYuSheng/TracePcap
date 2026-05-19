import { Spinner } from '@components/common/Spinner/Spinner';
import { useState } from 'react';
import { Badge, Button } from '@govtechsg/sgds-react';
import { formatBytes } from '@/utils/formatters';
import type { HostSummary, SortBy } from '@/features/intelligence/services/intelligenceService';

const GEO_SOURCE_INFO = {
  ipinfo: {
    label: 'Live',
    tooltip: 'Location data from ipinfo.io (live lookup). Generally accurate but may be imprecise for cloud/CDN IPs whose servers are distributed globally.',
    color: '#198754',
  },
  mmdb: {
    label: 'MMDB',
    tooltip: 'Location data from the bundled DB-IP Lite offline database. Approximate only — cloud provider IPs (AWS, Azure, Google, Cloudflare) may show incorrect cities or countries. No internet connection was available at lookup time.',
    color: '#6c757d',
  },
};

function GeoSourceBadge({ source }: { source: string | null }) {
  if (!source) return null;
  const info = GEO_SOURCE_INFO[source as keyof typeof GEO_SOURCE_INFO] ?? GEO_SOURCE_INFO.mmdb;
  return (
    <span
      title={info.tooltip}
      style={{
        fontSize: 9,
        fontWeight: 600,
        color: '#fff',
        background: info.color,
        borderRadius: 3,
        padding: '1px 4px',
        cursor: 'help',
        whiteSpace: 'nowrap',
        flexShrink: 0,
      }}
    >
      {info.label} ⓘ
    </span>
  );
}

interface TopHostsTableProps {
  hosts: HostSummary[];
  loading: boolean;
  sortBy: SortBy;
  onSortByChange: (s: SortBy) => void;
}

const SORT_OPTIONS: { value: SortBy; label: string }[] = [
  { value: 'bytes', label: 'Bytes' },
  { value: 'packets', label: 'Packets' },
  { value: 'conversations', label: 'Conversations' },
  { value: 'risks', label: 'Risks' },
];

export const TopHostsTable = ({ hosts, loading, sortBy, onSortByChange }: TopHostsTableProps) => {
  const [page, setPage] = useState(0);
  const pageSize = 20;
  const totalPages = Math.ceil(hosts.length / pageSize);
  const visible = hosts.slice(page * pageSize, (page + 1) * pageSize);

  return (
    <div>
      <div className="d-flex align-items-center gap-3 mb-2">
        <h6 className="mb-0">Top Hosts</h6>
        <div className="d-flex gap-1">
          {SORT_OPTIONS.map(o => (
            <Button
              key={o.value}
              size="sm"
              variant={sortBy === o.value ? 'primary' : 'outline-secondary'}
              onClick={() => { onSortByChange(o.value); setPage(0); }}
              disabled={loading}
            >
              {o.label}
            </Button>
          ))}
        </div>
        {loading && <Spinner animation="border" size="sm" className="text-primary" role="status" />}
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="table table-sm table-hover" style={{ fontSize: 12 }}>
          <thead className="table-light">
            <tr>
              <th>#</th>
              <th>IP / Hostname</th>
              <th>Bytes</th>
              <th>Packets</th>
              <th>Conversations</th>
              <th>Risks</th>
              <th>Role</th>
              <th>Device</th>
              <th>Country / Org</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((host, i) => (
              <tr key={host.ip}>
                <td className="text-muted">{page * pageSize + i + 1}</td>
                <td>
                  <span className="fw-semibold" style={{ fontFamily: 'monospace', fontSize: 11 }}>
                    {host.ip}
                  </span>
                  {host.hostname && (
                    <div className="text-info" style={{ fontSize: 10 }}>{host.hostname}</div>
                  )}
                </td>
                <td>{formatBytes(host.totalBytes)}</td>
                <td>{host.packetCount.toLocaleString()}</td>
                <td>{host.conversationCount.toLocaleString()}</td>
                <td>
                  {host.riskCount > 0 ? (
                    <Badge bg="danger">{host.riskCount}</Badge>
                  ) : (
                    <span className="text-muted">—</span>
                  )}
                </td>
                <td>
                  <Badge
                    style={{
                      background: host.role === 'server' ? '#107c10'
                        : host.role === 'client' ? '#0072c6'
                        : '#5c2d91',
                      fontSize: 10,
                    }}
                  >
                    {host.role}
                  </Badge>
                </td>
                <td>
                  {host.deviceType ? (
                    <span className="text-muted" style={{ fontSize: 10 }}>{host.deviceType}</span>
                  ) : (
                    <span className="text-muted">—</span>
                  )}
                </td>
                <td style={{ fontSize: 10 }}>
                  {(host.country || host.org) ? (
                    <div className="d-flex align-items-center gap-1">
                      <span>
                        {host.country && <span className="me-1">{host.country}</span>}
                        {host.org && <span className="text-muted">{host.org}</span>}
                      </span>
                      <GeoSourceBadge source={host.geoSource} />
                    </div>
                  ) : (
                    <span className="text-muted">—</span>
                  )}
                </td>
              </tr>
            ))}
            {!loading && hosts.length === 0 && (
              <tr>
                <td colSpan={9} className="text-center text-muted py-3">No host data available</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="d-flex align-items-center gap-2 mt-2">
          <Button
            size="sm"
            variant="outline-secondary"
            onClick={() => setPage(p => p - 1)}
            disabled={page === 0}
          >
            ‹ Prev
          </Button>
          <small className="text-muted">Page {page + 1} / {totalPages}</small>
          <Button
            size="sm"
            variant="outline-secondary"
            onClick={() => setPage(p => p + 1)}
            disabled={page >= totalPages - 1}
          >
            Next ›
          </Button>
        </div>
      )}
    </div>
  );
};
