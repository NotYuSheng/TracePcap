import {
  clusterApi,
  type DnsQueryLogResponse,
  type DnsQueryEntry,
} from '@/features/cluster/services/clusterApi';
import type { ServiceTabConfig } from './types';
import { IpList } from './IpList';

const pct = (ratio: number) => Math.round(ratio * 100);

/**
 * DNS query-log tab for the node modal (#362). Shown for hosts whose `serviceRoles` include "dns".
 * Lists the domains the DNS server resolved, which failed, and (if abnormal) a tunnelling/DGA banner.
 */
export const dnsServiceTab: ServiceTabConfig<DnsQueryLogResponse, DnsQueryEntry> = {
  role: 'dns',
  label: 'DNS',
  icon: 'bi-hdd-network',

  fetchDetail: (fileId, ip) => clusterApi.getDnsQueryLog(fileId, ip),
  getRows: d => d.entries,
  getSummary: d =>
    `${d.resolvedCount} resolved / ${d.failedCount} failed (${pct(d.nxdomainRatio)}% NXDOMAIN)`,
  getBanner: d =>
    d.suspicious
      ? 'Possible DNS tunnelling or domain-generation algorithm detected — this server returned an unusually high share of NXDOMAIN responses.'
      : null,

  // Unresolvable queries get a red edge.
  rowTone: row => (row.resolvable ? undefined : 'danger'),

  columns: [
    { header: 'Domain', slot: 'title', cell: row => <span className="font-monospace">{row.queryName}</span> },
    { header: 'Type', cell: row => row.queryType ?? '—' },
    {
      header: 'Response',
      cell: row => (
        <span className={row.resolvable ? 'text-success' : 'text-danger fw-semibold'}>
          {row.responseCode ?? '—'}
        </span>
      ),
    },
    {
      header: 'Resolved IPs',
      cell: row =>
        row.resolvedIps.length > 0 ? (
          <IpList ips={row.resolvedIps} />
        ) : (
          <span className="text-muted">—</span>
        ),
    },
    { header: 'Count', slot: 'aside', cell: row => `×${row.queryCount.toLocaleString()}` },
    {
      header: 'Packet',
      cell: (row, ctx) =>
        row.frame != null ? (
          <button
            type="button"
            className="btn btn-link btn-sm p-0"
            title="View this DNS response packet"
            onClick={() => ctx.openPacket(row.frame!)}
          >
            #{row.frame}<i className="bi bi-box-arrow-up-right ms-1" aria-hidden="true" />
          </button>
        ) : (
          <span className="text-muted">—</span>
        ),
    },
  ],
};
