import {
  intelligenceService,
  type DnsQueryLogResponse,
  type DnsQueryEntry,
} from '@/features/intelligence/services/intelligenceService';
import type { ServiceTabConfig } from './types';

const pct = (ratio: number) => Math.round(ratio * 100);

/**
 * DNS query-log tab for the node modal (#362). Shown for hosts whose `serviceRoles` include "dns".
 * Lists the domains the DNS server resolved, which failed, and (if abnormal) a tunnelling/DGA banner.
 */
export const dnsServiceTab: ServiceTabConfig<DnsQueryLogResponse, DnsQueryEntry> = {
  role: 'dns',
  label: 'DNS',
  icon: 'bi-hdd-network',

  fetchDetail: (fileId, ip) => intelligenceService.getDnsQueryLog(fileId, ip),
  getRows: d => d.entries,
  getSummary: d =>
    `${d.resolvedCount} resolved / ${d.failedCount} failed (${pct(d.nxdomainRatio)}% NXDOMAIN)`,
  getBanner: d =>
    d.suspicious
      ? 'Possible DNS tunnelling or domain-generation algorithm detected — this server returned an unusually high share of NXDOMAIN responses.'
      : null,

  // Light-red highlight for unresolvable queries (theme-independent; Bootstrap danger-subtle palette).
  rowStyle: row => (row.resolvable ? undefined : { backgroundColor: '#f8d7da', color: '#842029' }),

  columns: [
    { header: 'Domain', cell: row => <span style={{ fontFamily: 'monospace' }}>{row.queryName}</span> },
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
          <span style={{ fontFamily: 'monospace' }}>{row.resolvedIps.join(', ')}</span>
        ) : (
          <span className="text-muted">—</span>
        ),
    },
    { header: 'Count', cell: row => row.queryCount },
  ],
};
