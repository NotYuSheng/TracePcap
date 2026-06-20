import {
  intelligenceService,
  type WebServerDetail,
  type HttpEndpoint,
} from '@/features/intelligence/services/intelligenceService';
import type { ServiceTabConfig, ServiceLogInfoField } from './types';

const pct = (ratio: number) => Math.round(ratio * 100);

function statusClass(status: number | null): string {
  if (status == null) return 'text-muted';
  if (status >= 500) return 'text-danger fw-semibold';
  if (status >= 400) return 'text-warning-emphasis fw-semibold';
  return 'text-success';
}

function infoFields(d: WebServerDetail): ServiceLogInfoField[] {
  const fields: ServiceLogInfoField[] = [];
  if (d.serverSoftware) {
    fields.push({ label: 'Server', value: <span style={{ fontFamily: 'monospace' }}>{d.serverSoftware}</span> });
  }
  if (d.contentTypes.length > 0) {
    fields.push({ label: 'Content types', value: d.contentTypes.join(', ') });
  }
  if (d.tls) {
    if (d.tls.sniNames.length > 0) {
      fields.push({ label: 'TLS SNI names', value: <span style={{ fontFamily: 'monospace' }}>{d.tls.sniNames.join(', ')}</span> });
    }
    if (d.tls.subject) fields.push({ label: 'TLS subject', value: <span style={{ fontFamily: 'monospace' }}>{d.tls.subject}</span> });
    if (d.tls.issuer) fields.push({ label: 'TLS issuer', value: <span style={{ fontFamily: 'monospace' }}>{d.tls.issuer}</span> });
    if (d.tls.ja3s) fields.push({ label: 'JA3S', value: <span style={{ fontFamily: 'monospace' }}>{d.tls.ja3s}</span> });
  }
  return fields;
}

/**
 * Web/API server tab for the node modal: lists the cleartext HTTP endpoints the host served (method,
 * path, status, content type) plus server-level detail (software, content types, TLS metadata) and a
 * banner when client-error (4xx) rates suggest endpoint enumeration. Registered for both the `api`
 * and `web` roles.
 */
export const webServiceTab: ServiceTabConfig<WebServerDetail, HttpEndpoint> = {
  role: 'web',
  label: 'HTTP',
  icon: 'bi-globe',

  fetchDetail: (fileId, ip) => intelligenceService.getWebServerDetail(fileId, ip),
  getRows: d => d.endpoints,
  getSummary: d =>
    d.totalRequests === 0
      ? 'No cleartext HTTP requests observed (HTTPS endpoints are encrypted).'
      : `${d.successCount} ok / ${d.clientErrorCount} 4xx / ${d.serverErrorCount} 5xx (${pct(d.clientErrorRatio)}% client errors)`,
  getBanner: d =>
    d.suspicious
      ? 'Possible endpoint enumeration / scanning detected — this server returned an unusually high rate of client errors (4xx).'
      : null,
  getInfoFields: infoFields,

  // Light-red highlight for endpoints that mostly returned client errors (4xx).
  rowStyle: row =>
    row.clientErrorCount > row.successCount + row.serverErrorCount
      ? { backgroundColor: '#f8d7da', color: '#842029' }
      : undefined,

  columns: [
    { header: 'Method', cell: row => <span className="fw-semibold">{row.method ?? '—'}</span> },
    { header: 'Path', cell: row => <span style={{ fontFamily: 'monospace' }}>{row.path}</span> },
    {
      header: 'Status',
      cell: row => <span className={statusClass(row.topStatus)}>{row.topStatus ?? '—'}</span>,
    },
    { header: 'Content-Type', cell: row => row.contentType ?? <span className="text-muted">—</span> },
    { header: 'Count', cell: row => row.requestCount },
  ],
};
