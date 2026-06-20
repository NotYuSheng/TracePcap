import { useEffect, useState } from 'react';
import { Alert } from '@components/common/Alert';
import type { ServiceTabConfig } from '@/features/network/serviceTabs';

interface ServiceLogTabProps {
  fileId: string;
  ip: string;
  config: ServiceTabConfig<unknown, unknown>;
}

/**
 * Renders one service-role tab inside the node-details modal: lazy-loads the host's per-role detail
 * and shows a suspicious banner, a one-line summary, and a config-driven table. Generic across roles
 * — DNS today, web/API servers later — by swapping the {@link ServiceTabConfig}.
 */
export function ServiceLogTab({ fileId, ip, config }: ServiceLogTabProps) {
  const [detail, setDetail] = useState<unknown | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    config
      .fetchDetail(fileId, ip)
      .then(d => { if (active) setDetail(d); })
      .catch(e => { if (active) setError(e instanceof Error ? e.message : 'Failed to load'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [fileId, ip, config]);

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border spinner-border-sm text-primary" role="status" />
        <p className="text-muted mt-2 small">Loading {config.label} activity…</p>
      </div>
    );
  }
  if (error) {
    return <div className="alert alert-warning py-2 small mb-0">{error}</div>;
  }
  if (!detail) return null;

  const rows = config.getRows(detail);
  const banner = config.getBanner(detail);

  return (
    <div>
      {banner && (
        <Alert variant="danger" className="py-2">
          <i className="bi bi-shield-exclamation me-2" />
          {banner}
        </Alert>
      )}
      <p className="text-muted small mb-2">{config.getSummary(detail)}</p>
      <div className="table-responsive rounded border overflow-hidden">
        <table className="table table-sm table-hover mb-0" style={{ fontSize: '0.8rem' }}>
          <thead className="table-light">
            <tr>
              {config.columns.map(col => (
                <th key={col.header}>{col.header}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i} style={config.rowStyle?.(row)}>
                {config.columns.map(col => (
                  <td key={col.header}>{col.cell(row)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length === 0 && (
        <p className="text-muted small fst-italic mt-2 mb-0">No {config.label} activity recorded.</p>
      )}
    </div>
  );
}
