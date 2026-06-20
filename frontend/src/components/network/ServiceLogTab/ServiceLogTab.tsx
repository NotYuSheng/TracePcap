import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Alert } from '@components/common/Alert';
import type { ServiceTabConfig, ServiceLogCellContext } from '@/features/network/serviceTabs';

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
  const navigate = useNavigate();
  const [detail, setDetail] = useState<unknown | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Cell context: lets columns render "view packet" links that jump to the Conversations tab.
  const cellCtx = useMemo<ServiceLogCellContext>(
    () => ({
      fileId,
      openPacket: frame => navigate(`/analysis/${fileId}/conversations?packet=${frame}`),
    }),
    [fileId, navigate],
  );

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
  const infoFields = config.getInfoFields?.(detail) ?? [];

  return (
    <div>
      {banner && (
        <Alert variant="danger" className="py-2">
          <i className="bi bi-shield-exclamation me-2" />
          {banner}
        </Alert>
      )}
      {infoFields.length > 0 && (
        <dl className="row mb-2 small">
          {infoFields.map(field => (
            <div className="col-12 d-flex gap-2 mb-1" key={field.label}>
              <dt className="text-muted" style={{ minWidth: 130, flexShrink: 0 }}>{field.label}</dt>
              <dd className="mb-0">{field.value}</dd>
            </div>
          ))}
        </dl>
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
                  <td key={col.header}>{col.cell(row, cellCtx)}</td>
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
