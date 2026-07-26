import { useEffect, useState } from 'react';
import { Pagination } from '@components/common/Pagination/Pagination';
import {
  entityNotesService,
  type EntityHistoryEntry,
  type EntityType,
} from '@/features/notes/services/entityNotesService';
import { insightsService } from '@/features/insights/services/insightsService';
import { formatBytes, formatNumber } from '../format';

const HISTORY_PAGE_SIZE = 10;

type RoleInfo = { label: string | null; origin: string | null; stale: boolean };

interface Props {
  entityType: EntityType;
  entityKey: string;
  /** The file this modal is anchored to — its row is marked "current". */
  fileId: string;
  onNavigate: (path: string) => void;
}

/**
 * The graph host's cross-capture history with a per-file role trail — ported from the former
 * NodeDetails History tab (#578). Distinct from the plain CaptureHistoryTable: it adds the Role
 * column (with carried/stale badges) and a "current" marker, and links each row to its analysis.
 */
export function GraphHistoryTab({ entityType, entityKey, fileId, onNavigate }: Props) {
  const [history, setHistory] = useState<EntityHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyRoles, setHistoryRoles] = useState<Record<string, RoleInfo>>({});
  const [page, setPage] = useState(1);

  useEffect(() => {
    // Guard every async state write: the modal is reused across nodes, so a slow response for a
    // previous entity must not overwrite the newer one's history.
    let alive = true;
    setHistory([]);
    setHistoryRoles({});
    setHistoryError(null);
    setPage(1);
    setHistoryLoading(true);
    entityNotesService
      .getHistory(entityType, entityKey)
      .then(entries => {
        if (!alive) return;
        setHistory(entries);
        Promise.all(
          entries.map(e =>
            insightsService
              .getNodeRole(entityType, entityKey, e.fileId)
              .then(r => [e.fileId, { label: r?.roleLabel ?? null, origin: r?.origin ?? null, stale: !!r?.staleSince }] as const)
              .catch(() => [e.fileId, { label: null, origin: null, stale: false }] as const),
          ),
        ).then(pairs => { if (alive) setHistoryRoles(Object.fromEntries(pairs)); });
      })
      .catch(() => { if (alive) setHistoryError('Failed to load history'); })
      .finally(() => { if (alive) setHistoryLoading(false); });
    return () => { alive = false; };
  }, [entityType, entityKey]);

  const totalPages = Math.ceil(history.length / HISTORY_PAGE_SIZE);
  const pageClamped = Math.min(page, Math.max(1, totalPages));
  const visible = history.slice((pageClamped - 1) * HISTORY_PAGE_SIZE, pageClamped * HISTORY_PAGE_SIZE);

  return (
    <div>
      <p className="text-muted small mb-3">
        Files in which this {entityType === 'DEVICE' ? 'device (MAC)' : 'IP address'} has appeared, most recent first.
      </p>
      {historyLoading && (
        <div className="text-center py-4">
          <div className="spinner-border spinner-border-sm text-primary" role="status" />
          <p className="text-muted mt-2 small">Loading history…</p>
        </div>
      )}
      {historyError && <div className="alert alert-warning py-2 small">{historyError}</div>}
      {!historyLoading && !historyError && history.length === 0 && (
        <p className="text-muted small fst-italic">No history found across uploaded files.</p>
      )}
      {!historyLoading && history.length > 0 && (
        <div className="table-responsive rounded border overflow-hidden">
          <table className="table table-sm table-hover mb-0">
            <thead className="table-light" style={{ fontSize: '0.8rem' }}>
              <tr>
                <th>File</th>
                <th>Role</th>
                <th>Capture Start</th>
                <th className="text-end">Packets</th>
                <th className="text-end">Bytes</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visible.map(entry => {
                const r = historyRoles[entry.fileId];
                return (
                  <tr key={entry.fileId} className={entry.fileId === fileId ? 'table-active' : ''}>
                    <td className="small">
                      {entry.fileName}
                      {entry.fileId === fileId && (
                        <span className="badge bg-primary ms-2" style={{ fontSize: '0.6rem' }}>current</span>
                      )}
                    </td>
                    <td className="small">
                      {r?.label ? (
                        <span className="d-inline-flex align-items-center gap-1">
                          {r.label}
                          {r.origin === 'CARRIED_FORWARD' && (
                            <span className="badge bg-light text-secondary border" style={{ fontSize: '0.55rem', fontWeight: 400 }} title="Inherited from an earlier snapshot (carried forward)">carried</span>
                          )}
                          {r.stale && (
                            <span className="badge bg-warning text-dark" style={{ fontSize: '0.6rem' }} title="Label flagged stale in this file">
                              <i className="bi bi-exclamation-triangle" aria-hidden="true" />
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className="small">
                      {entry.startTime ? new Date(entry.startTime).toLocaleString('en-GB') : '—'}
                    </td>
                    <td className="text-end small">
                      {entry.packetCount != null ? formatNumber(entry.packetCount) : '—'}
                    </td>
                    <td className="text-end small">
                      {entry.totalBytes != null ? formatBytes(entry.totalBytes) : '—'}
                    </td>
                    <td className="text-end">
                      <button
                        className="btn btn-link btn-sm p-0 text-muted"
                        title="Go to this analysis"
                        onClick={() => onNavigate(`/analysis/${entry.fileId}`)}
                      >
                        <i className="bi bi-box-arrow-up-right" aria-hidden="true" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {totalPages > 1 && (
            <Pagination
              currentPage={pageClamped}
              totalPages={totalPages}
              totalItems={history.length}
              pageSize={HISTORY_PAGE_SIZE}
              onPageChange={setPage}
              showPageSizeSelector={false}
            />
          )}
        </div>
      )}
    </div>
  );
}
