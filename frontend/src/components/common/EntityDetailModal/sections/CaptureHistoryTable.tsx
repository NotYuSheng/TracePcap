import { useNavigate } from 'react-router-dom';
import type { EntityHistoryEntry } from '@/features/notes/services/entityNotesService';
import { formatBytes, formatNumber } from '../format';

interface CaptureHistoryTableProps {
  history: EntityHistoryEntry[];
  historyLoading: boolean;
  historyError: string | null;
  onClose: () => void;
}

/** Generic capture history: which uploaded files this entity appeared in. */
export function CaptureHistoryTable({ history, historyLoading, historyError, onClose }: CaptureHistoryTableProps) {
  const navigate = useNavigate();
  return (
    <div className="mt-4">
      <h6 className="text-muted fw-semibold mb-2">
        <i className="bi bi-clock-history me-1" />Capture History
      </h6>
      {historyLoading && (
        <div className="text-muted small py-2">
          <span className="spinner-border spinner-border-sm me-2" role="status" />Loading…
        </div>
      )}
      {historyError && (
        <div className="alert alert-warning py-2 small">{historyError}</div>
      )}
      {!historyLoading && !historyError && history.length === 0 && (
        <p className="text-muted small fst-italic">Not seen in any uploaded files.</p>
      )}
      {!historyLoading && history.length > 0 && (
        <div className="table-responsive rounded border overflow-hidden">
          <table className="table table-sm table-hover mb-0">
            <thead className="table-light" style={{ fontSize: '0.8rem' }}>
              <tr>
                <th className="text-muted fw-normal">File</th>
                <th className="text-muted fw-normal">Capture Start</th>
                <th className="text-end text-muted fw-normal">Packets</th>
                <th className="text-end text-muted fw-normal">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {history.map(entry => (
                <tr
                  key={entry.fileId}
                  style={{ cursor: 'pointer' }}
                  onClick={() => { onClose(); navigate(`/analysis/${entry.fileId}`); }}
                  title="Open in analysis"
                >
                  <td className="small">{entry.fileName}</td>
                  <td className="small text-muted">
                    {entry.startTime ? new Date(entry.startTime).toLocaleString('en-GB') : '—'}
                  </td>
                  <td className="text-end small text-muted">
                    {entry.packetCount != null ? formatNumber(entry.packetCount) : '—'}
                  </td>
                  <td className="text-end small text-muted">
                    {entry.totalBytes != null ? formatBytes(entry.totalBytes) : '—'}
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
