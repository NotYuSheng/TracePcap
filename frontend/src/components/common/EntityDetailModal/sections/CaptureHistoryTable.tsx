import { Table } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
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
          <Spinner size="sm" className="me-2" />Loading…
        </div>
      )}
      {historyError && (
        <Alert variant="warning" className="py-2 small">{historyError}</Alert>
      )}
      {!historyLoading && !historyError && history.length === 0 && (
        <p className="text-muted small fst-italic">Not seen in any uploaded files.</p>
      )}
      {!historyLoading && !historyError && history.length > 0 && (
        <div className="rounded border overflow-hidden">
          <Table size="sm" hover responsive className="mb-0">
            <Table.Header className="table-light" style={{ fontSize: '0.8rem' }}>
              <Table.Row>
                <Table.HeaderCell className="text-muted fw-normal">File</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Capture Start</Table.HeaderCell>
                <Table.HeaderCell className="text-end text-muted fw-normal">Packets</Table.HeaderCell>
                <Table.HeaderCell className="text-end text-muted fw-normal">Bytes</Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {history.map(entry => (
                <Table.Row
                  key={entry.fileId}
                  style={{ cursor: 'pointer' }}
                  role="button"
                  tabIndex={0}
                  onClick={() => { onClose(); navigate(`/analysis/${entry.fileId}`); }}
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onClose();
                      navigate(`/analysis/${entry.fileId}`);
                    }
                  }}
                  title="Open in analysis"
                >
                  <Table.DataCell className="small">{entry.fileName}</Table.DataCell>
                  <Table.DataCell className="small text-muted">
                    {entry.startTime ? new Date(entry.startTime).toLocaleString('en-GB') : '—'}
                  </Table.DataCell>
                  <Table.DataCell className="text-end small text-muted">
                    {entry.packetCount != null ? formatNumber(entry.packetCount) : '—'}
                  </Table.DataCell>
                  <Table.DataCell className="text-end small text-muted">
                    {entry.totalBytes != null ? formatBytes(entry.totalBytes) : '—'}
                  </Table.DataCell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        </div>
      )}
    </div>
  );
}
