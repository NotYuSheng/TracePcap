import { useState } from 'react';
import { Button, Modal } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { ScrollableTable } from '@/components/common/ScrollableTable';
import { parseDateTime } from '@/utils/dateUtils';

interface ManagePcapsModalProps {
  show: boolean;
  onHide: () => void;
  snapshots: NetworkSnapshot[];
  onRemove: (snapshotId: string) => Promise<void>;
  onAddSnapshot: () => void;
}

function formatCaptureDate(start: string | null): string {
  if (!start) return '—';
  const ms = parseDateTime(start as unknown as string | number[]);
  if (Number.isNaN(ms) || ms === 0) return '—';
  return new Date(ms).toLocaleString('en-GB');
}

function getStartMs(snap: NetworkSnapshot): number {
  if (!snap.startTime) return 0;
  return parseDateTime(snap.startTime as unknown as string | number[]);
}

export const ManagePcapsModal = ({
  show,
  onHide,
  snapshots,
  onRemove,
  onAddSnapshot,
}: ManagePcapsModalProps) => {
  const [removing, setRemoving] = useState<string | null>(null);
  // The snapshot pending removal — drives the confirmation modal (null = none).
  const [confirmTarget, setConfirmTarget] = useState<NetworkSnapshot | null>(null);

  const handleHide = () => {
    setRemoving(null);
    setConfirmTarget(null);
    onHide();
  };

  const sorted = [...snapshots].sort((a, b) => getStartMs(b) - getStartMs(a));

  const handleRemove = async (snapshotId: string) => {
    setRemoving(snapshotId);
    try {
      await onRemove(snapshotId);
      setConfirmTarget(null);
    } finally {
      setRemoving(null);
    }
  };

  return (
    <>
    <Modal show={show} onHide={handleHide} size="lg" centered>
      <Modal.Header closeButton>
        <Modal.Title>
          <i className="bi bi-collection me-2"></i>Manage PCAPs
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="d-flex justify-content-between align-items-center mb-3">
          <span className="text-muted">
            {snapshots.length} PCAP{snapshots.length !== 1 ? 's' : ''} in this network
          </span>
          <Button size="sm" variant="primary" onClick={onAddSnapshot}>
            <i className="bi bi-plus-lg me-1"></i>Add PCAP
          </Button>
        </div>

        {snapshots.length === 0 ? (
          <div className="text-muted text-center py-4">
            No PCAPs yet. Click "Add PCAP" to get started.
          </div>
        ) : (
          <div className="border rounded overflow-hidden">
            <ScrollableTable maxHeight="50vh">
              <table className="table table-hover align-middle mb-0">
                <thead>
                  <tr>
                    <th className="text-muted fw-normal" style={{ whiteSpace: 'nowrap' }}>Captured</th>
                    <th className="text-muted fw-normal">File</th>
                    <th className="text-muted fw-normal">Packets</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map(snap => (
                    <tr key={snap.id}>
                      <td>
                        <small className="text-muted">{formatCaptureDate(snap.startTime)}</small>
                      </td>
                      <td>
                        <span className="fw-medium text-break">{snap.fileName}</span>
                      </td>
                      <td>
                        <small className="text-muted">
                          {snap.packetCount != null ? snap.packetCount.toLocaleString() : '—'}
                        </small>
                      </td>
                      <td className="text-end">
                        <Button
                          size="sm"
                          variant="outline-danger"
                          onClick={() => setConfirmTarget(snap)}
                          disabled={removing !== null}
                          title="Remove PCAP"
                          aria-label={`Remove PCAP ${snap.fileName}`}
                        >
                          <i className="bi bi-trash"></i>
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollableTable>
          </div>
        )}

        <p className="text-muted small mt-3 mb-0">
          <i className="bi bi-info-circle me-1"></i>
          Removing a PCAP only detaches it from this network — the original file is not deleted.
        </p>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="outline-secondary" onClick={handleHide}>
          Done
        </Button>
      </Modal.Footer>
    </Modal>

    <Modal show={confirmTarget !== null} onHide={() => removing === null && setConfirmTarget(null)} centered>
      <Modal.Header closeButton>
        <Modal.Title className="h6 mb-0">Remove PCAP?</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <p className="mb-2">
          Remove <span className="fw-medium text-break">{confirmTarget?.fileName}</span> from this
          network?
        </p>
        <p className="text-muted small mb-0">
          <i className="bi bi-info-circle me-1"></i>
          This only detaches it from the network — the original file is not deleted.
        </p>
      </Modal.Body>
      <Modal.Footer>
        <Button
          variant="outline-secondary"
          onClick={() => setConfirmTarget(null)}
          disabled={removing !== null}
        >
          Cancel
        </Button>
        <Button
          variant="danger"
          onClick={() => confirmTarget && handleRemove(confirmTarget.id)}
          disabled={removing !== null}
        >
          {removing !== null ? <><Spinner animation="border" size="sm" className="me-1" />Removing…</> : 'Remove'}
        </Button>
      </Modal.Footer>
    </Modal>
    </>
  );
};
