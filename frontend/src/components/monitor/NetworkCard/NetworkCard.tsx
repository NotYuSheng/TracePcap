import { Button, Card } from '@govtechsg/sgds-react';
import type { Network } from '@/features/monitor/types/monitor.types';

interface NetworkCardProps {
  network: Network;
  onClick: () => void;
  onDelete: () => void;
}

export const NetworkCard = ({ network, onClick, onDelete }: NetworkCardProps) => {
  return (
    <Card className="h-100" style={{ cursor: 'pointer' }} onClick={onClick}>
      <Card.Body>
        <div className="d-flex justify-content-between align-items-start mb-2">
          <h5 className="mb-0 text-break">{network.name}</h5>
          <Button
            type="button"
            size="sm"
            variant="outline-danger"
            className="ms-2 flex-shrink-0"
            onClick={e => {
              e.stopPropagation();
              onDelete();
            }}
            title="Delete network"
            aria-label="Delete network"
          >
            <i className="bi bi-trash"></i>
          </Button>
        </div>

        {network.description && (
          <p className="text-muted small mb-3">{network.description}</p>
        )}

        <div className="d-flex gap-3 flex-wrap">
          <div className="text-center">
            <div className="fw-semibold">{network.snapshotCount}</div>
            <small className="text-muted">Snapshots</small>
          </div>
          {network.criticalChanges > 0 && (
            <div className="text-center">
              <div className="fw-semibold text-danger">{network.criticalChanges}</div>
              <small className="text-muted">Critical</small>
            </div>
          )}
          {network.warningChanges > 0 && (
            <div className="text-center">
              <div className="fw-semibold text-warning">{network.warningChanges}</div>
              <small className="text-muted">Warnings</small>
            </div>
          )}
          {network.criticalChanges === 0 && network.warningChanges === 0 && network.snapshotCount > 1 && (
            <div className="text-center">
              <div className="fw-semibold text-success">
                <i className="bi bi-check-circle-fill"></i>
              </div>
              <small className="text-muted">No changes</small>
            </div>
          )}
          {network.hasInsights && (
            <div className="text-center">
              <div className="fw-semibold text-primary">
                <i className="bi bi-stars"></i>
              </div>
              <small className="text-muted">Insights</small>
            </div>
          )}
        </div>
      </Card.Body>
    </Card>
  );
};
