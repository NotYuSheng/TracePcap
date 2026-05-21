import { Button, Modal } from '@govtechsg/sgds-react';
import { useNavigate } from 'react-router-dom';
import type { AbsentEntity } from '@/features/monitor/types/monitor.types';
import { parseDateTime } from '@/utils/dateUtils';

interface LastSeenModalProps {
  show: boolean;
  onHide: () => void;
  entity: AbsentEntity | null;
}

export const LastSeenModal = ({ show, onHide, entity }: LastSeenModalProps) => {
  const navigate = useNavigate();

  if (!entity) return null;

  const entityTypeLabel =
    entity.type === 'DEVICE' ? 'device'
    : entity.type === 'APP' ? 'application'
    : entity.type === 'IP' ? 'IP address'
    : 'protocol';

  const formattedDate = entity.lastSeenStartTime
    ? new Date(parseDateTime(entity.lastSeenStartTime as unknown as string | number[])).toLocaleString()
    : 'Unknown';

  return (
    <Modal show={show} onHide={onHide}>
      <Modal.Header closeButton>
        <Modal.Title>Last Seen: {entity.key}</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <p className="text-muted mb-3">
          This {entityTypeLabel} was last observed in a previous capture.
        </p>
        <div className="d-flex flex-column gap-2">
          <div>
            <small className="text-muted d-block">File</small>
            <span className="fw-semibold">{entity.lastSeenFileName}</span>
          </div>
          <div>
            <small className="text-muted d-block">Capture started</small>
            <span>{formattedDate}</span>
          </div>
        </div>
      </Modal.Body>
      <Modal.Footer>
        {entity.lastSeenFileId && (
          <Button
            type="button"
            size="sm"
            variant="outline-primary"
            onClick={() => {
              onHide();
              navigate(`/analysis/${entity.lastSeenFileId}`);
            }}
          >
            <i className="bi bi-box-arrow-up-right me-1"></i>Open in Analysis
          </Button>
        )}
        <Button type="button" size="sm" variant="secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};
