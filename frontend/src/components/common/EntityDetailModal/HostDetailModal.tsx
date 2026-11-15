import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Modal } from '@govtechsg/sgds-react';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { EntityDetailModal } from './EntityDetailModal';
import { graphNodeEntity } from './graphNodeEntity';

/** Large enough that no host is dropped into the "hidden" overflow while we look one up. */
const ALL_NODES = 100_000;

interface HostDetailModalProps {
  fileId: string;
  ip: string;
  onClose: () => void;
  /** Where peer/history links go; defaults to the router. */
  onNavigate?: (path: string) => void;
}

/**
 * A host's detail from anywhere that only knows its address (a conversation, a peer row): loads the
 * capture's network graph and opens the same identity-card-and-tabs view the network map shows for
 * that host. Falls back to the plain IP detail when the host isn't on the graph (e.g. it only
 * appears in filtered-out traffic).
 */
export function HostDetailModal({ fileId, ip, onClose, onNavigate }: HostDetailModalProps) {
  const navigate = useNavigate();
  const { nodes, edges, hiddenNodesList, crossEdges, loading } = useNetworkData(fileId, undefined, ALL_NODES);

  const node = useMemo(
    () => [...nodes, ...hiddenNodesList].find(n => !n.data.isL2 && n.data.ip === ip),
    [nodes, hiddenNodesList, ip]
  );
  const graphEdges = useMemo(() => [...edges, ...crossEdges], [edges, crossEdges]);

  if (loading) {
    return (
      <Modal show onHide={onClose} centered aria-label={`Loading ${ip}`}>
        <Modal.Body className="d-flex align-items-center gap-2 py-4 justify-content-center text-muted">
          <span className="spinner-border spinner-border-sm" aria-hidden="true" />
          Loading {ip}…
        </Modal.Body>
      </Modal>
    );
  }

  if (!node) {
    return <EntityDetailModal entityType="IP" entityKey={ip} displayName={ip} fileId={fileId} onClose={onClose} />;
  }

  return (
    <EntityDetailModal
      {...graphNodeEntity(node)}
      fileId={fileId}
      graphNode={node}
      graphEdges={graphEdges}
      onNavigate={onNavigate ?? navigate}
      onClose={onClose}
    />
  );
}
