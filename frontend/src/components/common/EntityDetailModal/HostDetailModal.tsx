import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Modal } from '@govtechsg/sgds-react';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { EntityDetailModal } from './EntityDetailModal';
import { graphNodeEntity } from './graphNodeEntity';
import { isPrivateIp } from '@/utils/ipClassification';
import type { EntityDetailModalProps } from './types';

/** Large enough that no host is dropped into the "hidden" overflow while we look one up. */
const ALL_NODES = 100_000;

interface HostDetailModalProps {
  fileId: string;
  /** The host's address. */
  ip?: string;
  /**
   * Or its MAC (a device in Monitor's inventory). With `ip` too, the card opens that host but stays
   * the MAC's (its notes and history); alone, the host carrying that MAC, a local one first.
   */
  mac?: string;
  onClose: () => void;
  /** Where peer/history links go; defaults to the router. */
  onNavigate?: (path: string) => void;
  /** Opened from a monitored network: whether it's still there, when it was last seen, and its captures. */
  monitor?: Pick<EntityDetailModalProps, 'isActive' | 'lastSeenTime' | 'lastSeenFileName' | 'snapshots'>;
}

/**
 * A host's detail from anywhere that only knows its address or MAC (a conversation, a peer row,
 * Monitor's inventory): loads the capture's network graph and opens the same identity-card-and-tabs
 * view the network map shows for that host. Falls back to the plain detail when the host isn't on
 * the graph (e.g. it only appears in filtered-out traffic).
 */
export function HostDetailModal({ fileId, ip, mac, onClose, onNavigate, monitor }: HostDetailModalProps) {
  const navigate = useNavigate();
  const { nodes, edges, hiddenNodesList, crossEdges, loading } = useNetworkData(fileId, undefined, ALL_NODES);
  const label = ip ?? mac ?? '';

  const node = useMemo(() => {
    const all = [...nodes, ...hiddenNodesList];
    if (ip) {
      const byIp = all.find(n => !n.data.isL2 && n.data.ip === ip);
      if (byIp || !mac) return byIp;
    }
    const m = mac?.toLowerCase();
    const withMac = all.filter(n => n.data.mac?.toLowerCase() === m);
    // A device with an address shows its traffic and evidence; a layer-2-only one, its MAC node.
    // A router's MAC is also on every outside host whose traffic it forwarded, so a local address
    // is the device's own; among several, the busiest.
    const hosts = withMac
      .filter(n => !n.data.isL2)
      .sort(
        (a, b) =>
          Number(isPrivateIp(b.data.ip)) - Number(isPrivateIp(a.data.ip)) ||
          (b.data.totalBytes ?? 0) - (a.data.totalBytes ?? 0)
      );
    return hosts[0] ?? withMac[0];
  }, [nodes, hiddenNodesList, ip, mac]);
  const graphEdges = useMemo(() => [...edges, ...crossEdges], [edges, crossEdges]);
  // By MAC it stays a device: its notes and history are the MAC's, across addresses.
  const entity = mac
    ? { entityType: 'DEVICE' as const, entityKey: mac, displayName: mac }
    : ip
      ? { entityType: 'IP' as const, entityKey: ip, displayName: ip }
      : null;

  if (loading) {
    return (
      <Modal
        show
        onHide={onClose}
        dialogClassName="side-drawer side-drawer-host"
        contentClassName="side-drawer-content"
        aria-label={`Loading ${label}`}
      >
        <Modal.Body className="d-flex align-items-center gap-2 py-4 justify-content-center text-muted">
          <span className="spinner-border spinner-border-sm" aria-hidden="true" />
          Loading {label}…
        </Modal.Body>
      </Modal>
    );
  }

  if (!node) {
    return entity ? <EntityDetailModal {...entity} fileId={fileId} {...monitor} onClose={onClose} /> : null;
  }

  return (
    <EntityDetailModal
      {...(mac ? entity! : graphNodeEntity(node))}
      fileId={fileId}
      graphNode={node}
      graphEdges={graphEdges}
      {...monitor}
      onNavigate={onNavigate ?? navigate}
      onClose={onClose}
    />
  );
}
