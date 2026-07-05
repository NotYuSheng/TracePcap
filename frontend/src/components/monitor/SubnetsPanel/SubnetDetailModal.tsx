import { useMemo, useState } from 'react';
import { Badge, Button, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { SubnetSnapshotHistory } from '@components/monitor/SubnetsPanel/SubnetSnapshotHistory';
import { subnetService } from '@/features/subnets/services/subnetService';
import type { SubnetDefinition } from '@/features/subnets/types/subnet.types';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';

interface SubnetDetailModalProps {
  subnet: SubnetDefinition;
  networkId: string;
  snapshots: NetworkSnapshot[];
  onClose: () => void;
}

/**
 * Subnet detail modal, structured exactly like the IP/DEVICE {@code EntityDetailModal}: a
 * <em>read-only</em> present-day summary of the label at the top, then a Snapshot History table
 * where the label is set <em>per snapshot</em>. There is no separate global-label editor — the
 * present-day label is simply the latest snapshot's label, mirroring how node roles work.
 */
export function SubnetDetailModal({ subnet, networkId, snapshots, onClose }: SubnetDetailModalProps) {
  const canScan = snapshots.length > 0 && subnet.id !== null;

  // Local copy of the stale state so Dismiss can clear the banner without a full reload.
  const [staleSince, setStaleSince] = useState(subnet.staleSince ?? null);
  const [dismissing, setDismissing] = useState(false);
  const staleFields = subnet.staleFields ?? [];

  const dismiss = async () => {
    if (subnet.id === null) return;
    setDismissing(true);
    try {
      await subnetService.dismissStaleness(subnet.id, networkId);
      setStaleSince(null);
    } catch {
      /* leave the banner up on failure */
    } finally {
      setDismissing(false);
    }
  };

  // Present-day = the latest snapshot's per-snapshot override label for this CIDR (read-only).
  const presentDayLabel = useMemo(() => {
    const latest = [...snapshots].sort((a, b) => b.snapshotOrder - a.snapshotOrder)[0];
    return latest?.subnetOverrides?.find(o => o.cidr === subnet.cidr)?.label ?? null;
  }, [snapshots, subnet.cidr]);

  return (
    <Modal show onHide={onClose} size="lg" centered>
      <Modal.Header closeButton>
        <Modal.Title className="h6 mb-0">
          <i className="bi bi-diagram-2 me-2" />
          <span className="font-monospace">{subnet.cidr}</span>
          {subnet.source === 'AUTO'
            ? <Badge bg="info" text="dark" className="ms-2" style={{ fontSize: '0.6rem' }}>Detected</Badge>
            : <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.6rem' }}>Manual</Badge>}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {/* ── Present-day label (read-only) ─────────────────────────────── */}
        <div className="mb-2">
          <h6 className="border-bottom pb-1 mb-2">
            Label <span className="text-muted fw-normal" style={{ fontSize: '0.75rem' }}>· present-day (latest snapshot)</span>
          </h6>
          {staleSince && (
            <Alert variant="warning" className="p-2 mb-2 small">
              <div className="d-flex align-items-start gap-2">
                <i className="bi bi-exclamation-triangle-fill mt-1 flex-shrink-0" />
                <div>
                  <strong>This label may be stale.</strong> The subnet's composition has drifted since
                  it was labelled.
                  {staleFields.length > 0 && (
                    <ul className="mb-0 mt-1 ps-3">
                      {staleFields.slice(0, 6).map((f, i) => <li key={i}>{f}</li>)}
                    </ul>
                  )}
                </div>
              </div>
              <div className="mt-2">
                <Button
                  variant="outline-secondary"
                  size="sm"
                  className="py-0"
                  style={{ fontSize: '0.75rem' }}
                  onClick={dismiss}
                  disabled={dismissing}
                  title="Mark the label as still correct and reset the composition baseline"
                >
                  {dismissing
                    ? <><Spinner size="sm" className="me-1" />Dismissing…</>
                    : <><i className="bi bi-check-lg me-1" />Dismiss — label is still correct</>}
                </Button>
              </div>
            </Alert>
          )}
          {presentDayLabel ? (
            <div className="p-2 rounded small bg-light">
              <div className="fw-semibold">
                {presentDayLabel}
                {staleSince && (
                  <Badge bg="warning" text="dark" className="ms-2" style={{ fontSize: '0.6rem' }}>
                    <i className="bi bi-exclamation-triangle me-1" />Stale
                  </Badge>
                )}
              </div>
            </div>
          ) : (
            <p className="text-muted small fst-italic mb-0">
              No label assigned. Set one per snapshot in the history below.
            </p>
          )}
        </div>

        {/* ── Per-snapshot history (where labels are set) ───────────────── */}
        {canScan && subnet.id !== null && (
          <SubnetSnapshotHistory
            subnetId={subnet.id}
            cidr={subnet.cidr}
            networkId={networkId}
            snapshots={snapshots}
          />
        )}
      </Modal.Body>
    </Modal>
  );
}
