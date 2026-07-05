import { useEffect, useState } from 'react';
import { Badge, Button, Table } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { SubnetSnapshotEditModal } from '@components/monitor/SubnetsPanel/SubnetSnapshotEditModal';
import { hashBadgeStyle } from '@components/common/EntityDetailModal/format';
import { subnetService } from '@/features/subnets/services/subnetService';
import type { SubnetCompositionHistoryEntry } from '@/features/subnets/types/subnet.types';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';

interface SubnetSnapshotHistoryProps {
  subnetId: number;
  cidr: string;
  networkId: string;
  snapshots: NetworkSnapshot[];
}

/**
 * Per-snapshot composition + label history for a subnet — the analog of the IP/DEVICE Snapshot
 * History. Each row shows the subnet's member count and dominant device types / protocols for that
 * snapshot, plus its per-snapshot label (a subnet override) which can be edited inline via a modal.
 */
export function SubnetSnapshotHistory({ subnetId, cidr, networkId, snapshots }: SubnetSnapshotHistoryProps) {
  const [rows, setRows] = useState<SubnetCompositionHistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [editSnap, setEditSnap] = useState<NetworkSnapshot | null>(null);
  // Per-snapshot override for this CIDR, keyed by snapshot id. Seeded from the parent's snapshots and
  // updated locally on save (the parent's prop only refreshes on its next poll). `inherited` marks a
  // label carried forward from an earlier snapshot rather than set directly here.
  type OverrideView = { label: string | null; inherited: boolean };
  const [overrides, setOverrides] = useState<Record<string, OverrideView>>(() =>
    Object.fromEntries(
      snapshots.map(s => {
        const o = s.subnetOverrides?.find(ov => ov.cidr === cidr);
        return [s.id, { label: o?.label ?? null, inherited: o?.inherited ?? false }];
      }),
    ),
  );

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(false);
    subnetService
      .history(subnetId, networkId)
      .then(r => { if (active) setRows(r); })
      .catch(() => { if (active) { setRows([]); setError(true); } })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [subnetId, networkId]);

  const overrideFor = (snapshotId: string): OverrideView =>
    overrides[snapshotId] ?? { label: null, inherited: false };

  return (
    <div className="mt-3">
      <h6 className="text-muted fw-semibold mb-2">
        <i className="bi bi-clock-history me-1" />Snapshot History
      </h6>
      {loading && (
        <div className="text-muted small py-2"><Spinner size="sm" className="me-2" />Loading…</div>
      )}
      {!loading && error && (
        <p className="text-danger small mb-0">
          <i className="bi bi-exclamation-triangle me-1" />Failed to load snapshot history.
        </p>
      )}
      {!loading && !error && rows.length === 0 && (
        <p className="text-muted small fst-italic mb-0">Not seen in any snapshots.</p>
      )}
      {!loading && rows.length > 0 && (
        <div className="rounded border overflow-hidden">
          <Table size="sm" hover responsive className="mb-0">
            <Table.Header className="table-light" style={{ fontSize: '0.8rem' }}>
              <Table.Row>
                <Table.HeaderCell className="text-muted fw-normal">#</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Snapshot</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Members</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Device Types</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Protocols</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Label</Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {rows.map(r => {
                const snap = snapshots.find(s => s.id === r.snapshotId);
                const ov = overrideFor(r.snapshotId);
                return (
                  <Table.Row key={r.snapshotId}>
                    <Table.DataCell><small className="text-muted">{r.snapshotOrder + 1}</small></Table.DataCell>
                    <Table.DataCell>
                      <small className="text-muted text-break" style={{ fontSize: '0.72rem' }}>{r.fileName}</small>
                    </Table.DataCell>
                    <Table.DataCell><small>{r.memberCount}</small></Table.DataCell>
                    <Table.DataCell>
                      {r.deviceTypes.length === 0 ? (
                        <small className="text-muted">—</small>
                      ) : (
                        <div className="d-flex flex-wrap gap-1">
                          {r.deviceTypes.map((d, i) => (
                            <Badge key={`dt-${d}-${i}`} style={{ fontSize: '0.65rem', fontWeight: 400, ...hashBadgeStyle(d) }}>{d}</Badge>
                          ))}
                        </div>
                      )}
                    </Table.DataCell>
                    <Table.DataCell>
                      {r.protocols.length === 0 ? (
                        <small className="text-muted">—</small>
                      ) : (
                        <div className="d-flex flex-wrap gap-1">
                          {r.protocols.map((p, i) => (
                            <Badge key={`p-${p}-${i}`} style={{ fontSize: '0.65rem', fontWeight: 400, ...hashBadgeStyle(p) }}>{p}</Badge>
                          ))}
                        </div>
                      )}
                    </Table.DataCell>
                    <Table.DataCell>
                      <div className="d-flex align-items-center gap-1">
                        {ov.label ? <small>{ov.label}</small> : <small className="text-muted fst-italic">—</small>}
                        {ov.label && ov.inherited && (
                          <Badge
                            bg="light"
                            text="secondary"
                            className="border"
                            style={{ fontSize: '0.55rem', fontWeight: 400 }}
                            title="Inherited from an earlier snapshot (carried forward), not set here"
                          >
                            carried
                          </Badge>
                        )}
                        {snap && (
                          <Button
                            variant="link"
                            size="sm"
                            className="p-0 ms-1 text-muted"
                            style={{ fontSize: '0.75rem', lineHeight: 1 }}
                            title="Edit this subnet's label for this snapshot"
                            onClick={() => setEditSnap(snap)}
                          >
                            <i className="bi bi-pencil" />
                          </Button>
                        )}
                      </div>
                    </Table.DataCell>
                  </Table.Row>
                );
              })}
            </Table.Body>
          </Table>
        </div>
      )}

      {editSnap && (
        <SubnetSnapshotEditModal
          subnetId={subnetId}
          networkId={networkId}
          cidr={cidr}
          snapshot={editSnap}
          onClose={() => setEditSnap(null)}
          onSaved={label => setOverrides(prev => ({ ...prev, [editSnap.id]: { label, inherited: false } }))}
        />
      )}
    </div>
  );
}
