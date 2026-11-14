import { useEffect, useState } from 'react';
import { Badge, Button, Form } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Pagination } from '@components/common/Pagination/Pagination';
import { SubnetDiagramModal } from '@components/monitor/SubnetDiagramModal/SubnetDiagramModal';
import { SubnetDetailModal } from '@components/monitor/SubnetsPanel/SubnetDetailModal';
import { subnetService } from '@/features/subnets/services/subnetService';
import { networkAddressService } from '@/features/networkAddress/networkAddressService';
import type { SubnetDefinition, SubnetOverlapWarning } from '@/features/subnets/types/subnet.types';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';

interface SubnetsPanelProps {
  networkId: string;
  subnets: SubnetDefinition[];
  snapshots: NetworkSnapshot[];
  onSaved: (subnet: SubnetDefinition) => void;
  onDeleted: (id: number) => void;
  /** Reloads the list, e.g. after reverting brings the default's entry back. */
  onChanged?: () => void;
}


/** A subnet's identity: its CIDR, and which network sharing the range it's for (#462). */
function subnetKey(s: { cidr: string; segmentKey?: string | null }): string {
  return `${s.cidr}|${s.segmentKey ?? ''}`;
}

export const SubnetsPanel = ({ networkId, subnets, snapshots, onSaved, onDeleted, onChanged }: SubnetsPanelProps) => {
  const [showAddForm, setShowAddForm] = useState(false);
  const [addCidr, setAddCidr] = useState('');
  const [addLabel, setAddLabel] = useState('');
  const [addDesc, setAddDesc] = useState('');
  const [addSaving, setAddSaving] = useState(false);

  const [detailSubnet, setDetailSubnet] = useState<SubnetDefinition | null>(null);

  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [diagramSubnet, setDiagramSubnet] = useState<SubnetDefinition | null>(null);
  const [diagramDefaultSnapId, setDiagramDefaultSnapId] = useState<string | undefined>(undefined);

  const [detectSnapshotId, setDetectSnapshotId] = useState('');
  const [detecting, setDetecting] = useState(false);
  const [candidates, setCandidates] = useState<SubnetDefinition[]>([]);
  const [savingCidr, setSavingCidr] = useState<string | null>(null);

  const [subnetsPage, setSubnetsPage] = useState(1);
  const [candidatesPage, setCandidatesPage] = useState(1);
  const PAGE_SIZE = 10;

  // Overlap warnings keyed by subnet id (gateway IP answered by >1 MAC → possible overlapping nets).
  const [overlaps, setOverlaps] = useState<Record<number, SubnetOverlapWarning>>({});
  // Stable signature of the subnet definitions so overlap badges refetch on any add/delete/CIDR
  // edit — but not on every re-render (a raw `subnets` dep would loop, the array is a new ref each time).
  const subnetsKey = subnets.map(s => `${s.id}:${s.cidr}`).join(',');

  useEffect(() => {
    let active = true;
    if (snapshots.length === 0) { setOverlaps({}); return; }
    subnetService
      .overlaps(networkId)
      .then(ws => { if (active) setOverlaps(Object.fromEntries(ws.map(w => [w.subnetId, w]))); })
      .catch(() => { if (active) setOverlaps({}); });
    return () => { active = false; };
  }, [networkId, snapshots.length, subnetsKey]);

  const sortedSnapshots = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);

  const subnetsTotalPages = Math.ceil(subnets.length / PAGE_SIZE);
  const visibleSubnets = subnets.slice((subnetsPage - 1) * PAGE_SIZE, subnetsPage * PAGE_SIZE);
  const candidatesTotalPages = Math.ceil(candidates.length / PAGE_SIZE);
  const visibleCandidates = candidates.slice((candidatesPage - 1) * PAGE_SIZE, candidatesPage * PAGE_SIZE);

  // Keep pages in range as subnets/candidates are added or removed.
  useEffect(() => {
    if (subnetsPage > subnetsTotalPages && subnetsTotalPages > 0) setSubnetsPage(subnetsTotalPages);
  }, [subnetsPage, subnetsTotalPages]);
  useEffect(() => {
    if (candidatesPage > candidatesTotalPages && candidatesTotalPages > 0) setCandidatesPage(candidatesTotalPages);
  }, [candidatesPage, candidatesTotalPages]);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!addCidr.trim()) return;
    setAddSaving(true);
    try {
      // Edits here are this network's own entries (#915 phase 4); the shared default is edited in
      // the System console.
      const saved = await networkAddressService.put(networkId, 'subnets', {
        cidr: addCidr.trim(),
        label: addLabel.trim() || null,
        description: addDesc.trim() || null,
      });
      onSaved(saved as unknown as SubnetDefinition);
      setAddCidr(''); setAddLabel(''); setAddDesc('');
      setShowAddForm(false);
    } finally {
      setAddSaving(false);
    }
  };

  /**
   * In a network, removing a subnet acts on this network only: the default's subnet is hidden
   * here, and the network's own entry is removed (bringing back the default's, if it has one).
   */
  const handleDelete = async (subnet: SubnetDefinition) => {
    if (subnet.id === null) return;
    const id = subnet.id;
    setDeletingId(id);
    try {
      if (subnet.scope === 'network') {
        await networkAddressService.revert(networkId, 'subnets', id);
      } else {
        await networkAddressService.put(networkId, 'subnets', { cidr: subnet.cidr, hidden: true });
      }
      onDeleted(id);
      onChanged?.();
    } finally {
      setDeletingId(null);
    }
  };

  const handleDetect = async () => {
    if (!detectSnapshotId) return;
    const snap = snapshots.find(s => s.id === detectSnapshotId);
    if (!snap) return;
    setDetecting(true);
    setCandidates([]);
    try {
      const results = await subnetService.detect(snap.fileId);
      const savedCidrs = new Set(subnets.map(subnetKey));
      setCandidates(results.filter(c => !savedCidrs.has(subnetKey(c))));
    } finally {
      setDetecting(false);
    }
  };

  const handleDetectNetwork = async () => {
    setDetecting(true);
    setCandidates([]);
    try {
      const results = await subnetService.detectFromNetwork(networkId);
      const savedCidrs = new Set(subnets.map(subnetKey));
      setCandidates(results.filter(c => !savedCidrs.has(subnetKey(c))));
    } finally {
      setDetecting(false);
    }
  };

  const handleSaveCandidate = async (candidate: SubnetDefinition) => {
    setSavingCidr(subnetKey(candidate));
    try {
      const saved = await networkAddressService.put(networkId, 'subnets', {
        cidr: candidate.cidr,
        label: candidate.label ?? null,
        description: candidate.description ?? null,
        segmentKey: candidate.segmentKey ?? null,
        segmentLabel: candidate.segmentLabel ?? null,
      });
      onSaved(saved as unknown as SubnetDefinition);
      setCandidates(prev => prev.filter(c => subnetKey(c) !== subnetKey(candidate)));
    } finally {
      setSavingCidr(null);
    }
  };

  return (
    <>
    <div>
      {/* Saved subnets table */}
      {subnets.length > 0 && (
        <div className="border rounded overflow-hidden mb-3">
          <table className="table table-sm table-hover align-middle mb-0">
            <thead>
              <tr>
                <th className="text-muted fw-normal">CIDR</th>
                <th className="text-muted fw-normal">Label</th>
                <th className="text-muted fw-normal">Description</th>
                <th className="text-muted fw-normal">Source</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visibleSubnets.map(subnet => {
                const warning = subnet.id !== null ? overlaps[subnet.id] : undefined;
                return (
                <tr
                  key={subnet.id}
                  onClick={() => setDetailSubnet(subnet)}
                  style={{ cursor: 'pointer' }}
                  title="Open subnet details"
                >
                      <td className="small">
                        <span className="font-monospace">{subnet.cidr}</span>
                        {subnet.segmentLabel && <div className="text-muted">on {subnet.segmentLabel}</div>}
                      </td>
                      <td className="small">
                        <div className="d-flex align-items-center gap-1">
                          {subnet.label || <span className="text-muted fst-italic">—</span>}
                          {subnet.scope === 'network' && (
                            <Badge bg="primary" style={{ fontSize: '0.6rem' }}>
                              {subnet.overridesDefault ? 'overridden here' : 'this network'}
                            </Badge>
                          )}
                          {subnet.staleSince && (
                            <Badge
                              bg="warning"
                              text="dark"
                              style={{ fontSize: '0.6rem' }}
                              title="Composition drifted since this label was set — open to review"
                            >
                              <i className="bi bi-exclamation-triangle me-1" />Stale
                            </Badge>
                          )}
                          {warning && (
                            <Badge
                              bg="danger"
                              style={{ fontSize: '0.6rem' }}
                              title={`${warning.conflictingIp} is claimed by ${warning.macs.length} MACs — this CIDR may be two overlapping networks. Open for details.`}
                            >
                              <i className="bi bi-diagram-3 me-1" />Overlap?
                            </Badge>
                          )}
                        </div>
                      </td>
                      <td className="small text-muted">{subnet.description || '—'}</td>
                      <td>
                        <span className={`badge ${subnet.source === 'AUTO' ? 'bg-info text-dark' : 'bg-secondary'}`} style={{ fontSize: '0.65rem' }}>
                          {subnet.source === 'AUTO' ? 'Detected' : 'Manual'}
                        </span>
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        <div className="d-flex gap-1">
                          {snapshots.length > 0 && (
                            <Button
                              size="sm"
                              variant="outline-primary"
                              title="View network diagram for this subnet"
                              onClick={() => { setDiagramDefaultSnapId(undefined); setDiagramSubnet(subnet); }}
                            >
                              <i className="bi bi-diagram-2" />
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="outline-danger"
                            aria-label={
                              subnet.scope !== 'network'
                                ? `Hide ${subnet.cidr} in this network`
                                : subnet.overridesDefault
                                  ? `Revert ${subnet.cidr} to the default`
                                  : `Remove ${subnet.cidr}`
                            }
                            onClick={() => handleDelete(subnet)}
                            disabled={deletingId === subnet.id}
                          >
                            {deletingId === subnet.id
                              ? <Spinner animation="border" size="sm" />
                              : <i className="bi bi-trash" />}
                          </Button>
                        </div>
                      </td>
                </tr>
                );
              })}
            </tbody>
          </table>
          {subnetsTotalPages > 1 && (
            <Pagination
              currentPage={subnetsPage}
              totalPages={subnetsTotalPages}
              totalItems={subnets.length}
              pageSize={PAGE_SIZE}
              onPageChange={setSubnetsPage}
              showPageSizeSelector={false}
            />
          )}
        </div>
      )}

      {subnets.length === 0 && !showAddForm && candidates.length === 0 && (
        <p className="text-muted small mb-3">
          No subnets defined. Add manually or detect from a snapshot.
        </p>
      )}

      {/* Detection candidates */}
      {candidates.length > 0 && (
        <div className="mb-3">
          <p className="small fw-semibold mb-2">
            <i className="bi bi-search me-1" />
            Detected subnets — click Save to add:
          </p>
          <div className="border rounded overflow-hidden">
            <table className="table table-sm table-hover align-middle mb-0">
              <thead>
                <tr>
                  <th className="text-muted fw-normal">CIDR</th>
                  <th className="text-muted fw-normal">Hosts</th>
                  <th className="text-muted fw-normal">Density</th>
                  <th className="text-muted fw-normal">Consistency</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {visibleCandidates.map(c => (
                  <tr key={subnetKey(c)}>
                    <td className="small">
                      <span className="font-monospace">{c.cidr}</span>
                      {c.segmentLabel && <div className="text-muted">on {c.segmentLabel}</div>}
                    </td>
                    <td className="small text-muted">{c.hostCount ?? '—'}</td>
                    <td className="small text-muted">
                      {c.densityScore != null
                        ? <>{(c.densityScore * 100).toFixed(1)}%</>
                        : '—'}
                    </td>
                    <td className="small">
                      {c.snapshotsSeen != null && c.totalSnapshots != null ? (
                        <span className={`badge ${c.snapshotsSeen === c.totalSnapshots ? 'bg-success' : c.snapshotsSeen === 1 ? 'bg-warning text-dark' : 'bg-secondary'}`} style={{ fontSize: '0.65rem' }}>
                          {c.snapshotsSeen}/{c.totalSnapshots} snapshots
                        </span>
                      ) : '—'}
                    </td>
                    <td>
                      <div className="d-flex gap-1">
                        <Button
                          size="sm"
                          variant="outline-secondary"
                          title="View network diagram"
                          onClick={() => { setDiagramDefaultSnapId(detectSnapshotId || undefined); setDiagramSubnet(c); }}
                        >
                          <i className="bi bi-diagram-2" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline-primary"
                          onClick={() => handleSaveCandidate(c)}
                          disabled={savingCidr === subnetKey(c)}
                        >
                          {savingCidr === subnetKey(c)
                            ? <Spinner animation="border" size="sm" />
                            : <><i className="bi bi-plus-lg me-1" />Save</>}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {candidatesTotalPages > 1 && (
            <Pagination
              currentPage={candidatesPage}
              totalPages={candidatesTotalPages}
              totalItems={candidates.length}
              pageSize={PAGE_SIZE}
              onPageChange={setCandidatesPage}
              showPageSizeSelector={false}
            />
          )}
        </div>
      )}

      {/* Action row: detect + add manually */}
      <div className="d-flex gap-2 flex-wrap align-items-center">
        {snapshots.length > 0 && (
          <div className="d-flex gap-2 align-items-center flex-wrap">
            <Button
              size="sm"
              variant="outline-secondary"
              onClick={handleDetectNetwork}
              disabled={detecting}
              title="Scan all snapshots and score subnets by consistency across captures"
            >
              {detecting
                ? <><Spinner animation="border" size="sm" className="me-1" />Detecting…</>
                : <><i className="bi bi-layers me-1" />Scan All Snapshots</>}
            </Button>
            <span className="text-muted small">or scan one:</span>
            <Form.Select
              size="sm"
              style={{ width: 'auto', minWidth: 200 }}
              value={detectSnapshotId}
              onChange={e => setDetectSnapshotId(e.target.value)}
            >
              <option value="">Select snapshot…</option>
              {sortedSnapshots.map((s, i) => (
                <option key={s.id} value={s.id}>{i + 1}. {s.fileName}</option>
              ))}
            </Form.Select>
            <Button
              size="sm"
              variant="outline-secondary"
              onClick={handleDetect}
              disabled={!detectSnapshotId || detecting}
            >
              {detecting
                ? <><Spinner animation="border" size="sm" className="me-1" />Detecting…</>
                : <><i className="bi bi-search me-1" />Detect</>}
            </Button>
          </div>
        )}

        {!showAddForm && (
          <Button size="sm" variant="outline-primary" onClick={() => setShowAddForm(true)}>
            <i className="bi bi-plus-lg me-1" />Add Manually
          </Button>
        )}
      </div>

      {/* Add form */}
      {showAddForm && (
        <form onSubmit={handleAdd} className="border rounded p-3 bg-light mt-3">
          <p className="small text-muted mb-2">
            Adds to this network only. Subnets for every network are set in the System console's
            address defaults.
          </p>
          <div className="row g-2">
            <div className="col-sm-4">
              <Form.Label className="small fw-semibold">CIDR <span className="text-danger">*</span></Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="e.g. 10.0.0.0/16"
                value={addCidr}
                onChange={e => setAddCidr(e.target.value)}
                required
              />
            </div>
            <div className="col-sm-4">
              <Form.Label className="small fw-semibold">Label</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="e.g. Corporate LAN"
                value={addLabel}
                onChange={e => setAddLabel(e.target.value)}
              />
            </div>
            <div className="col-sm-4">
              <Form.Label className="small fw-semibold">Description</Form.Label>
              <Form.Control
                size="sm"
                type="text"
                placeholder="Optional"
                value={addDesc}
                onChange={e => setAddDesc(e.target.value)}
              />
            </div>
          </div>
          <div className="d-flex gap-2 mt-3">
            <Button size="sm" type="submit" variant="primary" disabled={addSaving || !addCidr.trim()}>
              {addSaving ? <Spinner animation="border" size="sm" className="me-1" /> : null}
              Save
            </Button>
            <Button size="sm" variant="secondary" onClick={() => { setShowAddForm(false); setAddCidr(''); setAddLabel(''); setAddDesc(''); }} disabled={addSaving}>
              Cancel
            </Button>
          </div>
        </form>
      )}
    </div>

      {diagramSubnet && (
        <SubnetDiagramModal
          subnet={diagramSubnet}
          snapshots={snapshots}
          onHide={() => setDiagramSubnet(null)}
          defaultSnapId={diagramDefaultSnapId}
        />
      )}

      {detailSubnet && (
        <SubnetDetailModal
          subnet={detailSubnet}
          networkId={networkId}
          snapshots={snapshots}
          overlap={detailSubnet.id !== null ? overlaps[detailSubnet.id] ?? null : null}
          onClose={() => setDetailSubnet(null)}
        />
      )}

    </>
  );
};
