import { useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { SubnetDiagramModal } from '@components/monitor/SubnetDiagramModal/SubnetDiagramModal';
import { subnetService } from '@/features/subnets/services/subnetService';
import type { SubnetDefinition } from '@/features/subnets/types/subnet.types';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';

interface SubnetsPanelProps {
  networkId: string;
  subnets: SubnetDefinition[];
  snapshots: NetworkSnapshot[];
  onSaved: (subnet: SubnetDefinition) => void;
  onDeleted: (id: number) => void;
}

interface EditState {
  id: number | null;
  cidr: string;
  label: string;
  description: string;
}

export const SubnetsPanel = ({ networkId, subnets, snapshots, onSaved, onDeleted }: SubnetsPanelProps) => {
  const [showAddForm, setShowAddForm] = useState(false);
  const [addCidr, setAddCidr] = useState('');
  const [addLabel, setAddLabel] = useState('');
  const [addDesc, setAddDesc] = useState('');
  const [addSaving, setAddSaving] = useState(false);

  const [editState, setEditState] = useState<EditState | null>(null);
  const [editSaving, setEditSaving] = useState(false);

  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [diagramSubnet, setDiagramSubnet] = useState<SubnetDefinition | null>(null);
  const [diagramDefaultSnapId, setDiagramDefaultSnapId] = useState<string | undefined>(undefined);

  const [detectSnapshotId, setDetectSnapshotId] = useState('');
  const [detecting, setDetecting] = useState(false);
  const [candidates, setCandidates] = useState<SubnetDefinition[]>([]);
  const [savingCidr, setSavingCidr] = useState<string | null>(null);

  const sortedSnapshots = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!addCidr.trim()) return;
    setAddSaving(true);
    try {
      const saved = await subnetService.upsert(addCidr.trim(), addLabel.trim(), addDesc.trim(), true);
      onSaved(saved);
      setAddCidr(''); setAddLabel(''); setAddDesc('');
      setShowAddForm(false);
    } finally {
      setAddSaving(false);
    }
  };

  const handleEditSave = async () => {
    if (!editState) return;
    setEditSaving(true);
    try {
      const saved = await subnetService.upsert(editState.cidr.trim(), editState.label.trim(), editState.description.trim(), true);
      onSaved(saved);
      setEditState(null);
    } finally {
      setEditSaving(false);
    }
  };

  const handleDelete = async (id: number) => {
    setDeletingId(id);
    try {
      await subnetService.delete(id);
      onDeleted(id);
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
      const savedCidrs = new Set(subnets.map(s => s.cidr));
      setCandidates(results.filter(c => !savedCidrs.has(c.cidr)));
    } finally {
      setDetecting(false);
    }
  };

  const handleDetectNetwork = async () => {
    setDetecting(true);
    setCandidates([]);
    try {
      const results = await subnetService.detectFromNetwork(networkId);
      const savedCidrs = new Set(subnets.map(s => s.cidr));
      setCandidates(results.filter(c => !savedCidrs.has(c.cidr)));
    } finally {
      setDetecting(false);
    }
  };

  const handleSaveCandidate = async (candidate: SubnetDefinition) => {
    setSavingCidr(candidate.cidr);
    try {
      const saved = await subnetService.saveDetected(candidate.cidr, candidate.label ?? '', candidate.description ?? '');
      onSaved(saved);
      setCandidates(prev => prev.filter(c => c.cidr !== candidate.cidr));
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
              {subnets.map(subnet => (
                <tr key={subnet.id}>
                  {editState?.id === subnet.id ? (
                    <>
                      <td>
                        <Form.Control
                          size="sm"
                          value={editState.cidr}
                          onChange={e => setEditState({ ...editState, cidr: e.target.value })}
                        />
                      </td>
                      <td>
                        <Form.Control
                          size="sm"
                          value={editState.label}
                          onChange={e => setEditState({ ...editState, label: e.target.value })}
                          placeholder="e.g. Corporate LAN"
                        />
                      </td>
                      <td>
                        <Form.Control
                          size="sm"
                          value={editState.description}
                          onChange={e => setEditState({ ...editState, description: e.target.value })}
                          placeholder="Optional description"
                        />
                      </td>
                      <td></td>
                      <td>
                        <div className="d-flex gap-1">
                          <Button size="sm" variant="primary" onClick={handleEditSave} disabled={editSaving || !editState.cidr.trim()}>
                            {editSaving ? <Spinner animation="border" size="sm" /> : <i className="bi bi-floppy" />}
                          </Button>
                          <Button size="sm" variant="outline-secondary" onClick={() => setEditState(null)} disabled={editSaving}>
                            <i className="bi bi-x-lg" />
                          </Button>
                        </div>
                      </td>
                    </>
                  ) : (
                    <>
                      <td className="font-monospace small">{subnet.cidr}</td>
                      <td className="small">{subnet.label || <span className="text-muted fst-italic">—</span>}</td>
                      <td className="small text-muted">{subnet.description || '—'}</td>
                      <td>
                        <span className={`badge ${subnet.source === 'AUTO' ? 'bg-info text-dark' : 'bg-secondary'}`} style={{ fontSize: '0.65rem' }}>
                          {subnet.source === 'AUTO' ? 'Detected' : 'Manual'}
                        </span>
                      </td>
                      <td>
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
                            variant="outline-secondary"
                            onClick={() => setEditState({ id: subnet.id, cidr: subnet.cidr, label: subnet.label ?? '', description: subnet.description ?? '' })}
                          >
                            <i className="bi bi-pencil" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline-danger"
                            onClick={() => subnet.id !== null && handleDelete(subnet.id)}
                            disabled={deletingId === subnet.id}
                          >
                            {deletingId === subnet.id
                              ? <Spinner animation="border" size="sm" />
                              : <i className="bi bi-trash" />}
                          </Button>
                        </div>
                      </td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
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
                {candidates.map(c => (
                  <tr key={c.cidr}>
                    <td className="font-monospace small">{c.cidr}</td>
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
                          disabled={savingCidr === c.cidr}
                        >
                          {savingCidr === c.cidr
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

    </>
  );
};
