import { useCallback, useEffect, useState } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { insightsService } from '@/features/insights/services/insightsService';
import { subnetService } from '@/features/subnets/services/subnetService';
import type { SubnetDefinition } from '@/features/subnets/types/subnet.types';
import type { NetworkSnapshot, SubnetOverrideInput } from '@/features/monitor/types/monitor.types';

interface Props {
  networkId: string;
  snapshot: NetworkSnapshot;
  onSnapshotUpdated: (updated: NetworkSnapshot) => void;
}

/** This capture's own subnet list, overriding the network's for its change detection. */
export function SnapshotSubnetsTab({ networkId, snapshot, onSnapshotUpdated }: Props) {
  const [subnetDraft, setSubnetDraft] = useState<SubnetOverrideInput[]>(
    (snapshot.subnetOverrides ?? []).map(o => ({ cidr: o.cidr, label: o.label, description: o.description, inherited: o.inherited }))
  );
  const [subnetCustomizeMode, setSubnetCustomizeMode] = useState((snapshot.subnetOverrides ?? []).length > 0);
  const [subnetNewCidr, setSubnetNewCidr] = useState('');
  const [subnetNewLabel, setSubnetNewLabel] = useState('');
  const [loadingGlobals, setLoadingGlobals] = useState(false);
  const [savingSubnets, setSavingSubnets] = useState(false);
  const subnetOverridesActive = subnetCustomizeMode;

  // Detect unsaved subnet edits by comparing the draft against the persisted overrides.
  const serializeOverrides = (rows: { cidr: string; label: string | null; description: string | null }[]) =>
    rows.map(o => `${o.cidr}|${o.label ?? ''}|${o.description ?? ''}`).join(',');
  const subnetChanged =
    serializeOverrides(subnetDraft) !== serializeOverrides(snapshot.subnetOverrides ?? []);

  // Stable key: changes only when the server-persisted overrides actually change (IDs rotate on each save)
  const savedOverrideKey = (snapshot.subnetOverrides ?? []).map(o => o.id).join(',');
  // Keep draft in sync when parent updates the snapshot (e.g. after save), without resetting on every poll
  useEffect(() => {
    const saved = snapshot.subnetOverrides ?? [];
    setSubnetDraft(saved.map(o => ({
      cidr: o.cidr, label: o.label, description: o.description, inherited: o.inherited,
    })));
    setSubnetCustomizeMode(saved.length > 0);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshot.id, savedOverrideKey]);

  const handleLoadGlobalSubnets = useCallback(async () => {
    setLoadingGlobals(true);
    try {
      const globals = await subnetService.list(networkId);
      setSubnetDraft(globals.map((s: SubnetDefinition) => ({
        cidr: s.cidr, label: s.label ?? null, description: s.description ?? null, inherited: true,
      })));
    } catch {
      // fetch failed — user can still add CIDRs manually
    } finally {
      setSubnetCustomizeMode(true);
      setLoadingGlobals(false);
    }
  }, [networkId]);

  const updateSubnetRow = (i: number, field: 'cidr' | 'label', value: string | null) => {
    setSubnetDraft(prev => prev.map((o, idx) =>
      idx === i ? { ...o, [field]: value, inherited: false } : o
    ));
  };

  const removeSubnetRow = (i: number) => setSubnetDraft(prev => prev.filter((_, idx) => idx !== i));

  const addSubnetRow = () => {
    const cidr = subnetNewCidr.trim();
    if (!cidr) return;
    setSubnetDraft(prev => [...prev, { cidr, label: subnetNewLabel.trim() || null, description: null, inherited: false }]);
    setSubnetNewCidr('');
    setSubnetNewLabel('');
  };

  const handleSaveSubnets = async () => {
    setSavingSubnets(true);
    try {
      const updated = await insightsService.patchSnapshot(networkId, snapshot.id, {
        subnetOverrides: subnetDraft,
      });
      onSnapshotUpdated(updated);
    } finally {
      setSavingSubnets(false);
    }
  };

  const handleResetSubnets = async () => {
    setSavingSubnets(true);
    try {
      const updated = await insightsService.patchSnapshot(networkId, snapshot.id, {
        subnetOverrides: [],
      });
      onSnapshotUpdated(updated);
      setSubnetDraft([]);
      setSubnetCustomizeMode(false);
    } finally {
      setSavingSubnets(false);
    }
  };

  return (
    <div>
      <p className="text-muted small mb-3">
        Override which CIDR ranges are treated as <strong>internal</strong> for this snapshot's change detection.
        If no overrides are set, the global subnet definitions apply.
      </p>

      {!subnetOverridesActive ? (
        <div className="text-center py-4 border rounded bg-light">
          <i className="bi bi-diagram-2 text-muted d-block mb-2" style={{ fontSize: '2rem' }} />
          <p className="text-muted small mb-3">Using global subnet definitions for change detection.</p>
          <Button size="sm" variant="outline-primary" disabled={loadingGlobals} onClick={handleLoadGlobalSubnets}>
            {loadingGlobals
              ? <><Spinner animation="border" size="sm" className="me-1" />Loading…</>
              : <><i className="bi bi-pencil me-1" />Customize for this snapshot</>}
          </Button>
        </div>
      ) : (
        <>
          <div className="d-flex align-items-center justify-content-between mb-2">
            <span className="small text-muted">
              {subnetDraft.length} range{subnetDraft.length !== 1 ? 's' : ''}&nbsp;—&nbsp;
              <span className="text-success">{subnetDraft.filter(o => o.inherited).length} inherited</span>,&nbsp;
              <span className="text-primary">{subnetDraft.filter(o => !o.inherited).length} custom</span>
            </span>
            <Button
              size="sm"
              variant="outline-danger"
              disabled={savingSubnets}
              onClick={handleResetSubnets}
              title="Remove all overrides and fall back to global definitions"
            >
              <i className="bi bi-arrow-counterclockwise me-1" />Reset to global
            </Button>
          </div>

          {subnetDraft.length > 0 ? (
            <div className="table-responsive mb-3">
              <table className="table table-sm table-bordered mb-0" style={{ fontSize: '0.82rem' }}>
                <thead className="table-light">
                  <tr>
                    <th style={{ width: '38%' }}>CIDR</th>
                    <th>Label</th>
                    <th style={{ width: '6rem' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {subnetDraft.map((o, i) => (
                    <tr key={i}>
                      <td>
                        <input
                          className="form-control form-control-sm font-monospace"
                          value={o.cidr}
                          onChange={e => updateSubnetRow(i, 'cidr', e.target.value)}
                          style={{ fontSize: '0.8rem' }}
                        />
                      </td>
                      <td>
                        <input
                          className="form-control form-control-sm"
                          value={o.label ?? ''}
                          onChange={e => updateSubnetRow(i, 'label', e.target.value || null)}
                          placeholder="Optional"
                          style={{ fontSize: '0.8rem' }}
                        />
                      </td>
                      <td className="text-center align-middle">
                        {o.inherited && (
                          <span className="badge bg-secondary me-1" style={{ fontSize: '0.6rem' }}>Inherited</span>
                        )}
                        <button
                          type="button"
                          className="btn btn-sm btn-outline-danger p-0"
                          style={{ width: 22, height: 22, lineHeight: 1 }}
                          onClick={() => removeSubnetRow(i)}
                          title="Remove"
                        >
                          <i className="bi bi-trash" style={{ fontSize: '0.7rem' }} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-muted text-center small py-2 mb-3 border rounded">
              No ranges configured. Saving an empty list reverts this snapshot to global definitions.
            </p>
          )}

          <div className="d-flex gap-2 align-items-center mb-3 flex-wrap">
            <input
              className="form-control form-control-sm font-monospace"
              placeholder="e.g. 192.168.1.0/24"
              value={subnetNewCidr}
              onChange={e => setSubnetNewCidr(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addSubnetRow(); } }}
              style={{ maxWidth: 200, fontSize: '0.82rem' }}
            />
            <input
              className="form-control form-control-sm"
              placeholder="Label (optional)"
              value={subnetNewLabel}
              onChange={e => setSubnetNewLabel(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addSubnetRow(); } }}
              style={{ maxWidth: 200, fontSize: '0.82rem' }}
            />
            <Button size="sm" variant="outline-primary" onClick={addSubnetRow} disabled={!subnetNewCidr.trim()}>
              <i className="bi bi-plus me-1" />Add CIDR
            </Button>
          </div>

          <Button
            size="sm"
            variant="primary"
            onClick={handleSaveSubnets}
            disabled={savingSubnets || !subnetChanged}
          >
            {savingSubnets
              ? <><Spinner animation="border" size="sm" className="me-1" />Saving…</>
              : <><i className="bi bi-floppy me-1" />Save subnet overrides</>}
          </Button>
        </>
      )}
    </div>
  );
}
