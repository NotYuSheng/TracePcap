import { useState } from 'react';
import { Badge, Button, Form, Table } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { insightsService } from '@/features/insights/services/insightsService';
import type { EntityType } from '@/features/notes/services/entityNotesService';
import { formatSnapTime, hashBadgeStyle } from '../format';
import type { IpSnapshotEntry } from '../types';

interface SnapshotHistoryTableProps {
  entityType: EntityType;
  entityKey: string;
  ipSnapHistory: IpSnapshotEntry[];
  ipHistoryLoading: boolean;
  /** Called after a per-snapshot role is saved/dismissed so the parent can refetch. */
  onRoleChanged?: () => void;
}

/** Per-snapshot MAC/device/protocol/role history for an IP, with per-snapshot role editing (#369). */
export function SnapshotHistoryTable({
  entityType,
  entityKey,
  ipSnapHistory,
  ipHistoryLoading,
  onRoleChanged,
}: SnapshotHistoryTableProps) {
  const [editingFileId, setEditingFileId] = useState<string | null>(null);
  const [labelDraft, setLabelDraft] = useState('');
  const [descDraft, setDescDraft] = useState('');
  const [saving, setSaving] = useState(false);

  const startEdit = (entry: IpSnapshotEntry) => {
    setEditingFileId(entry.snap.fileId);
    setLabelDraft(entry.roleLabel ?? '');
    setDescDraft('');
  };

  const save = async (fileId: string) => {
    setSaving(true);
    try {
      await insightsService.upsertNodeRole(entityType, entityKey, labelDraft, descDraft, true, fileId);
      setEditingFileId(null);
      onRoleChanged?.();
    } catch (err) {
      console.error('Failed to save snapshot role:', err);
    } finally {
      setSaving(false);
    }
  };

  const dismiss = async (fileId: string) => {
    setSaving(true);
    try {
      await insightsService.dismissNodeRoleStaleness(entityType, entityKey, fileId);
      onRoleChanged?.();
    } catch (err) {
      console.error('Failed to dismiss snapshot staleness:', err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="mt-4">
      <h6 className="text-muted fw-semibold mb-2">
        <i className="bi bi-clock-history me-1" />Snapshot History
      </h6>
      {ipHistoryLoading && (
        <div className="text-muted small py-2">
          <Spinner size="sm" className="me-2" />Loading…
        </div>
      )}
      {!ipHistoryLoading && ipSnapHistory.length === 0 && (
        <p className="text-muted small fst-italic">Not seen in any snapshots.</p>
      )}
      {!ipHistoryLoading && ipSnapHistory.length > 0 && (
        <div className="rounded border overflow-hidden">
          <Table size="sm" hover responsive className="mb-0">
            <Table.Header className="table-light" style={{ fontSize: '0.8rem' }}>
              <Table.Row>
                <Table.HeaderCell className="text-muted fw-normal">#</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Snapshot</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">MAC Address</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Device Type</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Role</Table.HeaderCell>
                <Table.HeaderCell className="text-muted fw-normal">Protocols / Apps</Table.HeaderCell>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {ipSnapHistory.map(({ snap, host, protocols, apps, roleLabel, roleStale }, idx) => (
                <Table.Row key={snap.id}>
                  <Table.DataCell><small className="text-muted">{snap.snapshotOrder + 1}</small></Table.DataCell>
                  <Table.DataCell>
                    <small className="text-muted d-block">{formatSnapTime(snap)}</small>
                    <small className="text-muted text-break" style={{ fontSize: '0.7rem' }}>{snap.fileName}</small>
                  </Table.DataCell>
                  <Table.DataCell>
                    <code style={{ fontSize: '0.75rem' }}>{host?.mac ?? '—'}</code>
                    {idx > 0 && host?.mac && ipSnapHistory[idx - 1].host?.mac &&
                      host.mac !== ipSnapHistory[idx - 1].host!.mac && (
                        <Badge bg="warning" text="dark" className="ms-1" style={{ fontSize: '0.65rem' }}>changed</Badge>
                      )}
                  </Table.DataCell>
                  <Table.DataCell><small className="text-muted">{host?.deviceType ?? '—'}</small></Table.DataCell>
                  <Table.DataCell style={{ minWidth: 180 }}>
                    {editingFileId === snap.fileId ? (
                      <div className="d-flex flex-column gap-1">
                        <Form.Control size="sm" placeholder="Role label" value={labelDraft} onChange={e => setLabelDraft(e.target.value)} autoFocus />
                        <Form.Control size="sm" placeholder="Description (optional)" value={descDraft} onChange={e => setDescDraft(e.target.value)} />
                        <div className="d-flex gap-1">
                          <Button variant="primary" size="sm" className="py-0" style={{ fontSize: '0.7rem' }} disabled={saving || !labelDraft.trim()} onClick={() => save(snap.fileId)}>
                            {saving ? <Spinner size="sm" /> : 'Save'}
                          </Button>
                          <Button variant="outline-secondary" size="sm" className="py-0" style={{ fontSize: '0.7rem' }} disabled={saving} onClick={() => setEditingFileId(null)}>Cancel</Button>
                        </div>
                      </div>
                    ) : (
                      <div className="d-flex align-items-center gap-1">
                        {roleLabel ? <small>{roleLabel}</small> : <small className="text-muted">—</small>}
                        {roleStale && (
                          <Badge bg="warning" text="dark" style={{ fontSize: '0.6rem' }} title="Label flagged stale in this snapshot"><i className="bi bi-exclamation-triangle" /></Badge>
                        )}
                        <Button variant="link" size="sm" className="p-0 ms-1 text-muted" style={{ fontSize: '0.75rem', lineHeight: 1 }} title="Edit role for this snapshot" onClick={() => startEdit({ snap, host, protocols, apps, roleLabel, roleStale })}>
                          <i className="bi bi-pencil" />
                        </Button>
                        {roleStale && (
                          <Button variant="link" size="sm" className="p-0 text-muted" style={{ fontSize: '0.75rem', lineHeight: 1 }} title="Dismiss — label is still correct (re-baseline this snapshot)" disabled={saving} onClick={() => dismiss(snap.fileId)}>
                            <i className="bi bi-check-lg" />
                          </Button>
                        )}
                      </div>
                    )}
                  </Table.DataCell>
                  <Table.DataCell>
                    {protocols.length === 0 && apps.length === 0 ? (
                      <small className="text-muted">—</small>
                    ) : (
                      <div className="d-flex flex-wrap gap-1">
                        {protocols.map((p, i) => (
                          <Badge key={`proto-${p}-${i}`} style={{ fontSize: '0.65rem', fontWeight: 400, ...hashBadgeStyle(p) }}>{p}</Badge>
                        ))}
                        {apps.map((a, i) => (
                          <Badge key={`app-${a}-${i}`} style={{ fontSize: '0.65rem', fontWeight: 400, ...hashBadgeStyle(a) }}>{a}</Badge>
                        ))}
                      </div>
                    )}
                  </Table.DataCell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        </div>
      )}
    </div>
  );
}
