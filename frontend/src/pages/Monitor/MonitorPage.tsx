import { Spinner } from '@components/common/Spinner/Spinner';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Button, Container, Dropdown, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { monitorService } from '@/features/monitor/services/monitorService';
import type { Network } from '@/features/monitor/types/monitor.types';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';
import { markTone, matchesFilter, networkStatus, type NetworkFilter } from './networkStatus';
import './MonitorPage.css';
import { CreateNetworkModal } from '@/components/monitor/CreateNetworkModal/CreateNetworkModal';
import { EditNetworkModal } from '@/components/monitor/EditNetworkModal/EditNetworkModal';

const POLL_MS = 30_000;

const FILTERS: { key: NetworkFilter; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'review', label: 'Needs review' },
  { key: 'empty', label: 'No captures' },
];

export const MonitorPage = () => {
  const [networks, setNetworks] = useState<Network[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [editNetwork, setEditNetwork] = useState<Network | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [filter, setFilter] = useState<NetworkFilter>('all');
  const [query, setQuery] = useState('');
  const [deviceCounts, setDeviceCounts] = useState<Record<string, number>>({});

  const loadNetworks = (showSpinner = false) => {
    if (showSpinner) setLoading(true);
    monitorService
      .listNetworks()
      .then(nets => { setNetworks(nets); setLastUpdated(new Date()); })
      .catch(() => setError('Failed to load networks.'))
      .finally(() => { if (showSpinner) setLoading(false); });
  };

  useEffect(() => {
    loadNetworks(true);
    const interval = setInterval(() => loadNetworks(false), POLL_MS);
    return () => clearInterval(interval);
  }, []);

  // Device totals, one small request per network with captures.
  const withCaptures = networks.filter(n => n.snapshotCount > 0).map(n => n.id).join(',');
  useEffect(() => {
    if (!withCaptures) return;
    let alive = true;
    Promise.all(
      withCaptures.split(',').map(id =>
        apiClient
          .get<{ all: number }>(API_ENDPOINTS.NETWORK_DEVICE_COUNTS(id))
          .then(r => [id, r.data.all] as const)
          .catch(() => null),
      ),
    ).then(rows => {
      if (!alive) return;
      setDeviceCounts(Object.fromEntries(rows.filter((r): r is readonly [string, number] => r != null)));
    });
    return () => {
      alive = false;
    };
  }, [withCaptures]);

  const handleCreate = async (name: string, description: string) => {
    const network = await monitorService.createNetwork(name, description);
    setNetworks(prev => [network, ...prev]);
  };

  const handleUpdate = async (name: string, description: string) => {
    if (!editNetwork) return;
    const updated = await monitorService.updateNetwork(editNetwork.id, name, description);
    setNetworks(prev => prev.map(n => n.id === updated.id ? updated : n));
    setEditNetwork(null);
  };

  const handleDelete = async (id: string) => {
    setDeleting(true);
    try {
      await monitorService.deleteNetwork(id);
      setNetworks(prev => prev.filter(n => n.id !== id));
      setConfirmDeleteId(null);
    } catch {
      setError('Failed to delete network.');
    } finally {
      setDeleting(false);
    }
  };

  const shown = networks.filter(
    n => matchesFilter(n, filter) && n.name.toLowerCase().includes(query.trim().toLowerCase()),
  );
  const count = (f: NetworkFilter) => networks.filter(n => matchesFilter(n, f)).length;

  return (
    <Container className="py-4 monitor-page">
      <div className="d-flex justify-content-between align-items-end mb-3 flex-wrap gap-3">
        <div>
          <h1 className="monitor-title">Monitored networks</h1>
          <p className="text-muted mb-0">
            Captures of the same network over time, each compared with the one before.
          </p>
        </div>
        <Button type="button" variant="primary" onClick={() => setShowCreate(true)}>
          <i className="bi bi-plus-lg me-1" aria-hidden="true"></i>New network
        </Button>
      </div>

      {error && (
        <Alert variant="danger" dismissible onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {loading ? (
        <div className="text-center py-5">
          <Spinner animation="border" className="text-primary" />
        </div>
      ) : networks.length === 0 ? (
        <div className="text-center py-5 text-muted">
          <i className="bi bi-diagram-3 display-4 d-block mb-3" aria-hidden="true"></i>
          <h2 className="h5">No networks yet</h2>
          <p>
            A network collects captures of the same place over time. TracePcap compares each one with
            the last and flags what changed.
          </p>
          <Button type="button" variant="primary" onClick={() => setShowCreate(true)}>
            <i className="bi bi-plus-lg me-1" aria-hidden="true"></i>Create your first network
          </Button>
        </div>
      ) : (
        <>
          <div className="monitor-toolbar">
            <div role="group" aria-label="Show" className="d-flex gap-2 flex-wrap">
              {FILTERS.map(f => (
                <button
                  key={f.key}
                  type="button"
                  className={`monitor-chip${filter === f.key ? ' active' : ''}`}
                  aria-pressed={filter === f.key}
                  onClick={() => setFilter(f.key)}
                >
                  {f.label} {count(f.key)}
                </button>
              ))}
            </div>
            <Form.Control
              type="search"
              size="sm"
              className="monitor-search"
              placeholder="Search networks"
              aria-label="Search networks"
              value={query}
              onChange={e => setQuery(e.target.value)}
            />
          </div>

          <div className="monitor-table-card">
            <div className="table-responsive">
              <table className="table align-middle mb-0 monitor-table">
                <thead>
                  <tr>
                    <th scope="col">Network</th>
                    <th scope="col">Status</th>
                    <th scope="col">Captures</th>
                    <th scope="col">Last capture</th>
                    <th scope="col">Devices</th>
                    <th scope="col">
                      <span className="visually-hidden">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map(n => {
                    const st = networkStatus(n);
                    const caps = n.captures ?? [];
                    const last = caps[caps.length - 1];
                    return (
                      <tr key={n.id}>
                        <td>
                          <Link to={`/monitor/${n.id}`} className="monitor-name">
                            {n.name}
                          </Link>
                          {n.description && <div className="small text-muted">{n.description}</div>}
                        </td>
                        <td>
                          <span className={`monitor-pill monitor-pill-${st.key}`}>{st.label}</span>
                        </td>
                        <td>
                          {caps.length === 0 ? (
                            <span className="small text-muted">None</span>
                          ) : (
                            <span className="monitor-track" aria-label={`${caps.length} capture${caps.length === 1 ? '' : 's'}`}>
                              {caps.slice(-12).map(m => (
                                <span key={m.snapshotId} className={`monitor-dot monitor-dot-${markTone(m)}`} aria-hidden="true" />
                              ))}
                              <span className="small text-muted ms-1">{caps.length}</span>
                            </span>
                          )}
                        </td>
                        <td>
                          {last ? (
                            <>
                              <div>{last.capturedAt ? new Date(parseDateTime(last.capturedAt)).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '—'}</div>
                              <div className="small text-muted text-truncate monitor-file">{last.fileName}</div>
                            </>
                          ) : (
                            <span className="text-muted">Never</span>
                          )}
                        </td>
                        <td className="monitor-num">{deviceCounts[n.id] ?? (caps.length === 0 ? 0 : '…')}</td>
                        <td className="text-end text-nowrap">
                          <Link
                            to={st.to}
                            className={`btn btn-sm ${st.key === 'review' || st.key === 'critical' ? 'btn-primary' : 'btn-outline-secondary'}`}
                          >
                            {st.action}
                          </Link>
                          <Dropdown align="end" className="d-inline-block ms-2">
                            <Dropdown.Toggle
                              variant="outline-secondary"
                              size="sm"
                              className="monitor-more"
                              id={`network-more-${n.id}`}
                              aria-label={`More for ${n.name}`}
                            >
                              <i className="bi bi-three-dots" aria-hidden="true"></i>
                            </Dropdown.Toggle>
                            <Dropdown.Menu>
                              <Dropdown.Item onClick={() => setEditNetwork(n)}>Rename</Dropdown.Item>
                              <Dropdown.Item className="text-danger" onClick={() => setConfirmDeleteId(n.id)}>
                                Delete
                              </Dropdown.Item>
                            </Dropdown.Menu>
                          </Dropdown>
                        </td>
                      </tr>
                    );
                  })}
                  {shown.length === 0 && (
                    <tr>
                      <td colSpan={6} className="text-center text-muted py-4">
                        No networks match.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
          <div className="monitor-legend" aria-label="Capture colours">
            <span><span className="monitor-dot monitor-dot-baseline" aria-hidden="true" />Baseline</span>
            <span><span className="monitor-dot monitor-dot-none" aria-hidden="true" />No changes</span>
            <span><span className="monitor-dot monitor-dot-warning" aria-hidden="true" />Changes</span>
            <span><span className="monitor-dot monitor-dot-critical" aria-hidden="true" />Critical change</span>
            {lastUpdated && <span className="ms-auto">Updated {lastUpdated.toLocaleTimeString()}</span>}
          </div>
        </>
      )}

      <CreateNetworkModal
        show={showCreate}
        onHide={() => setShowCreate(false)}
        onCreate={handleCreate}
      />

      <EditNetworkModal
        show={!!editNetwork}
        onHide={() => setEditNetwork(null)}
        initialName={editNetwork?.name ?? ''}
        initialDescription={editNetwork?.description ?? null}
        onSave={handleUpdate}
      />

      <Modal show={!!confirmDeleteId} onHide={() => setConfirmDeleteId(null)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Delete Network</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="mb-0">
            Are you sure you want to delete{' '}
            <strong>{networks.find(n => n.id === confirmDeleteId)?.name}</strong>?{' '}
            The original PCAP files will not be deleted.
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button
            type="button"
            variant="outline-secondary"
            onClick={() => setConfirmDeleteId(null)}
            disabled={deleting}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="outline-danger"
            onClick={() => confirmDeleteId && handleDelete(confirmDeleteId)}
            disabled={deleting}
          >
            {deleting ? <Spinner animation="border" size="sm" className="me-1" /> : null}
            Delete
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};
