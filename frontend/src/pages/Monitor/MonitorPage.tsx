import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Container, Row, Col, Modal } from '@govtechsg/sgds-react';
import { monitorService } from '@/features/monitor/services/monitorService';
import type { Network } from '@/features/monitor/types/monitor.types';
import { NetworkCard } from '@/components/monitor/NetworkCard/NetworkCard';
import { CreateNetworkModal } from '@/components/monitor/CreateNetworkModal/CreateNetworkModal';

export const MonitorPage = () => {
  const navigate = useNavigate();
  const [networks, setNetworks] = useState<Network[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [pollInterval, setPollInterval] = useState(30);

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
    if (pollInterval === 0) return;
    const interval = setInterval(() => loadNetworks(false), pollInterval * 1000);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pollInterval]);

  const handleCreate = async (name: string, description: string) => {
    const network = await monitorService.createNetwork(name, description);
    setNetworks(prev => [network, ...prev]);
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

  return (
    <Container className="py-4">
      <div className="d-flex justify-content-between align-items-start mb-4 flex-wrap gap-2">
        <div>
          <h3 className="mb-1">Network Monitor</h3>
          <p className="text-muted mb-0">
            Group PCAPs by network to track changes over time.
          </p>
        </div>
        <div className="d-flex align-items-center gap-2 flex-wrap">
          {lastUpdated && (
            <small className="text-muted">
              <i className="bi bi-clock me-1"></i>
              Updated {lastUpdated.toLocaleTimeString()}
            </small>
          )}
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={() => loadNetworks(false)}
            title="Refresh now"
          >
            <i className="bi bi-arrow-clockwise"></i>
          </button>
          <select
            className="form-select form-select-sm"
            style={{ width: 'auto' }}
            value={pollInterval}
            onChange={e => setPollInterval(Number(e.target.value))}
            title="Auto-refresh interval"
          >
            <option value={10}>Every 10s</option>
            <option value={30}>Every 30s</option>
            <option value={60}>Every 1m</option>
            <option value={300}>Every 5m</option>
            <option value={0}>Manual only</option>
          </select>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setShowCreate(true)}
          >
            <i className="bi bi-plus-lg me-1"></i>Create Network
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible">
          {error}
          <button type="button" className="btn-close" onClick={() => setError(null)} />
        </div>
      )}

      {loading ? (
        <div className="text-center py-5">
          <div className="spinner-border text-primary" role="status" />
        </div>
      ) : networks.length === 0 ? (
        <div className="text-center py-5 text-muted">
          <i className="bi bi-diagram-3 display-4 d-block mb-3"></i>
          <h5>No networks yet</h5>
          <p>Create a network group to start monitoring changes across PCAPs.</p>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setShowCreate(true)}
          >
            <i className="bi bi-plus-lg me-1"></i>Create your first network
          </button>
        </div>
      ) : (
        <Row>
          {networks.map(network => (
            <Col key={network.id} xs={12} md={6} lg={4} className="mb-3">
              <NetworkCard
                network={network}
                onClick={() => navigate(`/monitor/${network.id}`)}
                onDelete={() => setConfirmDeleteId(network.id)}
              />
            </Col>
          ))}
        </Row>
      )}

      <CreateNetworkModal
        show={showCreate}
        onHide={() => setShowCreate(false)}
        onCreate={handleCreate}
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
          <button
            type="button"
            className="btn btn-outline-secondary"
            onClick={() => setConfirmDeleteId(null)}
            disabled={deleting}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-outline-danger"
            onClick={() => confirmDeleteId && handleDelete(confirmDeleteId)}
            disabled={deleting}
          >
            {deleting ? <span className="spinner-border spinner-border-sm me-1" /> : null}
            Delete
          </button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
};
