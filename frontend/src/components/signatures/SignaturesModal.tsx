import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect } from 'react';
import { Button, ButtonGroup, Form, Modal } from '@govtechsg/sgds-react';
import { Link } from 'react-router-dom';
import { ipOrgRuleService, type IpOrgRule } from '@/features/cluster/services/ipOrgRuleService';

interface SignaturesModalProps {
  show: boolean;
  onHide: () => void;
}

export function SignaturesModal({ show, onHide }: SignaturesModalProps) {
  const [activeTab, setActiveTab] = useState<'rules' | 'labels'>('rules');

  // ── Network Labels tab state ──────────────────────────────────────────────
  const [rules, setRules] = useState<IpOrgRule[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [newLabel, setNewLabel] = useState('');
  const [newCidr, setNewCidr] = useState('');
  const [addError, setAddError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  useEffect(() => {
    if (!show || activeTab !== 'labels') return;
    setRulesLoading(true);
    ipOrgRuleService
      .list()
      .then(setRules)
      .catch(() => setAddError('Failed to load network labels.'))
      .finally(() => setRulesLoading(false));
  }, [show, activeTab]);

  const handleAdd = async () => {
    if (!newLabel.trim() || !newCidr.trim()) {
      setAddError('Both label and CIDR are required.');
      return;
    }
    setAdding(true);
    setAddError(null);
    try {
      const created = await ipOrgRuleService.create(newLabel.trim(), newCidr.trim());
      setRules(prev => [...prev, created].sort((a, b) => a.label.localeCompare(b.label)));
      setNewLabel('');
      setNewCidr('');
    } catch (e: unknown) {
      setAddError(e instanceof Error ? e.message : 'Failed to add rule.');
    } finally {
      setAdding(false);
    }
  };

  const handleDelete = async (id: number) => {
    setDeletingId(id);
    try {
      await ipOrgRuleService.delete(id);
      setRules(prev => prev.filter(r => r.id !== id));
    } catch {
      setAddError('Failed to delete rule.');
    } finally {
      setDeletingId(null);
    }
  };

  const handleHide = () => {
    setActiveTab('rules');
    onHide();
  };

  return (
    <Modal show={show} onHide={handleHide} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>
          <i className="bi bi-shield-check me-2"></i>Custom Detection Rules
        </Modal.Title>
      </Modal.Header>

      <Modal.Body>
        {/* Tabs */}
        <ButtonGroup size="sm" className="mb-3">
          <Button
            variant={activeTab === 'rules' ? 'primary' : 'outline-primary'}
            onClick={() => setActiveTab('rules')}
          >
            <i className="bi bi-code-square me-1" />
            Detection Rules
          </Button>
          <Button
            variant={activeTab === 'labels' ? 'primary' : 'outline-primary'}
            onClick={() => setActiveTab('labels')}
          >
            <i className="bi bi-tag me-1" />
            Network Labels
          </Button>
        </ButtonGroup>

        {/* ── Detection Rules tab ─────────────────────────────────────── */}
        {activeTab === 'rules' && (
          <div className="small">
            <p>
              Detection rules flag conversations that match them, alongside nDPI's built-in risk
              flags. They now live in the database and are edited with a form, with a record of who
              changed what, on the System page.
            </p>
            <Link to="/system?tab=rules" className="btn btn-primary btn-sm" onClick={handleHide}>
              <i className="bi bi-shield-check me-1" aria-hidden="true" />
              Open detection rules
            </Link>
          </div>
        )}

        {/* ── Network Labels tab ──────────────────────────────────────── */}
        {activeTab === 'labels' && (
          <>
            <p className="text-muted small mb-3">
              Map IP addresses or ranges to organisation names. Accepts individual IPs (e.g.{' '}
              <code>10.0.1.5</code>) or CIDR ranges (e.g. <code>10.0.1.0/24</code>). These labels
              are available as the <strong>Network Labels</strong> grouping strategy in the Network
              Intelligence tab. More specific ranges take priority over broader ones.
            </p>

            {/* Existing rules */}
            {rulesLoading ? (
              <div className="text-center py-4 text-muted">
                <Spinner animation="border" size="sm" className="me-2" role="status" />
                Loading…
              </div>
            ) : rules.length === 0 ? (
              <div
                className="text-muted small text-center py-3 border rounded mb-3"
                style={{ background: 'var(--tp-bg-subtle, #f8f9fa)' }}
              >
                No network labels defined yet. Add one below.
              </div>
            ) : (
              <table className="table table-sm table-hover mb-3">
                <thead>
                  <tr>
                    <th>Label</th>
                    <th>CIDR Range</th>
                    <th style={{ width: 48 }}></th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map(r => (
                    <tr key={r.id}>
                      <td>{r.label}</td>
                      <td>
                        <code>{r.cidr}</code>
                      </td>
                      <td>
                        <Button
                          size="sm"
                          variant="link"
                          className="text-danger p-0"
                          onClick={() => handleDelete(r.id)}
                          disabled={deletingId === r.id}
                          title="Delete"
                        >
                          {deletingId === r.id ? (
                            <Spinner
                              animation="border"
                              size="sm"
                              style={{ width: 12, height: 12 }}
                            />
                          ) : (
                            <i className="bi bi-trash" />
                          )}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {/* Add form */}
            <div
              className="border rounded p-3"
              style={{ background: 'var(--tp-bg-subtle, #f8f9fa)' }}
            >
              <div className="row g-2 align-items-end">
                <div className="col">
                  <Form.Label className="small mb-1">Label</Form.Label>
                  <Form.Control
                    size="sm"
                    type="text"
                    placeholder="e.g. Engineering Team"
                    value={newLabel}
                    onChange={e => {
                      setNewLabel(e.target.value);
                      setAddError(null);
                    }}
                    onKeyDown={e => e.key === 'Enter' && handleAdd()}
                  />
                </div>
                <div className="col">
                  <Form.Label className="small mb-1">CIDR Range</Form.Label>
                  <Form.Control
                    size="sm"
                    type="text"
                    placeholder="e.g. 10.0.1.0/24 or 10.0.1.5"
                    value={newCidr}
                    onChange={e => {
                      setNewCidr(e.target.value);
                      setAddError(null);
                    }}
                    onKeyDown={e => e.key === 'Enter' && handleAdd()}
                  />
                </div>
                <div className="col-auto">
                  <Button size="sm" variant="primary" onClick={handleAdd} disabled={adding}>
                    {adding ? (
                      <Spinner animation="border" size="sm" />
                    ) : (
                      <>
                        <i className="bi bi-plus-lg me-1" />
                        Add
                      </>
                    )}
                  </Button>
                </div>
              </div>
              {addError && <div className="text-danger small mt-2">{addError}</div>}
            </div>
          </>
        )}
      </Modal.Body>

      <Modal.Footer>
        <Button variant="outline-secondary" onClick={handleHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
