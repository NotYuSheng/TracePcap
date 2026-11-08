import { useEffect, useState } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { usePermission } from '@/features/me/useMe';
import { RuleEditorModal } from '@/pages/System/RuleEditorModal';
import { describeCriteria } from './describeCriteria';
import {
  detectionRulesService,
  errorMessage,
  toInput,
  type DetectionRule,
} from './detectionRulesService';
import { RuleSyncBanner } from './RuleSyncBanner';

interface NetworkRulesModalProps {
  show: boolean;
  networkId: string;
  networkName: string;
  onHide: () => void;
}

/**
 * One network's own detection rules (#925 phase 3). Their matches show when the network's
 * captures are viewed in this network. Opening the editor stacks a second SGDS modal; each closes
 * on its own Escape.
 */
export function NetworkRulesModal({
  show,
  networkId,
  networkName,
  onHide,
}: NetworkRulesModalProps) {
  const perm = usePermission('DETECTION_RULES_NETWORK');
  const globalPerm = usePermission('DETECTION_RULES_GLOBAL');
  const [rules, setRules] = useState<DetectionRule[] | null>(null);
  const [reload, setReload] = useState(0);
  const [editing, setEditing] = useState<DetectionRule | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [deleting, setDeleting] = useState<DetectionRule | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!show) return;
    detectionRulesService
      .listNetwork(networkId)
      .then(setRules)
      .catch(() => setRules([]));
  }, [show, networkId, reload]);

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      setReload(n => n + 1);
    } catch (e) {
      setError(errorMessage(e, "Couldn't save the change."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Modal show={show && !showEditor && deleting === null} onHide={onHide} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Detection rules for {networkName}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="small text-muted">
            These rules flag conversations in this network's captures, and show when you view them
            here (snapshots, the Security tab). Each capture that joins the network is checked
            against them. Rules for every capture are on the System page.
          </p>
          {!perm.allowed && (
            <Alert variant="info" className="py-2 small">
              <i className="bi bi-lock me-2" aria-hidden="true" />
              You can view these rules but not change them:{' '}
              {perm.reason ?? 'only admins can change them.'}
            </Alert>
          )}
          {error && (
            <Alert variant="danger" className="py-2 small">
              {error}
            </Alert>
          )}
          <RuleSyncBanner
            canReapply={globalPerm.allowed}
            reason={globalPerm.reason}
            refreshKey={reload}
          />
          <div className="d-flex mb-2">
            <Button
              size="sm"
              className="ms-auto"
              disabled={!perm.allowed}
              onClick={() => {
                setEditing(null);
                setShowEditor(true);
              }}
            >
              <i className="bi bi-plus me-1" aria-hidden="true" />
              Add rule
            </Button>
          </div>
          {rules && rules.length === 0 && (
            <p className="small text-muted mb-0">No rules for this network yet.</p>
          )}
          {rules && rules.length > 0 && (
            <ul className="list-unstyled small mb-0">
              {rules.map(r => (
                <li key={r.id} className="d-flex align-items-center gap-2 border-top py-2">
                  <Form.Check
                    type="switch"
                    id={`net-rule-on-${r.id}`}
                    aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.name}`}
                    checked={r.enabled}
                    disabled={!perm.allowed || busy}
                    onChange={() =>
                      run(() =>
                        detectionRulesService.update(r.id, { ...toInput(r), enabled: !r.enabled })
                      )
                    }
                  />
                  <span className="me-auto">
                    <span className="font-monospace fw-semibold">{r.name}</span>{' '}
                    <span className="text-muted font-monospace">{describeCriteria(r)}</span>
                    <div className="text-muted">
                      {r.updatedBy} · v{r.version}
                    </div>
                  </span>
                  <Button
                    size="sm"
                    variant="outline-primary"
                    aria-label={`${perm.allowed ? 'Edit' : 'View'} ${r.name}`}
                    onClick={() => {
                      setEditing(r);
                      setShowEditor(true);
                    }}
                  >
                    <i
                      className={`bi ${perm.allowed ? 'bi-pencil' : 'bi-eye'}`}
                      aria-hidden="true"
                    />
                  </Button>
                  <Button
                    size="sm"
                    variant="outline-danger"
                    aria-label={`Delete ${r.name}`}
                    disabled={!perm.allowed || busy}
                    onClick={() => setDeleting(r)}
                  >
                    <i className="bi bi-trash" aria-hidden="true" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={onHide}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>

      <RuleEditorModal
        show={show && showEditor}
        rule={editing}
        networkId={networkId}
        readOnly={!perm.allowed}
        onHide={() => setShowEditor(false)}
        onSaved={() => setReload(n => n + 1)}
      />

      <Modal show={show && deleting !== null} onHide={() => !busy && setDeleting(null)}>
        <Modal.Header closeButton>
          <Modal.Title>Delete rule</Modal.Title>
        </Modal.Header>
        <Modal.Body className="small">
          Delete <strong className="font-monospace">{deleting?.name}</strong>? Its matches in this
          network go with it. The deletion is recorded in the audit log.
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setDeleting(null)} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={busy}
            onClick={async () => {
              const r = deleting;
              setDeleting(null);
              if (r) await run(() => detectionRulesService.remove(r.id));
            }}
          >
            Delete
          </Button>
        </Modal.Footer>
      </Modal>
    </>
  );
}
