import { Link } from 'react-router-dom';
import { useCallback, useEffect, useState } from 'react';
import { Button, Card, Form, Modal } from '@govtechsg/sgds-react';
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

interface CaptureRulesCardProps {
  fileId: string;
  /** Called after any change, so the page can reload the matches it shows. */
  onChanged?: () => void;
}

/**
 * This capture's own detection rules (#925 phase 3). They flag conversations in this capture only,
 * straight away, wherever it's viewed; a useful one can be promoted to a global rule.
 */
export function CaptureRulesCard({ fileId, onChanged }: CaptureRulesCardProps) {
  const capturePerm = usePermission('DETECTION_RULES_CAPTURE');
  const globalPerm = usePermission('DETECTION_RULES_GLOBAL');
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [reload, setReload] = useState(0);
  const [editing, setEditing] = useState<DetectionRule | null>(null);
  const [showEditor, setShowEditor] = useState(false);
  const [promoting, setPromoting] = useState<DetectionRule | null>(null);
  const [keepOriginal, setKeepOriginal] = useState(true);
  const [deleting, setDeleting] = useState<DetectionRule | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    detectionRulesService
      .listCapture(fileId)
      .then(setRules)
      .catch(() => setRules([]));
  }, [fileId, reload]);

  const changed = useCallback(
    (message?: string) => {
      setReload(n => n + 1);
      if (message) setNotice(message);
      onChanged?.();
    },
    [onChanged]
  );

  const run = async (action: () => Promise<unknown>, message: string) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      changed(message);
    } catch (e) {
      setError(errorMessage(e, "Couldn't save the change."));
    } finally {
      setBusy(false);
    }
  };

  const canEdit = capturePerm.allowed;

  return (
    <Card className="mb-4" data-testid="capture-rules-card">
      <Card.Body className="py-3">
        <div className="d-flex align-items-center gap-2 mb-1">
          <h6 className="mb-0 me-auto">
            <i className="bi bi-shield-check me-2" aria-hidden="true" />
            Rules for this capture{' '}
            {rules.length > 0 && <span className="text-muted">({rules.length})</span>}
          </h6>
          <Button
            size="sm"
            variant="outline-primary"
            disabled={!canEdit}
            onClick={() => {
              setEditing(null);
              setShowEditor(true);
            }}
          >
            <i className="bi bi-plus me-1" aria-hidden="true" />
            Add rule
          </Button>
        </div>
        <p className="small text-muted mb-2">
          Flag conversations in this capture only, straight away. Rules for every capture are in{' '}
          <Link to="/settings?tab=rules">Settings › Detection rules</Link>.
          {!canEdit && capturePerm.reason && <> You can't add rules here: {capturePerm.reason}</>}
        </p>
        {error && (
          <Alert variant="danger" className="py-2 small">
            {error}
          </Alert>
        )}
        {notice && (
          <Alert
            variant="success"
            className="py-2 small"
            dismissible
            onClose={() => setNotice(null)}
          >
            {notice}
          </Alert>
        )}
        {rules.length > 0 && (
          <ul className="list-unstyled mb-0 small">
            {rules.map(r => (
              <li key={r.id} className="d-flex align-items-center gap-2 border-top py-2">
                <Form.Check
                  type="switch"
                  id={`cap-rule-on-${r.id}`}
                  aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.name}`}
                  checked={r.enabled}
                  disabled={!canEdit || busy}
                  onChange={() =>
                    run(
                      () =>
                        detectionRulesService.update(r.id, { ...toInput(r), enabled: !r.enabled }),
                      r.enabled ? `${r.name} switched off.` : `${r.name} switched on and checked.`
                    )
                  }
                />
                <span className="me-auto">
                  <span className="font-monospace fw-semibold">{r.name}</span>{' '}
                  <span className="text-muted font-monospace">{describeCriteria(r)}</span>
                </span>
                <Button
                  size="sm"
                  variant="outline-secondary"
                  aria-label={`Promote ${r.name} to a global rule`}
                  disabled={!globalPerm.allowed || busy}
                  title={globalPerm.allowed ? undefined : (globalPerm.reason ?? undefined)}
                  onClick={() => {
                    setKeepOriginal(true);
                    setPromoting(r);
                  }}
                >
                  <i className="bi bi-arrow-up-circle me-1" aria-hidden="true" />
                  Promote
                </Button>
                <Button
                  size="sm"
                  variant="outline-primary"
                  aria-label={`${canEdit ? 'Edit' : 'View'} ${r.name}`}
                  onClick={() => {
                    setEditing(r);
                    setShowEditor(true);
                  }}
                >
                  <i className={`bi ${canEdit ? 'bi-pencil' : 'bi-eye'}`} aria-hidden="true" />
                </Button>
                <Button
                  size="sm"
                  variant="outline-danger"
                  aria-label={`Delete ${r.name}`}
                  disabled={!canEdit || busy}
                  onClick={() => setDeleting(r)}
                >
                  <i className="bi bi-trash" aria-hidden="true" />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card.Body>

      <RuleEditorModal
        show={showEditor}
        rule={editing}
        fileId={fileId}
        readOnly={!canEdit}
        onHide={() => setShowEditor(false)}
        onSaved={() =>
          changed(
            editing
              ? 'Rule saved and checked against this capture.'
              : 'Rule added and checked against this capture.'
          )
        }
      />

      <Modal show={promoting !== null} onHide={() => !busy && setPromoting(null)}>
        <Modal.Header closeButton>
          <Modal.Title>Promote to a global rule</Modal.Title>
        </Modal.Header>
        <Modal.Body className="small">
          <p>
            Makes a global copy of <strong className="font-monospace">{promoting?.name}</strong>, so
            it flags matching conversations in every capture. Other captures show as out of date
            until the rules are re-applied to them.
          </p>
          <Form.Check
            id="promote-keep"
            label="Keep this capture's rule as well"
            checked={keepOriginal}
            onChange={e => setKeepOriginal(e.target.checked)}
            disabled={busy}
          />
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setPromoting(null)} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            disabled={busy}
            onClick={async () => {
              const r = promoting;
              setPromoting(null);
              if (r)
                await run(
                  () => detectionRulesService.promote(r.id, keepOriginal),
                  `${r.name} is now a global rule. Re-apply in Settings › Detection rules to check other captures.`
                );
            }}
          >
            Promote
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal show={deleting !== null} onHide={() => !busy && setDeleting(null)}>
        <Modal.Header closeButton>
          <Modal.Title>Delete rule</Modal.Title>
        </Modal.Header>
        <Modal.Body className="small">
          Delete <strong className="font-monospace">{deleting?.name}</strong>? Its matches in this
          capture go with it. The deletion is recorded in the audit log.
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
              if (r) await run(() => detectionRulesService.remove(r.id), `${r.name} deleted.`);
            }}
          >
            Delete
          </Button>
        </Modal.Footer>
      </Modal>
    </Card>
  );
}
