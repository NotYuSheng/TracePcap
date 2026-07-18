import { useState } from 'react';
import { Badge, Button, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { staleTooltip } from '@/features/insights/utils/nodeRoleStaleness';
import type { useEntityRole } from '../hooks/useEntityRole';

interface RoleSectionProps {
  fileId: string;
  role: ReturnType<typeof useEntityRole>;
  /**
   * Read-only "present-day" summary (no editing). Used in the multi-snapshot drift-panel modal,
   * where roles are edited per-snapshot in the Snapshot History table below (#369).
   */
  readOnly?: boolean;
  /**
   * When set, the role help modal renders above a raised parent panel (monitor mode's NodeDetails
   * is itself a modal, so a plain nested modal would hide behind it — modal-in-modal).
   */
  raisedModal?: boolean;
}

/** Role panel for IP/DEVICE entities — view, AI-suggest, accept/discard, manual edit. */
export function RoleSection({ fileId, role: r, readOnly, raisedModal }: RoleSectionProps) {
  const [showRoleHelp, setShowRoleHelp] = useState(false);
  if (readOnly) {
    return (
      <div className="mb-4">
        <h6 className="border-bottom pb-1 mb-2">Role <span className="text-muted fw-normal" style={{ fontSize: '0.75rem' }}>· present-day (latest snapshot)</span></h6>
        {r.roleLoading && <div className="text-muted small fst-italic">Loading role…</div>}
        {!r.roleLoading && !r.role && (
          <p className="text-muted small fst-italic mb-0">No role assigned. Set one per snapshot in the history below.</p>
        )}
        {!r.roleLoading && r.role && (
          <div className={`p-2 rounded small ${r.role.confirmedByHuman && r.role.staleSince ? 'bg-warning-subtle border border-warning' : 'bg-light'}`}>
            <div className="fw-semibold">
              {r.role.roleLabel || <span className="text-muted fst-italic">No label</span>}
              {r.role.llmSuggested && !r.role.confirmedByHuman && (
                <Badge bg="warning" text="dark" className="ms-2" style={{ fontSize: '0.65rem' }}><i className="bi bi-stars me-1" />AI suggested</Badge>
              )}
              {r.role.confirmedByHuman && (
                <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.65rem' }}><i className="bi bi-tag me-1" />Manual label</Badge>
              )}
              {r.role.confirmedByHuman && r.role.staleSince && (
                <Badge bg="warning" text="dark" className="ms-2" style={{ fontSize: '0.65rem' }} title={staleTooltip(r.role)}><i className="bi bi-exclamation-triangle me-1" />Stale</Badge>
              )}
            </div>
            {r.role.roleDescription && <div className="text-muted mt-1">{r.role.roleDescription}</div>}
          </div>
        )}
      </div>
    );
  }
  return (
    <div className="mb-4">
      <h6 className="border-bottom pb-1 mb-2 d-flex align-items-center justify-content-between">
        <span>
          Role <span className="text-muted fw-normal" style={{ fontSize: '0.75rem' }}>· analyst-assigned name</span>
          <i
            role="button"
            aria-label="What is a role label?"
            className="bi bi-info-circle ms-1 text-muted"
            style={{ fontSize: '0.72rem', cursor: 'pointer' }}
            onClick={() => setShowRoleHelp(v => !v)}
          />
        </span>
        {!r.roleEditing && !r.roleLoading && (
          <div className="d-flex gap-1">
            <Button
              variant="outline-secondary"
              size="sm"
              className="py-0"
              style={{ fontSize: '0.75rem' }}
              onClick={r.openEdit}
            >
              <i className="bi bi-pencil me-1" />Edit
            </Button>
            {/* Removal for a confirmed role — AI suggestions already have their own Discard. */}
            {r.role?.confirmedByHuman && (
              <Button
                variant="outline-danger"
                size="sm"
                className="py-0"
                style={{ fontSize: '0.75rem' }}
                onClick={r.discard}
                disabled={r.roleSaving}
                title="Delete this role label and description"
              >
                <i className="bi bi-trash me-1" />Remove
              </Button>
            )}
            {fileId && (
              <div className="d-flex align-items-center gap-1">
                <Button
                  variant="outline-secondary"
                  size="sm"
                  className="py-0"
                  style={{ fontSize: '0.75rem' }}
                  onClick={r.suggest}
                  disabled={r.roleSuggesting}
                >
                  {r.roleSuggesting
                    ? <><Spinner size="sm" className="me-1" />Suggesting…</>
                    : <><i className="bi bi-stars me-1" />Suggest with AI</>
                  }
                </Button>
              </div>
            )}
          </div>
        )}
      </h6>

      <Modal
        show={showRoleHelp}
        onHide={() => setShowRoleHelp(false)}
        centered
        className={raisedModal ? 'tp-nested-modal' : undefined}
        backdropClassName={raisedModal ? 'tp-nested-modal-backdrop' : undefined}
      >
        <Modal.Header closeButton>
          <Modal.Title style={{ fontSize: '1rem' }}>What is a role?</Modal.Title>
        </Modal.Header>
        <Modal.Body style={{ fontSize: '0.85rem' }}>
          <p className="mb-0">
            A <strong>role</strong> is a name you assign this host (e.g. <em>Finance DB</em>,{' '}
            <em>Guest Wi-Fi AP</em>, <em>Domain Controller</em>) — not a measured classification. It
            persists across captures and feeds Monitor change-detection, independent of the measured
            Identity above.
          </p>
        </Modal.Body>
      </Modal>

      {r.roleInfoOpen && (
        <Alert variant="info" className="p-2 mb-2 small">
          <strong>How it works:</strong> The AI analyses traffic signals for this entity — manufacturer OUI, device type, TTL, observed applications and protocols — and suggests an operational role label. If the signals are too sparse or generic to make a meaningful assessment, it will decline rather than guess.
        </Alert>
      )}

      {r.roleLoading && (
        <div className="text-muted small fst-italic">Loading role…</div>
      )}

      {r.roleSuggestError && (
        <Alert variant="warning" className="d-flex align-items-start gap-2 p-2 mb-2 small">
          <i className="bi bi-exclamation-triangle-fill mt-1 flex-shrink-0" />
          <span>{r.roleSuggestError}</span>
        </Alert>
      )}

      {!r.roleLoading && !r.role && !r.roleEditing && (
        <p className="text-muted small fst-italic mb-0">
          No role assigned.
        </p>
      )}

      {!r.roleLoading && r.role && !r.roleEditing && (
        <div
          className={`p-2 rounded small ${
            r.role.confirmedByHuman && r.role.staleSince
              ? 'bg-warning-subtle border border-warning'
              : r.role.llmSuggested && !r.role.confirmedByHuman
                ? 'bg-warning-subtle border border-warning-subtle'
                : 'bg-light'
          }`}
        >
          <div className="fw-semibold">
            {r.role.roleLabel || <span className="text-muted fst-italic">No label</span>}
            {r.role.llmSuggested && !r.role.confirmedByHuman && (
              <Badge bg="warning" text="dark" className="ms-2" style={{ fontSize: '0.65rem' }}>
                <i className="bi bi-stars me-1" />AI suggested
              </Badge>
            )}
            {r.role.confirmedByHuman && (
              <Badge
                bg="secondary"
                className="ms-2"
                style={{ fontSize: '0.65rem' }}
                title={
                  r.role.confirmedBy && r.role.confirmedBy !== 'system'
                    ? `Manually labelled by ${r.role.confirmedBy}. Future deviating behaviour can still be flagged.`
                    : 'Manually labelled by an analyst. Future deviating behaviour can still be flagged.'
                }
              >
                <i className="bi bi-tag me-1" />Manual label
                {r.role.confirmedBy && r.role.confirmedBy !== 'system' && (
                  <span className="ms-1 fw-normal">· {r.role.confirmedBy}</span>
                )}
              </Badge>
            )}
            {r.role.confirmedByHuman && r.role.staleSince && (
              <Badge bg="warning" text="dark" className="ms-2" style={{ fontSize: '0.65rem' }} title={staleTooltip(r.role)}>
                <i className="bi bi-exclamation-triangle me-1" />Stale
              </Badge>
            )}
          </div>
          {r.role.roleDescription && (
            <div className="text-muted mt-1">{r.role.roleDescription}</div>
          )}
          {r.role.confirmedByHuman && r.role.staleSince && (
            <Alert variant="warning" className="d-flex flex-column gap-2 p-2 mt-2 mb-0 small">
              <div className="d-flex align-items-start gap-2">
                <i className="bi bi-exclamation-triangle-fill mt-1 flex-shrink-0" />
                <span title={staleTooltip(r.role)}>{staleTooltip(r.role)}</span>
              </div>
              <div className="d-flex flex-wrap gap-2">
                <Button
                  variant="primary"
                  size="sm"
                  className="py-0"
                  style={{ fontSize: '0.75rem' }}
                  onClick={r.openEdit}
                  disabled={r.roleSaving}
                >
                  <i className="bi bi-pencil me-1" />Update label
                </Button>
                {fileId && (
                  <Button
                    variant="outline-primary"
                    size="sm"
                    className="py-0"
                    style={{ fontSize: '0.75rem' }}
                    onClick={r.suggestUpdate}
                    disabled={r.roleSaving || r.roleSuggesting}
                    title="Ask the AI to re-classify this node from its current traffic and pre-fill the editor"
                  >
                    {r.roleSuggesting
                      ? <><Spinner size="sm" className="me-1" />Suggesting…</>
                      : <><i className="bi bi-stars me-1" />Suggest updated label</>}
                  </Button>
                )}
                <Button
                  variant="outline-secondary"
                  size="sm"
                  className="py-0"
                  style={{ fontSize: '0.75rem' }}
                  onClick={r.dismissStaleness}
                  disabled={r.roleSaving || !fileId}
                  title={!fileId ? 'Open from a file context to dismiss' : 'Mark the label as still correct and reset the baseline'}
                >
                  <i className="bi bi-check-lg me-1" />Dismiss — label is still correct
                </Button>
              </div>
            </Alert>
          )}
          {r.role.llmSuggested && !r.role.confirmedByHuman && (
            <div className="d-flex gap-2 mt-2">
              <Button
                variant="success"
                size="sm"
                className="py-0"
                style={{ fontSize: '0.75rem' }}
                onClick={r.accept}
                disabled={r.roleSaving}
              >
                <i className="bi bi-check-lg me-1" />Accept
              </Button>
              <Button
                variant="outline-secondary"
                size="sm"
                className="py-0"
                style={{ fontSize: '0.75rem' }}
                onClick={r.discard}
                disabled={r.roleSaving}
              >
                <i className="bi bi-x-lg me-1" />Discard
              </Button>
            </div>
          )}
        </div>
      )}

      {r.roleEditing && (
        <div>
          <Form.Control
            size="sm"
            className="mb-2"
            placeholder="Role label (e.g. Finance DB, Domain Controller, Guest Wi-Fi AP, SCADA Controller)"
            value={r.roleLabelDraft}
            onChange={e => r.setRoleLabelDraft(e.target.value)}
          />
          <Form.Control
            as="textarea"
            size="sm"
            className="mb-2"
            rows={2}
            placeholder="Description (optional)"
            value={r.roleDescDraft}
            onChange={e => r.setRoleDescDraft(e.target.value)}
          />
          <div className="d-flex gap-2">
            <Button
              variant="primary"
              size="sm"
              className="py-0"
              style={{ fontSize: '0.75rem' }}
              onClick={r.save}
              disabled={r.roleSaving || !r.roleLabelDraft.trim()}
            >
              {r.roleSaving
                ? <><Spinner size="sm" className="me-1" />Saving…</>
                : <><i className="bi bi-floppy me-1" />Save</>
              }
            </Button>
            <Button
              variant="outline-secondary"
              size="sm"
              className="py-0"
              style={{ fontSize: '0.75rem' }}
              onClick={() => r.setRoleEditing(false)}
              disabled={r.roleSaving}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
