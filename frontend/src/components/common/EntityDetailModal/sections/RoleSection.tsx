import { Badge, Button, Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { staleTooltip } from '@/features/insights/utils/nodeRoleStaleness';
import type { useEntityRole } from '../hooks/useEntityRole';

interface RoleSectionProps {
  fileId: string;
  role: ReturnType<typeof useEntityRole>;
}

/** Role panel for IP/DEVICE entities — view, AI-suggest, accept/discard, manual edit. */
export function RoleSection({ fileId, role: r }: RoleSectionProps) {
  return (
    <div className="mb-4">
      <h6 className="border-bottom pb-1 mb-2 d-flex align-items-center justify-content-between">
        <span>Role</span>
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
                <Button
                  variant="link"
                  size="sm"
                  className="p-0 text-muted"
                  style={{ fontSize: '0.8rem', lineHeight: 1 }}
                  onClick={() => r.setRoleInfoOpen(o => !o)}
                  title="How does this work?"
                >
                  <i className="bi bi-info-circle" />
                </Button>
              </div>
            )}
          </div>
        )}
      </h6>

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
              <Badge bg="secondary" className="ms-2" style={{ fontSize: '0.65rem' }} title="Manually labelled by an analyst. Future deviating behaviour can still be flagged.">
                <i className="bi bi-tag me-1" />Manual label
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
              <div className="d-flex gap-2">
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
            placeholder="Role label (e.g. SCADA Controller)"
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
