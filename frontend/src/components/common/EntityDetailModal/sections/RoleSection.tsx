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
            <button
              className="btn btn-outline-secondary btn-sm py-0"
              style={{ fontSize: '0.75rem' }}
              onClick={r.openEdit}
            >
              <i className="bi bi-pencil me-1" />Edit
            </button>
            {fileId && (
              <div className="d-flex align-items-center gap-1">
                <button
                  className="btn btn-outline-secondary btn-sm py-0"
                  style={{ fontSize: '0.75rem' }}
                  onClick={r.suggest}
                  disabled={r.roleSuggesting}
                >
                  {r.roleSuggesting
                    ? <><span className="spinner-border spinner-border-sm me-1" role="status" />Suggesting…</>
                    : <><i className="bi bi-stars me-1" />Suggest with AI</>
                  }
                </button>
                <button
                  className="btn btn-link btn-sm p-0 text-muted"
                  style={{ fontSize: '0.8rem', lineHeight: 1 }}
                  onClick={() => r.setRoleInfoOpen(o => !o)}
                  title="How does this work?"
                >
                  <i className="bi bi-info-circle" />
                </button>
              </div>
            )}
          </div>
        )}
      </h6>

      {r.roleInfoOpen && (
        <div className="p-2 rounded mb-2 small text-muted" style={{ background: 'var(--tp-bg-subtle, #f8f9fa)', border: '1px solid var(--bs-border-color)' }}>
          <strong>How it works:</strong> The AI analyses traffic signals for this entity — manufacturer OUI, device type, TTL, observed applications and protocols — and suggests an operational role label. If the signals are too sparse or generic to make a meaningful assessment, it will decline rather than guess.
        </div>
      )}

      {r.roleLoading && (
        <div className="text-muted small fst-italic">Loading role…</div>
      )}

      {r.roleSuggestError && (
        <div className="d-flex align-items-start gap-2 p-2 rounded mb-2 small" style={{ background: 'var(--bs-warning-bg-subtle, #fff3cd)', color: 'var(--bs-warning-text-emphasis, #664d03)', border: '1px solid var(--bs-warning-border-subtle, #ffc107)' }}>
          <i className="bi bi-exclamation-triangle-fill mt-1 flex-shrink-0" />
          <span>{r.roleSuggestError}</span>
        </div>
      )}

      {!r.roleLoading && !r.role && !r.roleEditing && (
        <p className="text-muted small fst-italic mb-0">
          No role assigned.
        </p>
      )}

      {!r.roleLoading && r.role && !r.roleEditing && (
        <div
          className={`p-2 rounded small ${r.role.llmSuggested && !r.role.confirmedByHuman ? 'bg-warning-subtle border border-warning-subtle' : 'bg-light'}`}
        >
          <div className="fw-semibold">
            {r.role.roleLabel || <span className="text-muted fst-italic">No label</span>}
            {r.role.llmSuggested && !r.role.confirmedByHuman && (
              <span className="badge bg-warning text-dark ms-2" style={{ fontSize: '0.65rem' }}>
                <i className="bi bi-stars me-1" />AI suggested
              </span>
            )}
            {r.role.confirmedByHuman && (
              <span className="badge bg-secondary ms-2" style={{ fontSize: '0.65rem' }} title="Manually labelled by an analyst. Future deviating behaviour can still be flagged.">
                <i className="bi bi-tag me-1" />Manual label
              </span>
            )}
          </div>
          {r.role.roleDescription && (
            <div className="text-muted mt-1">{r.role.roleDescription}</div>
          )}
          {r.role.llmSuggested && !r.role.confirmedByHuman && (
            <div className="d-flex gap-2 mt-2">
              <button
                className="btn btn-success btn-sm py-0"
                style={{ fontSize: '0.75rem' }}
                onClick={r.accept}
                disabled={r.roleSaving}
              >
                <i className="bi bi-check-lg me-1" />Accept
              </button>
              <button
                className="btn btn-outline-secondary btn-sm py-0"
                style={{ fontSize: '0.75rem' }}
                onClick={r.discard}
                disabled={r.roleSaving}
              >
                <i className="bi bi-x-lg me-1" />Discard
              </button>
            </div>
          )}
        </div>
      )}

      {r.roleEditing && (
        <div>
          <input
            className="form-control form-control-sm mb-2"
            placeholder="Role label (e.g. SCADA Controller)"
            value={r.roleLabelDraft}
            onChange={e => r.setRoleLabelDraft(e.target.value)}
          />
          <textarea
            className="form-control form-control-sm mb-2"
            rows={2}
            placeholder="Description (optional)"
            value={r.roleDescDraft}
            onChange={e => r.setRoleDescDraft(e.target.value)}
          />
          <div className="d-flex gap-2">
            <button
              className="btn btn-primary btn-sm py-0"
              style={{ fontSize: '0.75rem' }}
              onClick={r.save}
              disabled={r.roleSaving || !r.roleLabelDraft.trim()}
            >
              {r.roleSaving
                ? <><span className="spinner-border spinner-border-sm me-1" role="status" />Saving…</>
                : <><i className="bi bi-floppy me-1" />Save</>
              }
            </button>
            <button
              className="btn btn-outline-secondary btn-sm py-0"
              style={{ fontSize: '0.75rem' }}
              onClick={() => r.setRoleEditing(false)}
              disabled={r.roleSaving}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
