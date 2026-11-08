import { useEffect, useState } from 'react';
import { Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { meService, type Me, type PermissionLevel } from '@/features/me/meService';

const LEVEL_LABEL: Record<PermissionLevel, string> = { ANALYST: 'Analysts', ADMIN: 'Admins only' };

/**
 * Who may change each setting or rule set (#915). Everyone can see it. Only admins can change it;
 * for everyone else each row is greyed out, and clicking it says why.
 */
export function PermissionsPanel() {
  const [me, setMe] = useState<Me | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const load = () =>
    meService
      .getMe()
      .then(setMe)
      .catch(() => setLoadError(true));

  useEffect(() => {
    load();
  }, []);

  if (loadError) return <p className="text-danger small">Couldn't load the permissions.</p>;
  if (!me) {
    return (
      <div className="text-muted small py-3">
        <Spinner animation="border" size="sm" className="me-2" />
        Loading…
      </div>
    );
  }

  const manageReason = me.authEnabled
    ? 'Only admins can change who may do what. Ask an admin, or for the admin role in Keycloak.'
    : 'Only admins can change who may do what. With login off that needs SYSTEM_SETTINGS_EDITABLE=true on the server.';

  const change = async (action: string, level: PermissionLevel) => {
    setSaving(action);
    setError(null);
    try {
      await meService.setPermissionLevel(action as never, level);
      await load();
    } catch (err) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      setError(msg ?? "Couldn't save the change. Please try again.");
    } finally {
      setSaving(null);
    }
  };

  return (
    <div>
      <p className="small text-muted">
        Choose whether analysts or only admins may change each item. Every change to these items,
        and to this table, is recorded in the audit log.{' '}
        {me.authEnabled
          ? 'Admins are users with the Keycloak client role admin.'
          : 'Login is off, so everyone is an analyst.'}
      </p>
      {!me.canManagePermissions && (
        <Alert variant="info" className="py-2" data-testid="permissions-locked">
          <i className="bi bi-lock me-2" aria-hidden="true" />
          {manageReason}
        </Alert>
      )}
      {error && (
        <Alert variant="danger" className="py-2">
          {error}
        </Alert>
      )}
      <ul className="list-unstyled mb-0">
        {me.permissions.map(p => {
          const selectId = `perm-level-${p.action}`;
          const detailId = `perm-detail-${p.action}`;
          const expanded = open === p.action;
          return (
            <li key={p.action} className="border-bottom py-2">
              <div className="d-flex align-items-center justify-content-between gap-3">
                <button
                  type="button"
                  className="btn btn-link text-start text-decoration-none p-0"
                  style={{ color: 'inherit', opacity: me.canManagePermissions ? 1 : 0.7 }}
                  aria-expanded={expanded}
                  aria-controls={detailId}
                  onClick={() => setOpen(expanded ? null : p.action)}
                >
                  {!me.canManagePermissions && (
                    <i className="bi bi-lock me-1 text-muted" aria-hidden="true" />
                  )}
                  {p.label}
                  {p.level !== p.defaultLevel && (
                    <span className="badge bg-secondary-subtle text-secondary-emphasis ms-2">
                      changed
                    </span>
                  )}
                </button>
                <Form.Select
                  id={selectId}
                  size="sm"
                  style={{ width: 'auto' }}
                  aria-label={`Who may: ${p.label}`}
                  value={p.level}
                  disabled={!me.canManagePermissions || saving !== null}
                  onChange={e => change(p.action, e.target.value as PermissionLevel)}
                >
                  <option value="ANALYST">{LEVEL_LABEL.ANALYST}</option>
                  <option value="ADMIN">{LEVEL_LABEL.ADMIN}</option>
                </Form.Select>
              </div>
              {expanded && (
                <div id={detailId} className="small ps-3 pt-1">
                  <p className="text-muted mb-1">{p.description}</p>
                  <p className="mb-1">
                    Default: {LEVEL_LABEL[p.defaultLevel]}. You{' '}
                    {p.allowed ? 'can' : <strong>can't</strong>} change this item
                    {p.allowed ? '.' : `: ${p.reason ?? 'only admins can change it.'}`}
                  </p>
                  {!me.canManagePermissions && (
                    <p className="mb-0">
                      <strong>Why the level is greyed out:</strong> {manageReason}
                    </p>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
