import { Fragment, useEffect, useState } from 'react';
import { Form, Table } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { meService, type Me, type Permission, type PermissionAction, type Role } from '@/features/me/meService';

/** The catalogue's rows, grouped under their headings, in the server's order. */
function grouped(permissions: Permission[]): { label: string; items: Permission[] }[] {
  const out: { label: string; items: Permission[] }[] = [];
  for (const p of permissions) {
    const last = out[out.length - 1];
    if (last && last.label === p.groupLabel) last.items.push(p);
    else out.push({ label: p.groupLabel, items: [p] });
  }
  return out;
}

/**
 * What each role may do: the permission catalogue against the roles. Everyone can see it; only the
 * admin role can change it. Who has a role isn't set here: it's the Keycloak client role of the
 * same key, assigned in Keycloak to groups or people.
 */
export function PermissionsPanel() {
  const [me, setMe] = useState<Me | null>(null);
  const [roles, setRoles] = useState<Role[] | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () =>
    Promise.all([meService.getMe(), meService.getRoles()])
      .then(([m, r]) => {
        setMe(m);
        setRoles(r);
      })
      .catch(() => setLoadError(true));

  useEffect(() => {
    load();
  }, []);

  if (loadError) return <p className="text-danger small">Couldn't load the roles.</p>;
  if (!me || !roles) {
    return (
      <div className="text-muted small py-3">
        <Spinner animation="border" size="sm" className="me-2" />
        Loading…
      </div>
    );
  }

  const canManage = me.canManagePermissions;
  const manageReason = me.authEnabled
    ? 'Only the admin role can change what roles may do. Ask an admin, or for the admin role in Keycloak.'
    : 'Only admins can change what roles may do. With login off that needs SYSTEM_SETTINGS_EDITABLE=true on the server.';
  const mine = roles.filter(r => me.roles.includes(r.key)).map(r => r.label);
  const defaultRole = roles.find(r => r.defaultRole);

  const save = async (key: string, change: { permissions?: PermissionAction[]; defaultRole?: boolean }) => {
    setSaving(key);
    setError(null);
    try {
      await meService.updateRole(key, change);
      await load();
    } catch (err) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      setError(msg ?? "Couldn't save the change. Please try again.");
    } finally {
      setSaving(null);
    }
  };

  const toggle = (role: Role, action: PermissionAction, on: boolean) =>
    save(role.key, {
      permissions: on ? [...role.permissions, action] : role.permissions.filter(a => a !== action),
    });

  return (
    <div>
      <p className="small text-muted">
        What each role may do. Someone with several roles may do everything any of them allows.
        {me.authEnabled ? (
          <>
            {' '}
            Who has a role is set in Keycloak: each role is the client role of the same name on{' '}
            <code>tracepcap-frontend</code>, assigned there to groups or people.
          </>
        ) : (
          ' Login is off, so there are no accounts: everyone has every role but admin.'
        )}{' '}
        Every change is recorded in the audit log.
      </p>
      <p className="small mb-2" data-testid="my-roles">
        You: <strong>{mine.length ? mine.join(', ') : 'no role'}</strong>
      </p>
      {!canManage && (
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
      {me.authEnabled && (
        <div className="d-flex align-items-center gap-2 small mb-3">
          <label htmlFor="default-role" className="mb-0">
            Someone whose sign-in carries none of these roles is a
          </label>
          <Form.Select
            id="default-role"
            size="sm"
            style={{ width: 'auto' }}
            value={defaultRole?.key ?? ''}
            disabled={!canManage || saving !== null}
            onChange={e => save(e.target.value, { defaultRole: true })}
          >
            {roles
              .filter(r => r.editable)
              .map(r => (
                <option key={r.key} value={r.key}>
                  {r.label}
                </option>
              ))}
          </Form.Select>
        </div>
      )}
      <Table size="sm" responsive className="mb-0 permissions-matrix">
        <thead>
          <tr>
            <th scope="col">Permission</th>
            {roles.map(r => (
              <th key={r.key} scope="col" className="text-center" style={{ width: 96 }}>
                <div>{r.label}</div>
                <code className="small fw-normal">{r.key}</code>
                {!r.editable && <div className="small fw-normal text-muted">always everything</div>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {grouped(me.permissions).map(g => (
            <Fragment key={g.label}>
              <tr>
                <th scope="rowgroup" colSpan={roles.length + 1} className="small text-uppercase text-muted pt-3">
                  {g.label}
                </th>
              </tr>
              {g.items.map(p => (
                <tr key={p.action}>
                  <th scope="row" className="fw-normal">
                    <div>{p.label}</div>
                    <div className="small text-muted">{p.description}</div>
                  </th>
                  {roles.map(r => {
                    const has = r.permissions.includes(p.action);
                    const locked = !canManage || !r.editable || p.fixed || saving !== null;
                    return (
                      <td key={r.key} className="text-center align-middle">
                        <Form.Check
                          type="checkbox"
                          className="d-inline-block"
                          checked={has}
                          disabled={locked}
                          aria-label={`${r.label}: ${p.label}`}
                          onChange={e => toggle(r, p.action, e.target.checked)}
                        />
                      </td>
                    );
                  })}
                </tr>
              ))}
            </Fragment>
          ))}
        </tbody>
      </Table>
    </div>
  );
}
