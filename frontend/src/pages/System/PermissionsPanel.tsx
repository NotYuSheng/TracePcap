import { useEffect, useState } from 'react';
import { Button, Card, Dropdown, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { env } from '@/config/env';
import {
  meService,
  type Me,
  type Permission,
  type PermissionAction,
  type Role,
  type RoleChange,
} from '@/features/me/meService';
import { RoleFormModal, type RoleFormValues } from './RoleFormModal';
import './PermissionsPanel.css';

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
 * Settings › Roles: the roles down the left, and what the selected one may do on the right.
 * Everyone can see it; only the admin role can change it. Who has a role isn't set here: it's the
 * Keycloak client role of the same key, assigned in Keycloak to groups or people.
 */
export function PermissionsPanel() {
  const [me, setMe] = useState<Me | null>(null);
  const [roles, setRoles] = useState<Role[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [form, setForm] = useState<'new' | 'edit' | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const load = () =>
    Promise.all([meService.getMe(), meService.getRoles()])
      .then(([m, r]) => {
        setMe(m);
        setRoles(r);
        // Open on one of the caller's own roles, so "what may I do" is the first answer.
        setSelected(cur => cur ?? (r.find(x => m.roles.includes(x.key)) ?? r[0])?.key ?? null);
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

  const total = me.permissions.length;
  const canManage = me.canManagePermissions;
  const manageReason = me.authEnabled
    ? 'Only the admin role can change what roles may do. Ask an admin, or for the admin role in Keycloak.'
    : 'Only admins can change what roles may do. With login off that needs SYSTEM_SETTINGS_EDITABLE=true on the server.';
  const mine = roles.filter(r => me.roles.includes(r.key)).map(r => r.label);
  const defaultRole = roles.find(r => r.defaultRole);
  const role = roles.find(r => r.key === selected) ?? roles[0];

  const save = async (key: string, change: RoleChange) => {
    setSaving(true);
    setError(null);
    try {
      await meService.updateRole(key, change);
      await load();
    } catch (err) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      setError(msg ?? "Couldn't save the change. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  const toggle = (r: Role, action: PermissionAction, on: boolean) =>
    save(r.key, {
      permissions: on ? [...r.permissions, action] : r.permissions.filter(a => a !== action),
    });

  /** Replaces the role's permissions with another role's (the admin role's: everything it can hold). */
  const startFrom = (source: Role) =>
    save(role.key, {
      permissions: source.editable
        ? source.permissions
        : source.permissions.filter(a => !me.permissions.find(p => p.action === a)?.fixed),
    });

  const submitForm = async (v: RoleFormValues) => {
    if (form === 'edit') {
      await meService.updateRole(role.key, { label: v.label, description: v.description });
    } else {
      await meService.createRole({
        key: v.key,
        label: v.label,
        description: v.description || undefined,
        copyFrom: v.copyFrom || undefined,
      });
      setSelected(v.key);
    }
    await load();
  };

  const remove = async () => {
    setDeleting(true);
    setError(null);
    try {
      await meService.deleteRole(role.key);
      setConfirmDelete(false);
      setSelected(null);
      await load();
    } catch (err) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      setConfirmDelete(false);
      setError(msg ?? "Couldn't delete the role. Please try again.");
    } finally {
      setDeleting(false);
    }
  };

  const copyKey = async () => {
    try {
      await navigator.clipboard.writeText(role.key);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked: the name is on screen to copy by hand */
    }
  };

  return (
    <div className="roles-layout">
      <Card className="roles-list-card">
        <Card.Body>
          {canManage && (
            <Button
              type="button"
              size="sm"
              variant="outline-primary"
              className="w-100 mb-3"
              onClick={() => setForm('new')}
            >
              <i className="bi bi-plus-lg me-1" aria-hidden="true" />
              New role
            </Button>
          )}
          <p className="small text-muted mb-2">
            What each role may do.{' '}
            {me.authEnabled
              ? 'Who has a role is set in Keycloak.'
              : 'Login is off, so there are no accounts: everyone has every role but admin.'}
          </p>
          <div className="roles-list" role="listbox" aria-label="Roles">
            {roles.map(r => {
              const active = r.key === role.key;
              return (
                <button
                  key={r.key}
                  type="button"
                  role="option"
                  aria-selected={active}
                  className={`roles-list-item${active ? ' active' : ''}`}
                  onClick={() => setSelected(r.key)}
                >
                  <span className="roles-list-name">
                    <span className="fw-semibold">
                      {r.label}
                      {!r.editable && (
                        <i className="bi bi-lock-fill ms-1 small" aria-label="can't be changed" />
                      )}
                    </span>
                    {r.description && <span className="roles-list-desc">{r.description}</span>}
                  </span>
                  {r.defaultRole && me.authEnabled && (
                    <span className="roles-tag roles-tag-default">default</span>
                  )}
                  <span
                    className="roles-list-count"
                    aria-label={`${r.permissions.length} of ${total} permissions`}
                  >
                    {r.permissions.length}
                  </span>
                </button>
              );
            })}
          </div>
          {me.authEnabled && (
            <div className="roles-default">
              <label htmlFor="default-role" className="mb-1">
                Someone whose sign-in carries none of these roles is a
              </label>
              <Form.Select
                id="default-role"
                size="sm"
                value={defaultRole?.key ?? ''}
                disabled={!canManage || saving}
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
          <p className="small text-muted mt-3 mb-0" data-testid="my-roles">
            You: <strong className="text-body">{mine.length ? mine.join(', ') : 'no role'}</strong>
          </p>
        </Card.Body>
      </Card>

      <Card className="roles-detail-card">
        <Card.Body>
          <div className="d-flex align-items-center flex-wrap gap-2">
            <h3 className="h5 mb-0">{role.label}</h3>
            <span className="roles-tag">{role.builtIn ? 'built-in' : 'custom'}</span>
            <span className="small text-muted">
              {role.editable
                ? `${role.permissions.length} of ${total} permissions`
                : `all ${total} permissions, always`}
            </span>
            <span className="ms-auto d-flex align-items-center gap-2">
              {saving && <Spinner animation="border" size="sm" />}
              {canManage && role.editable && (
                <Dropdown align="end">
                  <Dropdown.Toggle
                    variant="outline-secondary"
                    size="sm"
                    id="role-start-from"
                    disabled={saving}
                  >
                    Start from…
                  </Dropdown.Toggle>
                  <Dropdown.Menu>
                    <Dropdown.Header>Replace these permissions with</Dropdown.Header>
                    {roles
                      .filter(r => r.key !== role.key)
                      .map(r => (
                        <Dropdown.Item key={r.key} onClick={() => startFrom(r)}>
                          {r.label}'s ({r.editable ? r.permissions.length : total - 1})
                        </Dropdown.Item>
                      ))}
                  </Dropdown.Menu>
                </Dropdown>
              )}
              {canManage && !role.builtIn && (
                <>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline-secondary"
                    onClick={() => setForm('edit')}
                  >
                    <i className="bi bi-pencil me-1" aria-hidden="true" />
                    Edit
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline-danger"
                    onClick={() => setConfirmDelete(true)}
                  >
                    <i className="bi bi-trash me-1" aria-hidden="true" />
                    Delete role
                  </Button>
                </>
              )}
            </span>
          </div>
          {role.description && <p className="small text-muted mt-1 mb-0">{role.description}</p>}

          {me.authEnabled && (
            <div className="roles-keycloak">
              <div>
                <strong>Given by the Keycloak client role</strong>{' '}
                <code className="roles-chip">{role.key}</code> on <code>{env.OIDC_CLIENT_ID}</code>
              </div>
              <div className="text-muted mt-1">
                TracePcap doesn't create it or give it to anyone. In Keycloak:{' '}
                {!role.builtIn && (
                  <>
                    <strong>Clients › {env.OIDC_CLIENT_ID} › Roles › Create role</strong> with this
                    name, then{' '}
                  </>
                )}
                assign it to a group (Groups › the group › Role mapping › Assign role › Filter by
                clients).
              </div>
              <button
                type="button"
                className="btn btn-outline-secondary btn-sm mt-2"
                onClick={copyKey}
              >
                <i
                  className={`bi ${copied ? 'bi-check2' : 'bi-clipboard'} me-1`}
                  aria-hidden="true"
                />
                {copied ? 'Copied' : 'Copy role name'}
              </button>
            </div>
          )}

          {!canManage && (
            <Alert variant="info" className="py-2 mt-3 mb-0 small" data-testid="permissions-locked">
              <i className="bi bi-lock me-2" aria-hidden="true" />
              {manageReason}
            </Alert>
          )}
          {canManage && !role.editable && (
            <Alert variant="info" className="py-2 mt-3 mb-0 small">
              <i className="bi bi-lock me-2" aria-hidden="true" />
              The admin role always has every permission, so no one can lock the admins out.
            </Alert>
          )}
          {error && (
            <Alert variant="danger" className="py-2 mt-3 mb-0">
              {error}
            </Alert>
          )}

          <div className="roles-perms">
            {grouped(me.permissions).map(g => (
              <section key={g.label} className="roles-perm-group">
                <h4 className="roles-perm-heading">{g.label}</h4>
                {g.items.map(p => {
                  const id = `perm-${role.key}-${p.action}`;
                  return (
                    <div key={p.action} className="roles-perm">
                      <Form.Check
                        type="checkbox"
                        id={id}
                        checked={role.permissions.includes(p.action)}
                        disabled={!canManage || !role.editable || p.fixed || saving}
                        aria-label={`${role.label}: ${p.label}`}
                        onChange={e => toggle(role, p.action, e.target.checked)}
                      />
                      <label htmlFor={id} className="roles-perm-text">
                        <span>{p.label}</span>
                        <span className="small text-muted d-block">{p.description}</span>
                      </label>
                    </div>
                  );
                })}
              </section>
            ))}
          </div>
        </Card.Body>
      </Card>

      <RoleFormModal
        show={form !== null}
        editing={form === 'edit' ? role : undefined}
        roles={roles}
        onHide={() => setForm(null)}
        onSubmit={submitForm}
      />
      <Modal show={confirmDelete} onHide={() => !deleting && setConfirmDelete(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Delete {role.label}?</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="mb-2">
            Anyone Keycloak gives <code>{role.key}</code> stops getting anything from it at their
            next request. If that leaves them with no TracePcap role, they get the default role (
            {defaultRole?.label ?? 'none'}).
          </p>
          <p className="small text-muted mb-0">
            The client role stays in Keycloak; remove it there too if no other app uses it. The
            deletion is recorded in the audit log.
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button
            type="button"
            variant="outline-secondary"
            onClick={() => setConfirmDelete(false)}
            disabled={deleting}
          >
            Cancel
          </Button>
          <Button type="button" variant="outline-danger" onClick={remove} disabled={deleting}>
            {deleting && <Spinner animation="border" size="sm" className="me-1" />}
            Delete role
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}
