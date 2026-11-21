import { useEffect, useState } from 'react';
import { Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Pagination } from '@components/common/Pagination/Pagination';
import { Spinner } from '@components/common/Spinner/Spinner';
import { env } from '@/config/env';
import { meService, type Paged, type Role, type SignedInUser } from '@/features/me/meService';
import { signInTime } from './signInTime';
import './PermissionsPanel.css';

const PAGE_SIZE = 25;
const SEARCH_DELAY_MS = 300;

/** The Keycloak admin console's user list for this realm. Keycloak is proxied same-origin by default. */
function keycloakUsersUrl(): string {
  const authority = env.OIDC_AUTHORITY || `${window.location.origin}/realms/${env.OIDC_REALM}`;
  const base = authority.replace(/\/realms\/[^/]+\/?$/, '');
  return `${base}/admin/master/console/#/${env.OIDC_REALM}/users`;
}

/**
 * Settings › Users: everyone who has signed in, the roles their last sign-in carried, and what
 * those add up to. Read-only: people, groups and role assignments live in Keycloak.
 */
export function UsersPanel() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<Paged<SignedInUser> | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    meService
      .getRoles()
      .then(setRoles)
      .catch(() => setRoles([]));
    meService
      .getMe()
      .then(m => setTotal(m.permissions.length))
      .catch(() => setTotal(0));
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      setQuery(search.trim());
      setPage(1);
    }, SEARCH_DELAY_MS);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => {
    let active = true;
    meService
      .getUsers(page, PAGE_SIZE, query || undefined)
      .then(r => {
        if (!active) return;
        setResult(r);
        setError(null);
      })
      .catch(err => {
        if (!active) return;
        const msg = (err as { response?: { data?: { message?: string } } })?.response?.data
          ?.message;
        setError(msg ?? "Couldn't load who has signed in.");
      });
    return () => {
      active = false;
    };
  }, [page, query]);

  const label = (key: string) => roles.find(r => r.key === key)?.label ?? key;

  return (
    <div>
      <div className="d-flex align-items-start gap-3 mb-3">
        <p className="small text-muted mb-0 flex-grow-1">
          Everyone who has signed in, and the roles their last sign-in carried. Read-only: people,
          groups and who has which role are managed in Keycloak. To give a group a role there, open
          it, then Role mapping › Assign role › Filter by clients, and pick{' '}
          <code>{env.OIDC_CLIENT_ID}</code> and the role. What each role may do is on the Roles tab.
        </p>
        <a
          href={keycloakUsersUrl()}
          target="_blank"
          rel="noreferrer"
          className="btn btn-outline-primary btn-sm text-nowrap"
        >
          <i className="bi bi-box-arrow-up-right me-1" aria-hidden="true" />
          Open Keycloak
        </a>
      </div>

      {!error && (
        <Form.Control
          type="search"
          size="sm"
          className="mb-3"
          style={{ maxWidth: 320 }}
          placeholder="Search by username or name…"
          aria-label="Search users"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      )}

      {error && (
        <Alert variant="info" className="py-2 small">
          <i className="bi bi-lock me-2" aria-hidden="true" />
          {error}
        </Alert>
      )}
      {!error && !result && (
        <div className="text-muted small py-3">
          <Spinner animation="border" size="sm" className="me-2" />
          Loading…
        </div>
      )}
      {result && result.total === 0 && (
        <p className="small text-muted mb-0">
          {query
            ? 'No one matches.'
            : 'No one has signed in yet. People appear here after their first sign-in.'}
        </p>
      )}
      {result && result.total > 0 && (
        <>
          <table className="table table-sm small align-middle mb-0">
            <thead>
              <tr>
                <th scope="col">User</th>
                <th scope="col">Roles from Keycloak</th>
                <th scope="col">So they may</th>
                <th scope="col">Last sign-in</th>
              </tr>
            </thead>
            <tbody>
              {result.data.map(u => (
                <tr key={u.username}>
                  <td>
                    <div className="fw-semibold">{u.username}</div>
                    {u.displayName && <div className="text-muted">{u.displayName}</div>}
                  </td>
                  <td>
                    <div className="d-flex flex-wrap gap-1 align-items-center">
                      {u.roles.map(r => (
                        <span key={r} className="roles-tag">
                          {label(r)}
                        </span>
                      ))}
                      {u.defaultRole && (
                        <span className="text-muted">(the default: no role in Keycloak)</span>
                      )}
                    </div>
                    {u.unknownRoles.length > 0 && (
                      <div className="text-warning-emphasis mt-1" data-testid="unknown-roles">
                        <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />
                        Also carries {u.unknownRoles.map(r => `“${r}”`).join(', ')}, which TracePcap
                        has no role for, so {u.unknownRoles.length === 1 ? 'it gives' : 'they give'}{' '}
                        nothing.
                      </div>
                    )}
                  </td>
                  <td className="text-muted text-nowrap">
                    {u.permissionCount}
                    {total > 0 && ` of ${total}`} permissions
                  </td>
                  <td className="text-muted text-nowrap">{signInTime(u.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {result.totalPages > 1 && (
            <Pagination
              currentPage={page}
              totalPages={result.totalPages}
              totalItems={result.total}
              pageSize={PAGE_SIZE}
              onPageChange={setPage}
              showPageSizeSelector={false}
            />
          )}
        </>
      )}
    </div>
  );
}
