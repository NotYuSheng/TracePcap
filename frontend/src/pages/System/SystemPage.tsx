import { Card, Container, Tab, Tabs } from '@govtechsg/sgds-react';
import { SystemSettingsTab } from '@components/settings/SettingsModal/SystemSettingsTab';
import { env } from '@/config/env';
import { useMe } from '@/features/me/useMe';
import { AuditLogPanel } from './AuditLogPanel';
import { PermissionsPanel } from './PermissionsPanel';

/** The Keycloak admin console's user list for this realm. Keycloak is proxied same-origin by default. */
function keycloakUsersUrl(): string {
  const authority = env.OIDC_AUTHORITY || `${window.location.origin}/realms/${env.OIDC_REALM}`;
  const base = authority.replace(/\/realms\/[^/]+\/?$/, '');
  return `${base}/admin/master/console/#/${env.OIDC_REALM}/users`;
}

/**
 * The System console (#915): everything that applies to the whole install. Everyone can open it;
 * what the caller can't change is greyed out with the reason.
 */
export function SystemPage() {
  const me = useMe();
  return (
    <Container className="py-4">
      <h2 className="mb-1">System</h2>
      <p className="text-muted">
        Settings that apply to everyone using this install, who may change them, and a record of
        every change.
        {me && (
          <>
            {' '}
            You are signed in as <strong>{me.username}</strong>
            {me.authEnabled ? (me.admin ? ' (admin).' : ' (analyst).') : ' (login is off).'}
          </>
        )}
      </p>
      <Card>
        <Card.Body>
          <Tabs defaultActiveKey="settings" id="system-tabs" className="mb-3" mountOnEnter>
            <Tab eventKey="settings" title="Settings">
              <SystemSettingsTab />
            </Tab>
            <Tab eventKey="permissions" title="Permissions">
              <PermissionsPanel />
            </Tab>
            <Tab eventKey="audit" title="Audit log">
              <AuditLogPanel />
            </Tab>
            <Tab eventKey="users" title="Users">
              {env.AUTH_ENABLED ? (
                <div className="small">
                  <p>
                    Users, passwords and the <strong>admin</strong> role are managed in Keycloak.
                    To make someone an admin, open the user, then Role mapping, Assign role, Filter
                    by clients, and pick <span className="font-monospace">{env.OIDC_CLIENT_ID}</span>{' '}
                    admin.
                  </p>
                  <a href={keycloakUsersUrl()} target="_blank" rel="noreferrer" className="btn btn-outline-primary btn-sm">
                    <i className="bi bi-box-arrow-up-right me-1" aria-hidden="true" />
                    Open users in Keycloak
                  </a>
                </div>
              ) : (
                <p className="small text-muted mb-0">
                  Login is off, so there are no user accounts: everyone shares one profile and acts
                  as <span className="font-monospace">system</span>. Turning login on is described
                  in the Authentication section of the docs.
                </p>
              )}
            </Tab>
          </Tabs>
        </Card.Body>
      </Card>
    </Container>
  );
}
