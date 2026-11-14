import { useSearchParams } from 'react-router-dom';
import { Card, Container } from '@govtechsg/sgds-react';
import { SystemSettingsTab } from '@components/settings/SettingsModal/SystemSettingsTab';
import { PersonalSettingsTab } from '@components/settings/SettingsModal/PersonalSettingsTab';
import { env } from '@/config/env';
import { useMe } from '@/features/me/useMe';
import { AddressDefaultsPanel } from './AddressDefaultsPanel';
import { AuditLogPanel } from './AuditLogPanel';
import { DetectionRulesPanel } from './DetectionRulesPanel';
import { PermissionsPanel } from './PermissionsPanel';

/** The Keycloak admin console's user list for this realm. Keycloak is proxied same-origin by default. */
function keycloakUsersUrl(): string {
  const authority = env.OIDC_AUTHORITY || `${window.location.origin}/realms/${env.OIDC_REALM}`;
  const base = authority.replace(/\/realms\/[^/]+\/?$/, '');
  return `${base}/admin/master/console/#/${env.OIDC_REALM}/users`;
}

/**
 * The Settings page: your own settings, and (#915) everything that applies to the whole install.
 * Everyone can open it; what the caller can't change is greyed out with the reason. Per-network
 * settings stay on each network's page.
 */
const TABS = [
  { key: 'personal', title: 'Personal' },
  { key: 'system', title: 'System' },
  { key: 'rules', title: 'Detection rules' },
  { key: 'addresses', title: 'Address defaults' },
  { key: 'permissions', title: 'Permissions' },
  { key: 'audit', title: 'Audit log' },
  { key: 'users', title: 'Users' },
] as const;
type TabKey = (typeof TABS)[number]['key'];

export function SystemPage() {
  const me = useMe();
  // Plain Bootstrap nav-tabs in the card header, as elsewhere in the app: the SGDS Tabs nav
  // doesn't render visibly in this theme.
  // The tab is in the URL (?tab=rules), so other pages can link straight to it.
  const [params, setParams] = useSearchParams();
  const requested = params.get('tab');
  // `?tab=settings` was the System tab before the two pages became one.
  const asked = requested === 'settings' ? 'system' : requested;
  const tab: TabKey = TABS.some(t => t.key === asked) ? (asked as TabKey) : 'personal';
  const setTab = (key: TabKey) =>
    setParams(key === 'personal' ? {} : { tab: key }, { replace: true });
  return (
    <Container className="py-4">
      <h2 className="mb-1">Settings</h2>
      <p className="text-muted">
        Your own settings, the settings for everyone using this install, custom detection rules,
        address defaults (subnet labels, internal ranges, organisations), who may change them, and a
        record of every change. A network's own settings are on its page.
        {me && (
          <>
            {' '}
            You are signed in as <strong>{me.username}</strong>
            {me.authEnabled ? (me.admin ? ' (admin).' : ' (analyst).') : ' (login is off).'}
          </>
        )}
      </p>
      <Card>
        <div className="card-header">
          <ul className="nav nav-tabs card-header-tabs" role="tablist">
            {TABS.map(t => (
              <li className="nav-item" key={t.key} role="presentation">
                <button
                  type="button"
                  role="tab"
                  id={`system-tab-${t.key}`}
                  aria-selected={tab === t.key}
                  aria-controls={`system-panel-${t.key}`}
                  className={`nav-link${tab === t.key ? ' active' : ''}`}
                  onClick={() => setTab(t.key)}
                >
                  {t.title}
                </button>
              </li>
            ))}
          </ul>
        </div>
        <Card.Body role="tabpanel" id={`system-panel-${tab}`} aria-labelledby={`system-tab-${tab}`}>
          {tab === 'personal' && <PersonalSettingsTab />}
          {tab === 'system' && <SystemSettingsTab />}
          {tab === 'rules' && <DetectionRulesPanel />}
          {tab === 'addresses' && <AddressDefaultsPanel />}
          {tab === 'permissions' && <PermissionsPanel />}
          {tab === 'audit' && <AuditLogPanel />}
          {tab === 'users' &&
            (env.AUTH_ENABLED ? (
              <div className="small">
                <p>
                  Users, passwords and the <strong>admin</strong> role are managed in Keycloak. To
                  make someone an admin, open the user, then Role mapping, Assign role, Filter by
                  clients, and pick <span className="font-monospace">{env.OIDC_CLIENT_ID}</span>{' '}
                  admin.
                </p>
                <a
                  href={keycloakUsersUrl()}
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-outline-primary btn-sm"
                >
                  <i className="bi bi-box-arrow-up-right me-1" aria-hidden="true" />
                  Open users in Keycloak
                </a>
              </div>
            ) : (
              <p className="small text-muted mb-0">
                Login is off, so there are no user accounts: everyone shares one profile and acts as{' '}
                <span className="font-monospace">system</span>. Turning login on is described in the
                Authentication section of the docs.
              </p>
            ))}
        </Card.Body>
      </Card>
    </Container>
  );
}
