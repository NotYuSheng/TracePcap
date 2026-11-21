import { useSearchParams } from 'react-router-dom';
import { Card } from '@govtechsg/sgds-react';
import { AnalysisRail, type RailItem } from '@pages/Analysis/AnalysisRail';
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
  { key: 'personal', title: 'Personal', short: 'Personal', icon: 'bi-person', group: 'You' },
  { key: 'system', title: 'System', short: 'System', icon: 'bi-sliders', group: 'This install' },
  { key: 'rules', title: 'Detection rules', short: 'Rules', icon: 'bi-shield-check' },
  { key: 'addresses', title: 'Address defaults', short: 'Addresses', icon: 'bi-signpost-split' },
  { key: 'permissions', title: 'Permissions', short: 'Permissions', icon: 'bi-key' },
  { key: 'audit', title: 'Audit log', short: 'Audit', icon: 'bi-clock-history' },
  { key: 'users', title: 'Users', short: 'Users', icon: 'bi-people' },
] as const;
type TabKey = (typeof TABS)[number]['key'];

const RAIL_ITEMS: RailItem[] = TABS.map(t => ({
  key: t.key,
  label: t.title,
  short: t.short,
  icon: t.icon,
  group: 'group' in t ? t.group : undefined,
}));

export function SystemPage() {
  const me = useMe();
  // The sections down the left, like a capture's analysis. The section is in the URL
  // (?tab=rules), so other pages can link straight to it.
  const [params, setParams] = useSearchParams();
  const requested = params.get('tab');
  // `?tab=settings` was the System tab before the two pages became one.
  const asked = requested === 'settings' ? 'system' : requested;
  const tab: TabKey = TABS.some(t => t.key === asked) ? (asked as TabKey) : 'personal';
  const setTab = (key: TabKey) =>
    setParams(key === 'personal' ? {} : { tab: key }, { replace: true });
  const current = TABS.find(t => t.key === tab)!;
  return (
    <div className="analysis-shell">
      <AnalysisRail
        items={RAIL_ITEMS}
        active={tab}
        onSelect={key => setTab(key as TabKey)}
        label="Settings sections"
        storageKey="tracepcap.settingsRail.expanded"
      />
      <div className="analysis-main">
        {/* The page bar: where you are, and who you're signed in as. */}
        <header className="analysis-capture-bar">
          <div className="analysis-capture-id">
            <h1 className="analysis-capture-name">Settings</h1>
            <div className="analysis-capture-facts">
              Yours, and everyone's on this install. A network's own settings are on its page.
              {me && (
                <>
                  {' '}
                  Signed in as <strong>{me.username}</strong>
                  {me.authEnabled ? (me.admin ? ' (admin).' : ' (analyst).') : ' (login is off).'}
                </>
              )}
            </div>
          </div>
        </header>
        <div className="analysis-body">
          <Card>
            <Card.Header>
              <h2 className="h6 mb-0" id={`system-tab-${tab}`}>
                {current.title}
              </h2>
            </Card.Header>
            <Card.Body id={`system-panel-${tab}`} aria-labelledby={`system-tab-${tab}`}>
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
                      Users, groups and who has which role are managed in Keycloak. To give a
                      group (or one person) a role, open it, then Role mapping, Assign role,
                      Filter by clients, and pick{' '}
                      <span className="font-monospace">{env.OIDC_CLIENT_ID}</span> and the role:
                      viewer, analyst, lead or admin. What each role may do is on the Permissions
                      tab.
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
                    Login is off, so there are no user accounts: everyone shares one profile and
                    acts as <span className="font-monospace">system</span>. Turning login on is
                    described in the Authentication section of the docs.
                  </p>
                ))}
            </Card.Body>
          </Card>
        </div>
      </div>
    </div>
  );
}
