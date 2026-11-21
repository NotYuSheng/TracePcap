import type { ReactNode } from 'react';
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
import { UsersPanel } from './UsersPanel';
import './SystemPage.css';

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
  { key: 'roles', title: 'Roles', short: 'Roles', icon: 'bi-key' },
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

/** A Settings section's content, in the app's standard card (no header: the title is above it). */
function SectionCard({ bare, children }: { bare: boolean; children: ReactNode }) {
  if (bare) return <>{children}</>;
  return (
    <Card>
      <Card.Body>{children}</Card.Body>
    </Card>
  );
}

export function SystemPage() {
  const me = useMe();
  // The sections down the left, like a capture's analysis. The section is in the URL
  // (?tab=rules), so other pages can link straight to it.
  const [params, setParams] = useSearchParams();
  const requested = params.get('tab');
  // Older links: `?tab=settings` was the System tab before the two pages became one, and
  // `?tab=permissions` the Roles tab before roles.
  const asked =
    requested === 'settings' ? 'system' : requested === 'permissions' ? 'roles' : requested;
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
                  {me.authEnabled
                    ? me.roles.length
                      ? ` (${me.roles.join(', ')}).`
                      : '.'
                    : ' (login is off).'}
                </>
              )}
            </div>
          </div>
        </header>
        <div className="analysis-body">
          {/* The section's title sits on the page, and its content in the same SGDS Card the
              Analysis and Monitor pages use (Roles lays out two cards of its own). */}
          <section id={`system-panel-${tab}`} aria-labelledby={`system-tab-${tab}`}>
            <h2 className="settings-section-title" id={`system-tab-${tab}`}>
              {current.title}
            </h2>
            <SectionCard bare={tab === 'roles'}>
              {tab === 'personal' && <PersonalSettingsTab />}
              {tab === 'system' && <SystemSettingsTab />}
              {tab === 'rules' && <DetectionRulesPanel />}
              {tab === 'addresses' && <AddressDefaultsPanel />}
              {tab === 'roles' && <PermissionsPanel />}
              {tab === 'audit' && <AuditLogPanel />}
              {tab === 'users' &&
                (env.AUTH_ENABLED ? (
                  <UsersPanel />
                ) : (
                  <p className="small text-muted mb-0">
                    Login is off, so there are no user accounts: everyone shares one profile and
                    acts as <span className="font-monospace">system</span>. Turning login on is
                    described in the Authentication section of the docs.
                  </p>
                ))}
            </SectionCard>
          </section>
        </div>
      </div>
    </div>
  );
}
