import { useEffect, useMemo, useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { settingsService, type SystemSetting } from '@/features/settings';
import { EditSystemSettingModal } from './EditSystemSettingModal';

const GROUPS: { key: SystemSetting['group']; title: string; blurb: string }[] = [
  {
    key: 'POLICY',
    title: 'Analysis policy',
    blurb: 'How captures are analysed and kept: detection thresholds, retention, display limits.',
  },
  {
    key: 'MEMORY',
    title: 'Memory and capacity',
    blurb: 'Limits tied to how much memory the backend has.',
  },
  {
    key: 'INFRASTRUCTURE',
    title: 'Infrastructure',
    blurb: 'How this install is wired up: servers, storage, login, the LLM.',
  },
];

function shownValue(s: SystemSetting): string {
  if (s.secret) return s.set ? 'Set (hidden)' : 'Not set';
  if (s.value === null || s.value === undefined || s.value === '') return 'Not set';
  return s.value;
}

/**
 * One setting. Greyed out when it can't be changed here; clicking it says why (#915). An editable
 * one offers Change…, which opens a modal.
 */
function SettingRow({ setting, onEdit }: { setting: SystemSetting; onEdit: (s: SystemSetting) => void }) {
  const [open, setOpen] = useState(false);
  const detailId = `setting-detail-${setting.key}`;
  return (
    <li className="border-bottom py-1">
      <button
        type="button"
        className="btn btn-link text-start text-decoration-none w-100 p-1 d-flex justify-content-between gap-3"
        style={{ opacity: setting.editable ? 1 : 0.6, color: 'inherit' }}
        aria-expanded={open}
        aria-controls={detailId}
        onClick={() => setOpen(o => !o)}
      >
        <span>
          {!setting.editable && <i className="bi bi-lock me-1 text-muted" aria-hidden="true"></i>}
          {setting.label}
          {setting.overridden && (
            <span className="badge bg-info-subtle text-info-emphasis ms-2">changed in the app</span>
          )}
        </span>
        <span className="font-monospace small text-truncate" style={{ maxWidth: '45%' }}>
          {shownValue(setting)}
        </span>
      </button>
      {open && (
        <div id={detailId} className="small ps-4 pe-2 pb-2">
          {setting.lockedReason && (
            <p className="mb-1">
              <strong>Why you can't change it here:</strong> {setting.lockedReason}
            </p>
          )}
          {setting.description && <p className="text-muted mb-1">{setting.description}</p>}
          {setting.inAppEditable && (
            <p className="mb-1">
              The deployment sets <span className="font-monospace">{setting.deployValue}</span>
              {setting.overridden ? '; the value above was changed in the app.' : '.'}
              {setting.takesEffect && <> Takes effect: {setting.takesEffect}</>}
            </p>
          )}
          {setting.editable && (
            <Button size="sm" variant="outline-primary" className="mb-2" onClick={() => onEdit(setting)}>
              Change…
            </Button>
          )}
          <div className="text-muted">
            <span className="font-monospace">{setting.key}</span>
            {setting.defaultValue && (
              <>
                {' '}· default <span className="font-monospace">{setting.defaultValue}</span>
              </>
            )}
          </div>
        </div>
      )}
    </li>
  );
}

/**
 * Every deploy-time setting with its effective value (#915). Retention and detection thresholds
 * can be changed here by whoever has the permission (phase 5); everything else is greyed out and
 * explains, when clicked, why and where it's set instead.
 */
export function SystemSettingsTab() {
  const [settings, setSettings] = useState<SystemSetting[] | null>(null);
  const [error, setError] = useState(false);
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState<SystemSetting | null>(null);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    settingsService
      .getSystemSettings()
      .then(setSettings)
      .catch(() => setError(true));
  }, [reload]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!settings) return [];
    if (!q) return settings;
    return settings.filter(
      s =>
        s.label.toLowerCase().includes(q) ||
        s.key.toLowerCase().includes(q) ||
        (s.description ?? '').toLowerCase().includes(q)
    );
  }, [settings, search]);

  if (error) return <p className="text-danger small">Couldn't load the system settings.</p>;
  if (!settings) {
    return (
      <div className="text-muted small py-3">
        <Spinner animation="border" size="sm" className="me-2" />
        Loading…
      </div>
    );
  }

  return (
    <div>
      <p className="small text-muted">
        These apply to everyone using this install. Most are set when TracePcap is deployed;
        retention and detection thresholds can also be changed here, if you have permission. Click
        any setting to see more.
      </p>
      <Form.Control
        type="search"
        size="sm"
        className="mb-3"
        placeholder="Search settings…"
        aria-label="Search settings"
        value={search}
        onChange={e => setSearch(e.target.value)}
      />
      {GROUPS.map(g => {
        const rows = filtered.filter(s => s.group === g.key);
        if (rows.length === 0) return null;
        return (
          <section key={g.key} className="mb-3">
            <h6 className="mb-0">{g.title}</h6>
            <p className="small text-muted mb-1">{g.blurb}</p>
            <ul className="list-unstyled mb-0">
              {rows.map(s => (
                <SettingRow key={s.key} setting={s} onEdit={setEditing} />
              ))}
            </ul>
          </section>
        );
      })}
      {filtered.length === 0 && <p className="small text-muted">No settings match "{search}".</p>}
      <EditSystemSettingModal
        setting={editing}
        onHide={() => setEditing(null)}
        onSaved={() => setReload(n => n + 1)}
      />
    </div>
  );
}
