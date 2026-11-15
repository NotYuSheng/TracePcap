import { useEffect, useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { useStore, type ThemeMode } from '@/store';
import { NodeLabelSettingsModal } from '@components/network/NodeLabelSettingsModal';
import { preferencesService } from '@/features/preferences/preferencesService';

const THEMES: { value: ThemeMode; label: string }[] = [
  { value: 'system', label: 'Match my device' },
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
];

/**
 * Personal preferences (#915 phase 2): look and layout only, never results. Saved per account with
 * login on, and shared by everyone using the install with login off, which this tab says plainly.
 */
export function PersonalSettingsTab() {
  const themeMode = useStore(s => s.themeMode);
  const setThemeMode = useStore(s => s.setThemeMode);
  const nodeLabelCount = useStore(s => s.nodeLabelConfig.fields.filter(f => f.enabled).length);
  const [shared, setShared] = useState<boolean | null>(null);
  const [showLabels, setShowLabels] = useState(false);

  useEffect(() => {
    preferencesService.get().then(p => setShared(!!p.shared)).catch(() => setShared(null));
  }, []);

  return (
    <div>
      {shared === true && (
        <Alert variant="info" className="small py-2" data-testid="shared-notice">
          <i className="bi bi-people me-1" aria-hidden="true"></i>
          Login is off on this install, so these preferences are <strong>shared by everyone</strong>{' '}
          using it. A change here changes it for everyone.
        </Alert>
      )}
      {shared === false && (
        <p className="small text-muted">Saved to your account, so they follow you to any browser.</p>
      )}

      <Form.Group className="mb-3">
        <Form.Label htmlFor="pref-theme">Theme</Form.Label>
        <Form.Select id="pref-theme" value={themeMode} onChange={e => setThemeMode(e.target.value as ThemeMode)}>
          {THEMES.map(t => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </Form.Select>
      </Form.Group>

      <div className="mb-3">
        <div className="fw-semibold small">Network diagram labels</div>
        <div className="d-flex align-items-center gap-2">
          <span className="small text-muted">
            {nodeLabelCount} label{nodeLabelCount === 1 ? '' : 's'} shown on each node.
          </span>
          <Button type="button" size="sm" variant="outline-secondary" onClick={() => setShowLabels(true)}>
            Edit labels
          </Button>
        </div>
      </div>

      <p className="small text-muted mb-0">
        Recent files stay in this browser only. They're history, not a preference.
      </p>

      <NodeLabelSettingsModal show={showLabels} onHide={() => setShowLabels(false)} />
    </div>
  );
}
