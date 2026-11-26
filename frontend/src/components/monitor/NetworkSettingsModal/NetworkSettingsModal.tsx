import { SideDrawer } from '@components/common/SideDrawer';
import { useEffect, useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import type { NetworkSettings } from '@/features/monitor/types/monitor.types';
import { DEFAULT_NETWORK_SETTINGS, describeRule } from '@/features/monitor/utils/presence';
import { usePermission } from '@/features/me/useMe';

interface NetworkSettingsModalProps {
  show: boolean;
  onHide: () => void;
  /** The network's current settings; missing means the defaults. */
  initial?: NetworkSettings;
  onSave: (settings: NetworkSettings) => Promise<void>;
}

const MAX_THRESHOLD = 3650;

/**
 * Per-network settings (#468, #488). Today that's the inactivity rule: how long a device, IP or
 * protocol can go unseen before the drift panels call it "no longer seen" instead of "quiet".
 */
export const NetworkSettingsModal = ({ show, onHide, initial, onSave }: NetworkSettingsModalProps) => {
  const current = initial ?? DEFAULT_NETWORK_SETTINGS;
  const [mode, setMode] = useState<NetworkSettings['inactivityMode']>(current.inactivityMode);
  const [threshold, setThreshold] = useState(String(current.inactivityThreshold));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Who may change this is configurable (#915). Everything stays visible, greyed out with the reason.
  const { allowed, reason } = usePermission('NETWORK_SETTINGS');
  const locked = saving || !allowed;

  useEffect(() => {
    if (show) {
      setMode(current.inactivityMode);
      setThreshold(String(current.inactivityThreshold));
      setError(null);
    }
  }, [show, current.inactivityMode, current.inactivityThreshold]);

  const n = Number(threshold);
  const valid = Number.isInteger(n) && n >= 1 && n <= MAX_THRESHOLD;
  const draft: NetworkSettings = { inactivityMode: mode, inactivityThreshold: valid ? n : 1 };
  const isDefault =
    mode === DEFAULT_NETWORK_SETTINGS.inactivityMode && n === DEFAULT_NETWORK_SETTINGS.inactivityThreshold;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setSaving(true);
    setError(null);
    try {
      await onSave(draft);
      onHide();
    } catch (err) {
      const apiMsg = (err as { response?: { status?: number; data?: { message?: string } } })?.response;
      setError(
        apiMsg?.status === 403 && apiMsg.data?.message
          ? apiMsg.data.message
          : 'Failed to save settings. Please try again.'
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <SideDrawer
      show={show}
      onHide={() => !saving && onHide()}
      title="Network settings"
      titleId="network-settings-title"
      footer={
        <>
          <Button
            type="button"
            variant="link"
            className="me-auto"
            onClick={() => {
              setMode(DEFAULT_NETWORK_SETTINGS.inactivityMode);
              setThreshold(String(DEFAULT_NETWORK_SETTINGS.inactivityThreshold));
            }}
            disabled={locked || isDefault}
          >
            Reset to default
          </Button>
          <Button type="button" variant="secondary" onClick={onHide} disabled={saving}>
            Cancel
          </Button>
          <Button type="submit" form="network-settings-form" variant="primary" disabled={locked || !valid}>
            {saving ? <><Spinner animation="border" size="sm" className="me-2" />Saving…</> : 'Save'}
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit} id="network-settings-form">
        {error && <Alert variant="danger" className="py-2">{error}</Alert>}
        {!allowed && (
          <Alert variant="info" className="py-2" data-testid="settings-locked">
            <i className="bi bi-lock me-2" aria-hidden="true" />
            You can view these settings but not change them: {reason ?? 'only admins can change this.'}
          </Alert>
        )}
        <h6 className="mb-1">When does something count as "no longer seen"?</h6>
        <p className="small text-muted">
          A device, IP or protocol missing from the latest capture may simply have been quiet
          during it. Until it passes this rule, the drift panels show it as <strong>quiet</strong>{' '}
          (dashed) rather than <strong>no longer seen</strong> (struck through).
        </p>

        <Form.Group className="mb-3">
          <Form.Label htmlFor="inactivity-mode">Count by</Form.Label>
          <Form.Select
            id="inactivity-mode"
            value={mode}
            onChange={e => setMode(e.target.value as NetworkSettings['inactivityMode'])}
            disabled={locked}
          >
            <option value="SNAPSHOTS">Captures: missing from the last N captures</option>
            <option value="DAYS">Days: not seen for N days before the latest capture</option>
          </Form.Select>
          <Form.Text muted>
            {mode === 'SNAPSHOTS'
              ? 'Suits irregular capture schedules.'
              : 'Suits regular schedules. Counted from the latest capture, not today, so reviewing old captures works.'}
          </Form.Text>
        </Form.Group>

        <Form.Group className="mb-3">
          <Form.Label htmlFor="inactivity-threshold">
            {mode === 'SNAPSHOTS' ? 'Number of captures' : 'Number of days'}
          </Form.Label>
          <Form.Control
            id="inactivity-threshold"
            type="number"
            min={1}
            max={MAX_THRESHOLD}
            step={1}
            value={threshold}
            onChange={e => setThreshold(e.target.value)}
            isInvalid={!valid}
            disabled={locked}
          />
          <Form.Control.Feedback type="invalid">
            Enter a whole number from 1 to {MAX_THRESHOLD}.
          </Form.Control.Feedback>
        </Form.Group>

        {valid && (
          <p className="small mb-0" data-testid="rule-preview">
            Something is <strong>{describeRule(draft)}</strong>.
            {isDefault && ' This is the default, and how the panels have always behaved.'}
          </p>
        )}
      </form>
    </SideDrawer>
  );
};
