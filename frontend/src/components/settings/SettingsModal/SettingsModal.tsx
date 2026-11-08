import { Modal, Tab, Tabs } from '@govtechsg/sgds-react';
import { SystemSettingsTab } from './SystemSettingsTab';

interface SettingsModalProps {
  show: boolean;
  onHide: () => void;
}

/**
 * Settings, grouped by who they affect (#915). Phase 1 has the System tab. Network settings live on
 * each network's page (Settings button), and Personal and File tabs come in later phases.
 */
export function SettingsModal({ show, onHide }: SettingsModalProps) {
  return (
    <Modal show={show} onHide={onHide} size="lg" scrollable>
      <Modal.Header closeButton>
        <Modal.Title>Settings</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Tabs defaultActiveKey="system" id="settings-tabs" className="mb-3">
          <Tab eventKey="system" title="System">
            <SystemSettingsTab />
          </Tab>
        </Tabs>
        <p className="small text-muted mb-0">
          Per-network settings (such as when a device counts as no longer seen) are on each
          network's page, under Settings.
        </p>
      </Modal.Body>
    </Modal>
  );
}
