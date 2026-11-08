import { Modal, Tab, Tabs } from '@govtechsg/sgds-react';
import { PersonalSettingsTab } from './PersonalSettingsTab';
import { SystemSettingsTab } from './SystemSettingsTab';

interface SettingsModalProps {
  show: boolean;
  onHide: () => void;
}

/**
 * Settings, grouped by who they affect (#915): Personal (only me, or everyone when login is off)
 * and System (everyone). Network settings live on each network's page (Settings button); a File
 * tab comes in a later phase.
 */
export function SettingsModal({ show, onHide }: SettingsModalProps) {
  return (
    <Modal show={show} onHide={onHide} size="lg" scrollable>
      <Modal.Header closeButton>
        <Modal.Title>Settings</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Tabs defaultActiveKey="personal" id="settings-tabs" className="mb-3">
          <Tab eventKey="personal" title="Personal">
            <PersonalSettingsTab />
          </Tab>
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
