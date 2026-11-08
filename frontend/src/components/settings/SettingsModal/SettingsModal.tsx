import { Modal } from '@govtechsg/sgds-react';
import { Link } from 'react-router-dom';
import { PersonalSettingsTab } from './PersonalSettingsTab';

interface SettingsModalProps {
  show: boolean;
  onHide: () => void;
}

/**
 * Personal settings (#915): only me, or everyone when login is off. Settings for the whole install
 * live on the System page; network settings on each network's page (Settings button).
 */
export function SettingsModal({ show, onHide }: SettingsModalProps) {
  return (
    <Modal show={show} onHide={onHide} size="lg" scrollable>
      <Modal.Header closeButton>
        <Modal.Title>Settings</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <PersonalSettingsTab />
        <p className="small text-muted mb-0 mt-3">
          Settings for everyone using this install, who may change them, and the audit log are on
          the{' '}
          <Link to="/system" onClick={onHide}>
            System page
          </Link>
          . Per-network settings (such as when a device counts as no longer seen) are on each
          network's page, under Settings.
        </p>
      </Modal.Body>
    </Modal>
  );
}
