/**
 * One Escape closes exactly one layer (#817, CLAUDE.md). A plain OverlayTrigger with rootClose
 * closes itself *and* the Modal it sits in on a single Escape, because both listen on document
 * independently.
 */
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { Button, Modal, Popover } from '@govtechsg/sgds-react';
import { useEscapeLayerRoot, __resetEscapeLayers } from '@utils/useEscapeLayer';
import { EscapableOverlayTrigger } from '../EscapableOverlayTrigger';

function Help() {
  return (
    <EscapableOverlayTrigger
      trigger="click"
      placement="right"
      overlay={
        <Popover id="help-popover">
          <Popover.Body>HELP TEXT</Popover.Body>
        </Popover>
      }
    >
      <Button aria-label="About this">i</Button>
    </EscapableOverlayTrigger>
  );
}

function Root({ children }: { children: React.ReactNode }) {
  useEscapeLayerRoot();
  return <>{children}</>;
}

function HelpInModal() {
  const [show, setShow] = useState(true);
  return (
    <Modal show={show} onHide={() => setShow(false)}>
      <Modal.Body>
        MODAL BODY
        <Help />
      </Modal.Body>
    </Modal>
  );
}

const settle = () => act(async () => { await new Promise(r => setTimeout(r, 400)); });

describe('EscapableOverlayTrigger', () => {
  afterEach(() => __resetEscapeLayers());

  it('opens on click and closes on Escape', async () => {
    render(<Root><Help /></Root>);

    await userEvent.click(screen.getByLabelText('About this'));
    expect(screen.getByText('HELP TEXT')).toBeInTheDocument();

    await userEvent.keyboard('{Escape}');
    await settle();
    expect(screen.queryByText('HELP TEXT')).not.toBeInTheDocument();
  });

  it('inside a Modal, the first Escape closes only the popover, the second the modal', async () => {
    render(<Root><HelpInModal /></Root>);
    await userEvent.click(screen.getByLabelText('About this'));
    expect(screen.getByText('HELP TEXT')).toBeInTheDocument();

    await userEvent.keyboard('{Escape}');
    await settle();
    expect(screen.queryByText('HELP TEXT')).not.toBeInTheDocument();
    expect(screen.getByText('MODAL BODY')).toBeInTheDocument();

    await userEvent.keyboard('{Escape}');
    await settle();
    expect(screen.queryByText('MODAL BODY')).not.toBeInTheDocument();
  });
});
