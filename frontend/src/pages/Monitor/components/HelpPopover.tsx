import type { ReactNode, CSSProperties } from 'react';
import { Button, OverlayTrigger, Popover } from '@govtechsg/sgds-react';

interface HelpPopoverProps {
  /** DOM id for the popover (also its a11y handle). */
  id: string;
  /** Popover header text. */
  title: string;
  /** Popover body content. */
  children: ReactNode;
  /** Max width of the popover (px). */
  maxWidth?: number;
  /** Tooltip on the trigger button. */
  buttonTitle?: string;
  /** Extra style merged onto the trigger button. */
  buttonStyle?: CSSProperties;
}

/**
 * Click-to-open info "ⓘ" button + popover, used for the per-section help text on
 * the network detail page. Factors out the repeated OverlayTrigger boilerplate.
 */
export const HelpPopover = ({ id, title, children, maxWidth = 380, buttonTitle, buttonStyle }: HelpPopoverProps) => (
  <OverlayTrigger
    trigger="click"
    placement="right"
    rootClose
    overlay={
      <Popover id={id} style={{ maxWidth }}>
        <Popover.Header>{title}</Popover.Header>
        <Popover.Body className="small">{children}</Popover.Body>
      </Popover>
    }
  >
    <Button
      type="button"
      size="sm"
      variant="link"
      className="text-muted p-0 ms-2"
      style={{ fontSize: '0.85rem', ...buttonStyle }}
      title={buttonTitle}
    >
      <i className="bi bi-info-circle"></i>
    </Button>
  </OverlayTrigger>
);
