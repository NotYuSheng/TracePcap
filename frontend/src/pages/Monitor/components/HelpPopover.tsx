import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';
import type { ReactNode, CSSProperties } from 'react';
import { Button } from '@govtechsg/sgds-react';
import { InfoPopover } from '@components/common/InfoPopover';

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
  <EscapableOverlayTrigger
    trigger="click"
    placement="right"
    overlay={
      <InfoPopover id={id} kind="Help" title={title} width={maxWidth} docs="features/network-monitor">
        {children}
      </InfoPopover>
    }
  >
    <Button
      type="button"
      size="sm"
      variant="link"
      className="text-muted p-0 ms-2"
      style={{ fontSize: '0.85rem', ...buttonStyle }}
      title={buttonTitle}
      aria-label={buttonTitle ?? title}
    >
      <i className="bi bi-info-circle"></i>
    </Button>
  </EscapableOverlayTrigger>
);
