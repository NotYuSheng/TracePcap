import { useId, type ReactElement } from 'react';
import { OverlayTrigger, TooltipBox } from '@govtechsg/sgds-react';

interface IconTooltipProps {
  /** What the icon button does, e.g. "Mark as reviewed". */
  text: string;
  placement?: 'top' | 'bottom' | 'left' | 'right';
  /** One element, usually an icon-only button that also carries the same text as its aria-label. */
  children: ReactElement;
}

/**
 * Hover and keyboard-focus text for an icon-only button. Not SGDS's own Tooltip: that replaces the
 * child's onClick with its own toggle, so the button would stop working. A label for an action,
 * not an explainer (those open a Modal or an EscapableOverlayTrigger popover).
 */
export function IconTooltip({ text, placement = 'top', children }: IconTooltipProps) {
  const id = useId();
  return (
    <OverlayTrigger placement={placement} overlay={<TooltipBox id={id}>{text}</TooltipBox>}>
      {children}
    </OverlayTrigger>
  );
}
