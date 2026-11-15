import type { ReactNode } from 'react';
import { Popover } from '@govtechsg/sgds-react';
import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';

/**
 * Says where a section's numbers come from ("nDPI", "tshark") right beside its heading; clicking
 * it explains how they are worked out. Visible, so nobody has to guess an info icon exists.
 */
export function SourceTag({
  id,
  source,
  title,
  children,
}: {
  id: string;
  source: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <EscapableOverlayTrigger
      trigger="click"
      placement="bottom"
      overlay={
        <Popover id={id} style={{ maxWidth: 340 }}>
          <Popover.Header>{title}</Popover.Header>
          <Popover.Body className="small">{children}</Popover.Body>
        </Popover>
      }
    >
      <button
        type="button"
        className="ov-source"
        aria-label={`How this is worked out: from ${source}`}
      >
        from {source}
        <i className="bi bi-info-circle ms-1" aria-hidden="true" />
      </button>
    </EscapableOverlayTrigger>
  );
}
