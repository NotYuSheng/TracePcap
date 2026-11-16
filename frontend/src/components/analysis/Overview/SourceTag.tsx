import type { ReactNode } from 'react';
import { InfoPopover } from '@components/common/InfoPopover';
import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';

/**
 * Says where a section's numbers come from ("nDPI", "tshark") right beside its heading; clicking
 * it explains how they are worked out. Visible, so nobody has to guess an info icon exists.
 */
export function SourceTag({
  id,
  source,
  title,
  docsAnchor,
  children,
}: {
  id: string;
  source: string;
  title: string;
  /** The section on the Overview's docs page, when it has its own. */
  docsAnchor?: string;
  children: ReactNode;
}) {
  return (
    <EscapableOverlayTrigger
      trigger="click"
      placement="bottom"
      overlay={
        <InfoPopover
          id={id}
          kind="How it's measured"
          title={title}
          source={source}
          docs="features/analysis-overview"
          docsAnchor={docsAnchor}
        >
          {children}
        </InfoPopover>
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
