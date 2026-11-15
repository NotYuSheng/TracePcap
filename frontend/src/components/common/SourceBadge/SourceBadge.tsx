import { useId } from 'react';
import { Popover } from '@govtechsg/sgds-react';
import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';

export interface SourceInfo {
  label: string;
  tooltip: string;
  color: string;
}

interface SourceBadgeProps {
  /** The source key to look up (e.g. 'dhcp', 'kerberos_as_req'). */
  source?: string | null;
  /** Map of known source keys to their display info. Unknown/absent sources render nothing. */
  info: Record<string, SourceInfo>;
}

/**
 * Small coloured chip showing where a piece of host metadata was discovered. Parameterised by a
 * source-info map so the same chip renders hostname sources (DHCP/mDNS/…), signed-in-user sources
 * (Kerberos/LDAP), and any future provenance badge without duplicating the styling and guards.
 */
export const SourceBadge = ({ source, info }: SourceBadgeProps) => {
  const popoverId = useId();
  if (!source) return null;
  const entry = info[source];
  if (!entry) return null;
  // A click-toggled popover, not a native title= tooltip (CLAUDE.md, #812 item 5): title= is
  // unreliable and unreachable from a keyboard or touch screen. A real button, so it can be focused.
  return (
    <EscapableOverlayTrigger
      trigger="click"
      placement="top"
      overlay={
        <Popover id={popoverId} style={{ maxWidth: 280 }}>
          <Popover.Body className="small">{entry.tooltip}</Popover.Body>
        </Popover>
      }
    >
      <button
        type="button"
        aria-label={`${entry.label}: what this means`}
        style={{
          fontSize: 9,
          fontWeight: 600,
          color: '#fff',
          background: entry.color,
          border: 'none',
          borderRadius: 3,
          padding: '1px 4px',
          cursor: 'pointer',
          whiteSpace: 'nowrap',
          flexShrink: 0,
          lineHeight: 'inherit',
        }}
      >
        {entry.label}
      </button>
    </EscapableOverlayTrigger>
  );
};
