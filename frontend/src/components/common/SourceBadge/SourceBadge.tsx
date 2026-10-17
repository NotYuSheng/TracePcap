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
  if (!source) return null;
  const entry = info[source];
  if (!entry) return null;
  return (
    <span
      title={entry.tooltip}
      style={{
        fontSize: 9,
        fontWeight: 600,
        color: '#fff',
        background: entry.color,
        borderRadius: 3,
        padding: '1px 4px',
        cursor: 'help',
        whiteSpace: 'nowrap',
        flexShrink: 0,
      }}
    >
      {entry.label}
    </span>
  );
};
