const SOURCE_INFO: Record<string, { label: string; tooltip: string; color: string }> = {
  kerberos_as_req: {
    label: 'Kerberos',
    tooltip:
      'This host authenticated to Active Directory as this principal (Kerberos AS-REQ) — strong evidence of who is signed in.',
    color: '#0072c6',
  },
  ldap_dn: {
    label: 'LDAP',
    tooltip:
      "This host looked up this account's directory entry (LDAP) — weaker: not proof the query is about the host's own user.",
    color: '#b35900',
  },
};

interface LoggedInUserSourceBadgeProps {
  source?: string | null;
}

/** Small coloured chip showing how a host's signed-in user was discovered (Kerberos vs LDAP). */
export const LoggedInUserSourceBadge = ({ source }: LoggedInUserSourceBadgeProps) => {
  if (!source) return null;
  const info = SOURCE_INFO[source];
  if (!info) return null;
  return (
    <span
      title={info.tooltip}
      style={{
        fontSize: 9,
        fontWeight: 600,
        color: '#fff',
        background: info.color,
        borderRadius: 3,
        padding: '1px 4px',
        cursor: 'help',
        whiteSpace: 'nowrap',
        flexShrink: 0,
      }}
    >
      {info.label}
    </span>
  );
};
