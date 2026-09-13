import { SourceBadge, type SourceInfo } from '@components/common/SourceBadge/SourceBadge';

const SOURCE_INFO: Record<string, SourceInfo> = {
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
export const LoggedInUserSourceBadge = ({ source }: LoggedInUserSourceBadgeProps) => (
  <SourceBadge source={source} info={SOURCE_INFO} />
);
