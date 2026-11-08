import { SourceBadge, type SourceInfo } from '@components/common/SourceBadge/SourceBadge';

const SOURCE_INFO: Record<string, SourceInfo> = {
  kerberos_as_req: {
    label: 'Kerberos',
    tooltip:
      'This host signed in to Active Directory as this account (a Kerberos login). Strong evidence of who is signed in.',
    color: '#0072c6',
  },
  ldap_dn: {
    label: 'LDAP',
    tooltip:
      "This host looked up this account in the directory (LDAP). Weaker: a lookup isn't proof that this account is the one signed in here.",
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
