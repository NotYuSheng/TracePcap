import { useEffect, useState } from 'react';
import { conversationService } from '@/features/conversation/services/conversationService';
import type { WindowsLogon } from '@/features/conversation/types';
import { parseDateTime } from '@/utils/dateUtils';

/** Device types where an LDAP lookup is not taken as a sign-in (mirrors AnalysisService, #812). */
const NO_LDAP_SIGN_IN = new Set(['SERVER', 'ROUTER', 'DNS_SERVER', 'WEB_SERVER', 'API_SERVER']);

function when(dt: WindowsLogon['firstSeen']): string | null {
  if (!dt) return null;
  const ms = parseDateTime(dt);
  return ms ? new Date(ms).toLocaleString() : null;
}

/** "Signed in" for a Kerberos login, "Looked up" for an LDAP lookup: the wording never overclaims. */
function evidenceWords(l: WindowsLogon): string {
  return l.evidence === 'kerberos_as_req' ? 'Signed in (Kerberos login)' : 'Looked up (LDAP directory)';
}

/** Where the account lives, in words an analyst can act on without reading CN=/OU= syntax. */
function folderWords(l: WindowsLogon): string | null {
  if (!l.folder) return null;
  const domain = l.domain ? `, domain ${l.domain}` : '';
  return l.folderKind === 'USERS'
    ? `Windows' default Users folder${domain}. Normally people.`
    : `Custom folder "${l.folder}"${domain}. Could be a person, a computer or a group.`;
}

interface Props {
  fileId: string;
  ip: string;
  /** The host's classified device type, to explain why LDAP lookups weren't used on a server. */
  deviceType?: string;
}

/**
 * Every Windows account seen on a host, oldest first (#812). A host can have several over one
 * capture (a shift change, a shared PC, a remote admin), so the answer to "who" is a timeline, not
 * one name. Renders nothing when no accounts were seen.
 */
export function WindowsLogonTimeline({ fileId, ip, deviceType }: Props) {
  const [logons, setLogons] = useState<WindowsLogon[] | null>(null);

  useEffect(() => {
    let active = true;
    conversationService
      .getWindowsLogons(fileId, ip)
      .then(rows => active && setLogons(rows))
      .catch(() => active && setLogons([]));
    return () => {
      active = false;
    };
  }, [fileId, ip]);

  if (!logons || logons.length === 0) return null;
  const ldapIgnored =
    deviceType !== undefined &&
    NO_LDAP_SIGN_IN.has(deviceType) &&
    logons.some(l => l.evidence === 'ldap_dn');

  return (
    <div className="mb-3" data-testid="windows-logon-timeline">
      <h6 className="small fw-semibold text-muted mb-1">Windows accounts seen on this host</h6>
      <p className="small text-muted mb-2">
        Oldest first. A capture shows logins, not logouts, so read each row as "this account was
        active from here".
      </p>
      {ldapIgnored && (
        <p className="small text-muted mb-2">
          LDAP lookups aren't used as this host's sign-in, because it's classified as a server or
          router. Those look up accounts all day.
        </p>
      )}
      <ul className="list-unstyled small mb-0">
        {logons.map((l, i) => {
          const first = when(l.firstSeen);
          const last = when(l.lastSeen);
          const folder = folderWords(l);
          return (
            <li key={`${l.username}-${l.evidence}-${i}`} className="border-start ps-2 mb-2">
              <div className="d-flex flex-wrap gap-2 align-items-baseline">
                <span className="text-muted font-monospace">{first ?? 'time unknown'}</span>
                <strong>{l.username}</strong>
                <span>{evidenceWords(l)}</span>
                {l.candidateOnly && <span className="badge text-bg-light border">Not used by default</span>}
              </div>
              {folder && <div className="text-muted">{folder}</div>}
              {l.directoryEntry && (
                <div className="text-muted font-monospace" style={{ fontSize: '0.7rem' }}>
                  {l.directoryEntry}
                </div>
              )}
              <div className="text-muted">
                Seen {l.seenCount} {l.seenCount === 1 ? 'time' : 'times'}
                {last && last !== first ? `, last at ${last}` : ''}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
