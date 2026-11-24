/**
 * Which protocols in a capture help answer which investigation question (#1292). One catalogue:
 * each question, the protocols and apps that speak to it, and what they show there. Matched
 * against what this capture actually contains, so the Overview points at the traffic worth opening
 * for the question at hand, rather than listing everything.
 *
 * Names are tshark's dissected protocols (upper case, as the Conversations filter takes them) and
 * nDPI's application names (as detected). Deterministic and offline.
 */

export interface ProtocolInsight {
  /** Shown on the chip. */
  label: string;
  /** tshark protocol names that mean this (upper case). */
  l7: string[];
  /** nDPI application names that mean this. */
  apps: string[];
  /** What it shows for this question, in a line. */
  shows: string;
  /**
   * Link by tshark's name even when nDPI's is present. The Conversations filters combine with AND,
   * so a link uses one. nDPI's application name is usually the better net (tshark's "CLDAP" misses
   * LDAP over TCP; its "SPNEGO-KRB5" is Kerberos inside SMB), but nDPI names TLS and HTTP sessions
   * by service (Microsoft, GitHub), so for those tshark's name catches them all.
   */
  byL7?: boolean;
}

export interface QuestionInsights {
  key: string;
  label: string;
  icon: string;
  /** The standard-question answers that answer it; none for pure context. */
  answeredBy: string[];
  insights: ProtocolInsight[];
}

const KERBEROS = { label: 'Kerberos', l7: ['KERBEROS', 'KRB5', 'SPNEGO-KRB5'], apps: ['Kerberos'] };
const LDAP = { label: 'LDAP', l7: ['LDAP', 'CLDAP'], apps: ['LDAP', 'CLDAP'] };
const NTLM = { label: 'NTLM', l7: ['NTLMSSP'], apps: [] };
const SMB = { label: 'SMB', l7: ['SMB', 'SMB2'], apps: ['SMBv1', 'SMBv23'] };
const HTTP = { label: 'HTTP', l7: ['HTTP'], apps: ['HTTP'], byL7: true };
const FTP = { label: 'FTP', l7: ['FTP', 'FTP-DATA'], apps: ['FTP_CONTROL', 'FTP_DATA'] };

export const QUESTION_INSIGHTS: QuestionInsights[] = [
  {
    key: 'who',
    label: 'Who is signed in',
    icon: 'bi-person-badge',
    answeredBy: ['signed-in-user'],
    insights: [
      { ...KERBEROS, shows: 'the account a host asked the domain controller for a ticket as' },
      { ...LDAP, shows: 'directory lookups, which name the person behind an account' },
      { ...NTLM, shows: 'sign-ins by account name where Kerberos wasn’t used' },
    ],
  },
  {
    key: 'machine',
    label: 'Which machine it is',
    icon: 'bi-pc-display',
    answeredBy: [],
    insights: [
      { label: 'DHCP', l7: ['DHCP', 'BOOTP'], apps: ['DHCP'], shows: 'the hostname and MAC a device asked for its address with' },
      { label: 'NetBIOS', l7: ['NBNS', 'BROWSER', 'NBSS'], apps: ['NetBIOS'], shows: 'Windows machine names and workgroups' },
      { label: 'LLMNR / mDNS', l7: ['LLMNR', 'MDNS'], apps: ['LLMNR', 'MDNS'], shows: 'names a machine announces or asks for on the local network' },
    ],
  },
  {
    key: 'c2',
    label: 'Command & control and malware',
    icon: 'bi-broadcast-pin',
    // Not the victim: naming the host says nothing about which server it reached.
    answeredBy: ['c2', 'malware'],
    insights: [
      { label: 'DNS', l7: ['DNS'], apps: ['DNS'], shows: 'every name a host looked up, a C2’s domain included' },
      { label: 'TLS', l7: ['TLS'], apps: ['TLS'], byL7: true, shows: 'server names, certificates and JA3/JA4 fingerprints, even though the content is encrypted' },
      { ...HTTP, shows: 'URLs and user agents: check-ins and payload requests in the clear' },
    ],
  },
  {
    key: 'downloads',
    label: 'Downloads and delivery',
    icon: 'bi-file-earmark-arrow-down',
    answeredBy: ['downloads'],
    insights: [
      { ...HTTP, shows: 'files fetched in the clear, hashed in the Files tab' },
      { ...FTP, shows: 'files moved over FTP' },
    ],
  },
  {
    key: 'lateral',
    label: 'Lateral movement',
    icon: 'bi-diagram-2',
    answeredBy: ['lateral-movement'],
    insights: [
      { ...SMB, shows: 'shares connected to, admin shares, files copied to another machine' },
      { label: 'DCE-RPC', l7: ['DCERPC'], apps: ['DCERPC'], shows: 'remote calls: services created, tasks scheduled, directory replication' },
      { label: 'RDP', l7: ['RDP'], apps: ['RDP'], shows: 'interactive sessions on another machine' },
    ],
  },
  {
    key: 'accounts',
    label: 'Account attacks',
    icon: 'bi-key',
    answeredBy: ['kerberos-attack'],
    insights: [
      { ...KERBEROS, shows: 'failed sign-ins by account, and each ticket’s encryption' },
      { ...NTLM, shows: 'sign-in attempts by account name' },
    ],
  },
  {
    key: 'leaving',
    label: 'Data leaving',
    icon: 'bi-arrow-up-right-circle',
    answeredBy: ['data-transfer'],
    insights: [
      { label: 'Mail', l7: ['SMTP', 'IMAP', 'POP'], apps: ['SMTP', 'SMTPS', 'IMAP', 'IMAPS', 'POP3', 'POPS'], shows: 'mail sent and fetched, attachments included' },
      { ...FTP, shows: 'files sent out over FTP' },
    ],
  },
  {
    key: 'remote',
    label: 'Remote access',
    icon: 'bi-display',
    answeredBy: ['remote-access'],
    insights: [
      {
        label: 'Remote-control tools',
        l7: ['VNC'],
        apps: ['TeamViewer', 'AnyDesk', 'VNC', 'Radmin', 'NoMachine', 'Splashtop', 'ScreenConnect'],
        shows: 'someone controlling a machine from elsewhere',
      },
    ],
  },
];

/** One protocol present in this capture, and where its conversations are. */
export interface PresentInsight {
  label: string;
  shows: string;
  /** Conversations URL query, e.g. "l7Protocols=KERBEROS". */
  query: string;
}

export interface WorthALookGroup {
  key: string;
  label: string;
  icon: string;
  /**
   * answered: the Investigation Summary has it; ruled-out: its candidates were tested and ruled out;
   * open: nothing concluded; context: no question answers it; unknown: the investigation isn't in.
   */
  status: 'answered' | 'ruled-out' | 'open' | 'context' | 'unknown';
  items: PresentInsight[];
}

/**
 * The questions this capture's protocols can speak to, each with the protocols present. A
 * question with none of its protocols in the capture is left out.
 */
export function worthALook(
  l7Protocols: string[],
  apps: string[],
  /** Null while the investigation is loading or when it failed: no status is claimed then. */
  answeredQuestions: string[] | null,
  ruledOutQuestions: string[] = [],
): WorthALookGroup[] {
  const l7 = new Map(l7Protocols.map(p => [p.toUpperCase(), p]));
  const app = new Map(apps.map(a => [a.toLowerCase(), a]));
  const answered = new Set(answeredQuestions ?? []);
  const ruledOut = new Set(ruledOutQuestions);
  const groups: WorthALookGroup[] = [];
  for (const q of QUESTION_INSIGHTS) {
    const items: PresentInsight[] = [];
    for (const i of q.insights) {
      const viaL7 = i.l7.filter(n => l7.has(n));
      const viaApp = i.apps.filter(n => app.has(n.toLowerCase())).map(n => app.get(n.toLowerCase())!);
      if (viaL7.length === 0 && viaApp.length === 0) continue;
      const useL7 = viaL7.length > 0 && (i.byL7 || viaApp.length === 0);
      const query = useL7
        ? `l7Protocols=${encodeURIComponent(viaL7.join(','))}`
        : `apps=${encodeURIComponent(viaApp.join(','))}`;
      items.push({ label: i.label, shows: i.shows, query });
    }
    if (items.length === 0) continue;
    const status = q.answeredBy.length === 0 ? 'context'
      : answeredQuestions === null ? 'unknown'
        : q.answeredBy.some(k => answered.has(k)) ? 'answered'
          : q.answeredBy.some(k => ruledOut.has(k)) ? 'ruled-out' : 'open';
    groups.push({ key: q.key, label: q.label, icon: q.icon, status, items });
  }
  return groups;
}
