export type SortField = 'srcIp' | 'dstIp' | 'packets' | 'bytes' | 'duration' | 'startTime' | '';

export type SortDir = 'asc' | 'desc';

export interface ConversationFilters {
  ip: string;
  /**
   * Exact directional pair (#471): conversations where srcIp = this AND dstIp = `dstIp`. Unlike
   * `ip` (contains-match on either end), this pins one flow. Optional; set by deep links such as
   * the monitor Security tab's flow rows.
   */
  srcIp?: string;
  dstIp?: string;
  port: string;
  payloadContains: string;
  protocols: string[];
  l7Protocols: string[];
  apps: string[];
  categories: string[];
  hasRisks: boolean;
  fileTypes: string[];
  riskTypes: string[];
  customSignatures: string[];
  suricataAlerts: string[];
  deviceTypes: string[];
  countries: string[];
  sortBy: SortField;
  sortDir: SortDir;
  page: number;
  pageSize: number;
}

/** One Windows account seen on a host (#812). Mirrors WindowsLogonResponse. */
export interface WindowsLogon {
  username: string;
  /** kerberos_as_req: signed in. ldap_dn: looked up in the directory. */
  evidence: 'kerberos_as_req' | 'ldap_dn' | string;
  /** LDAP only: the full directory entry. */
  directoryEntry?: string | null;
  /** LDAP only: the folder in plain words, e.g. "Users" or "Staff / Sales". */
  folder?: string | null;
  /** LDAP only: USERS (Windows' default folder, normally people) or CUSTOM. */
  folderKind?: 'USERS' | 'CUSTOM' | null;
  domain?: string | null;
  firstSeen?: string | number[] | null;
  lastSeen?: string | number[] | null;
  seenCount: number;
  /** A custom-folder lookup: could be a person, a computer or a group. Never the default label. */
  candidateOnly: boolean;
}
