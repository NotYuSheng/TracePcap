/** 'id' is for paging through everything in a stable order, not a column a user sorts by. */
export type SortField = 'srcIp' | 'dstIp' | 'packets' | 'bytes' | 'duration' | 'startTime' | 'id' | '';

export type SortDir = 'asc' | 'desc';

/** Conversations per filter value for one file (GET /conversations/{fileId}/facet-counts).
 *  Whole-file counts; l7Protocols keys are upper-cased. */
export interface ConversationFacetCounts {
  protocols: Record<string, number>;
  l7Protocols: Record<string, number>;
  apps: Record<string, number>;
  categories: Record<string, number>;
  fileTypes: Record<string, number>;
  riskTypes: Record<string, number>;
  customSignatures: Record<string, number>;
  suricataAlerts: Record<string, number>;
  countries: Record<string, number>;
  deviceTypes: Record<string, number>;
  /** Connection outcomes (#1233): ANSWERED, NO_ANSWER, REJECTED, UNKNOWN. */
  outcomes?: Record<string, number>;
}

export interface ConversationFilters {
  /**
   * View in this network (#925 phase 3): its own detection rules' matches are added to
   * customSignatures, and count for that filter. Optional.
   */
  networkId?: string;
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
  /** Connection outcomes (#1233): ANSWERED, NO_ANSWER, REJECTED, UNKNOWN. */
  outcomes?: string[];
  sortBy: SortField;
  sortDir: SortDir;
  page: number;
  pageSize: number;
}

/** One Windows account seen on a host (#812). Mirrors WindowsLogonResponse. */
export interface WindowsLogon {
  username: string;
  /** kerberos_as_req / ntlm_auth: signed in. ldap_dn: looked up in the directory. */
  evidence: 'kerberos_as_req' | 'ntlm_auth' | 'ldap_dn' | string;
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
