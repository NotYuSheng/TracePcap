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
