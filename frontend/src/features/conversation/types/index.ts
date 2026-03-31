export type SortField = 'srcIp' | 'dstIp' | 'packets' | 'bytes' | 'duration' | 'startTime' | '';

export type SortDir = 'asc' | 'desc';

export interface ConversationFilters {
  ip: string;
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
  deviceTypes: string[];
  sortBy: SortField;
  sortDir: SortDir;
  page: number;
  pageSize: number;
}
