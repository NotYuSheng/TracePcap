export type SortField =
  | 'srcIp'
  | 'dstIp'
  | 'packets'
  | 'bytes'
  | 'duration'
  | 'startTime'
  | '';

export type SortDir = 'asc' | 'desc';

export interface ConversationFilters {
  ip: string;
  port: string;
  protocols: string[];
  apps: string[];
  categories: string[];
  hasRisks: boolean;
  fileTypes: string[];
  riskTypes: string[];
  customSignatures: string[];
  sortBy: SortField;
  sortDir: SortDir;
  page: number;
  pageSize: number;
}
