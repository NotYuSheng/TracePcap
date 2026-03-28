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
  protocols: string[];
  apps: string[];
  categories: string[];
  hasRisks: boolean;
  fileTypes: string[];
  sortBy: SortField;
  sortDir: SortDir;
  page: number;
  pageSize: number;
}
