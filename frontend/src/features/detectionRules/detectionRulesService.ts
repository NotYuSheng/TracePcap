import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** All optional; a rule fires when every field given matches. Mirrors DetectionRuleRequest.Match. */
export interface RuleMatch {
  ip?: string | null;
  cidr?: string | null;
  srcPort?: number | null;
  dstPort?: number | null;
  ja3?: string | null;
  hostname?: string | null;
  app?: string | null;
  protocol?: string | null;
}

export interface PayloadPattern {
  ascii?: string | null;
  hex?: string | null;
}

export interface RegexPattern {
  pattern: string;
  caseInsensitive: boolean;
}

/** What the editor sends. Mirrors DetectionRuleRequest. */
export interface DetectionRuleInput {
  name: string;
  description?: string | null;
  severity: Severity;
  enabled: boolean;
  match: RuleMatch;
  payloadContains: PayloadPattern[];
  payloadRegex: RegexPattern[];
  matchAll: boolean;
}

/** Mirrors DetectionRuleDto. */
export type RuleScope = 'GLOBAL' | 'NETWORK' | 'CAPTURE';

export interface DetectionRule extends DetectionRuleInput {
  id: string;
  scope: RuleScope;
  /** For a capture rule: its capture. */
  fileId?: string | null;
  /** The rule this one was promoted from, if any. */
  promotedFrom?: string | null;
  /** Legacy, read-only: overrides matched hosts' device type until #926 replaces it. */
  deviceType?: string | null;
  version: number;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
}

export interface RuleImportResult {
  created: number;
  updated: number;
  unchanged: number;
  deleted: number;
  duplicates: string[];
}

/** Mirrors RuleSyncStatusDto (#925 phase 2). */
export interface RuleSyncStatus {
  captures: number;
  staleCaptures: number;
  uncheckableCaptures: number;
  staleRules: string[];
  uncheckableRules: string[];
}

/** Mirrors RuleReapplyJobDto. */
export interface ReapplyJob {
  id: string;
  fileId?: string | null;
  status: 'RUNNING' | 'DONE' | 'FAILED' | 'INTERRUPTED';
  total: number;
  done: number;
  failed: number;
  error?: string | null;
  requestedBy: string;
  createdAt: string;
  finishedAt?: string | null;
}

export function toInput(r: DetectionRule): DetectionRuleInput {
  return {
    name: r.name,
    description: r.description,
    severity: r.severity,
    enabled: r.enabled,
    match: r.match ?? {},
    payloadContains: r.payloadContains ?? [],
    payloadRegex: r.payloadRegex ?? [],
    matchAll: r.matchAll,
  };
}

/** The server's per-field messages from a 400, or null. Keys are paths such as `match.cidr`. */
export function fieldErrors(err: unknown): Record<string, string> | null {
  const data = (
    err as { response?: { status?: number; data?: { validationErrors?: Record<string, string> } } }
  )?.response;
  return data?.status === 400 && data.data?.validationErrors ? data.data.validationErrors : null;
}

export function errorMessage(err: unknown, fallback: string): string {
  return (
    (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? fallback
  );
}

export const detectionRulesService = {
  list: async (): Promise<DetectionRule[]> =>
    (await apiClient.get<DetectionRule[]>(API_ENDPOINTS.DETECTION_RULES)).data,
  /** Every rule that labels one capture: the global ones and its own (#925 phase 3). */
  listForFile: async (fileId: string): Promise<DetectionRule[]> =>
    (await apiClient.get<DetectionRule[]>(API_ENDPOINTS.DETECTION_RULES, { params: { fileId } }))
      .data,
  listCapture: async (fileId: string): Promise<DetectionRule[]> =>
    (await apiClient.get<DetectionRule[]>(API_ENDPOINTS.CAPTURE_DETECTION_RULES(fileId))).data,
  createForCapture: async (fileId: string, rule: DetectionRuleInput): Promise<DetectionRule> =>
    (await apiClient.post<DetectionRule>(API_ENDPOINTS.CAPTURE_DETECTION_RULES(fileId), rule)).data,
  /** Copies a capture rule up to a global one; keepOriginal false removes the capture rule. */
  promote: async (id: string, keepOriginal: boolean): Promise<DetectionRule> =>
    (
      await apiClient.post<DetectionRule>(API_ENDPOINTS.DETECTION_RULE_PROMOTIONS(id), {
        keepOriginal,
      })
    ).data,
  create: async (rule: DetectionRuleInput): Promise<DetectionRule> =>
    (await apiClient.post<DetectionRule>(API_ENDPOINTS.DETECTION_RULES, rule)).data,
  update: async (id: string, rule: DetectionRuleInput): Promise<DetectionRule> =>
    (await apiClient.put<DetectionRule>(API_ENDPOINTS.DETECTION_RULE(id), rule)).data,
  remove: async (id: string): Promise<void> => {
    await apiClient.delete(API_ENDPOINTS.DETECTION_RULE(id));
  },
  exportYaml: async (): Promise<Blob> =>
    (await apiClient.get(API_ENDPOINTS.DETECTION_RULES_EXPORT, { responseType: 'blob' }))
      .data as Blob,
  importYaml: async (content: string, mode: 'MERGE' | 'REPLACE'): Promise<RuleImportResult> =>
    (
      await apiClient.post<RuleImportResult>(API_ENDPOINTS.DETECTION_RULES_IMPORT, {
        content,
        mode,
      })
    ).data,
  status: async (): Promise<RuleSyncStatus> =>
    (await apiClient.get<RuleSyncStatus>(API_ENDPOINTS.DETECTION_RULES_STATUS)).data,
  fileStatus: async (fileId: string): Promise<RuleSyncStatus> =>
    (await apiClient.get<RuleSyncStatus>(API_ENDPOINTS.FILE_RULE_STATUS(fileId))).data,
  /** Starts Re-apply for one capture, or every out-of-date one. Returns the running job if one is. */
  startReapply: async (fileId?: string): Promise<ReapplyJob> =>
    (await apiClient.post<ReapplyJob>(API_ENDPOINTS.RULE_REAPPLY_JOBS, fileId ? { fileId } : {}))
      .data,
  getJob: async (id: string): Promise<ReapplyJob> =>
    (await apiClient.get<ReapplyJob>(API_ENDPOINTS.RULE_REAPPLY_JOB(id))).data,
  recentJobs: async (): Promise<ReapplyJob[]> =>
    (await apiClient.get<ReapplyJob[]>(API_ENDPOINTS.RULE_REAPPLY_JOBS)).data,
};
