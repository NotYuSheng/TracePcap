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
export interface DetectionRule extends DetectionRuleInput {
  id: string;
  scope: 'GLOBAL' | 'NETWORK' | 'CAPTURE';
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
};
