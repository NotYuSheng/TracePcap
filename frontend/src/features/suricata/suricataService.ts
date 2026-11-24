import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** Mirrors SuricataStatusDto (#600): the IDS engine and the age of the ruleset behind its alerts. */
export interface SuricataStatus {
  engineVersion?: string | null;
  /** "built-in" (baked into the image) or "imported" (from the import folder). */
  source: 'built-in' | 'imported' | string;
  /** ISO date (yyyy-mm-dd), or null when unknown. */
  rulesetDate?: string | null;
  ageDays?: number | null;
  stale: boolean;
  staleAfterDays: number;
  ruleCount: number;
  /** Rules the engine reported loading on its last start; null until it has run (#1269). */
  loadedRuleCount?: number | null;
  /** Rules Suricata reported failing to parse on its last start; null until it has run. */
  failedRuleCount?: number | null;
  importDir?: string | null;
  /** Why the last bundle in the import folder wasn't used, or null. */
  importError?: string | null;
}

export const suricataService = {
  getStatus: async (): Promise<SuricataStatus> =>
    (await apiClient.get<SuricataStatus>(API_ENDPOINTS.SYSTEM_SURICATA)).data,
};
