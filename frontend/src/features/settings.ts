import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** One deploy-time setting (#915 phase 1). Mirrors SystemSettingDto. */
export interface SystemSetting {
  key: string;
  label: string;
  group: 'INFRASTRUCTURE' | 'MEMORY' | 'POLICY' | 'LLM';
  value?: string | null;
  defaultValue?: string | null;
  secret: boolean;
  set: boolean;
  /** Whether the caller can change it here (#915 phase 5). */
  editable: boolean;
  /** Whether it can be changed in the app at all (retention, detection thresholds). */
  inAppEditable?: boolean;
  /** The deployment's value, used when not overridden. */
  deployValue?: string | null;
  /** Whether an in-app override is in effect. */
  overridden?: boolean;
  /** When a change takes effect. */
  takesEffect?: string | null;
  /** How an in-app-editable setting is entered. */
  type?: 'INT' | 'RATIO' | 'DECIMAL' | 'TEXT' | 'URL' | 'SECRET' | 'CHOICE' | null;
  /** For a CHOICE setting, the allowed values. */
  choices?: string[] | null;
  lockedReason?: string | null;
  description?: string | null;
}

/** One step of the LLM connection test. */
export interface LlmTestStep {
  key: 'reach' | 'key' | 'model' | 'reply';
  label: string;
  status: 'OK' | 'FAIL' | 'SKIPPED';
  detail: string;
  ms?: number | null;
}

export interface LlmTestResult {
  ok: boolean;
  steps: LlmTestStep[];
  /** The server's models, for picking one. */
  models: string[];
  baseUrl: string;
  model: string;
}

export const settingsService = {
  /**
   * Tests the LLM connection step by step. Blank fields use the current settings, so `{}` tests
   * what's in effect and e.g. `{ model }` tests a change before saving it.
   */
  testLlm: async (candidate: { baseUrl?: string; apiKey?: string; model?: string } = {}): Promise<LlmTestResult> =>
    (await apiClient.post<LlmTestResult>(API_ENDPOINTS.LLM_TEST, candidate)).data,
  getSystemSettings: async (): Promise<SystemSetting[]> =>
    (await apiClient.get<SystemSetting[]>(API_ENDPOINTS.SYSTEM_SETTINGS)).data,
  /** Overrides an editable policy setting (audited). Setting the deployment's value resets it. */
  setSystemSetting: async (key: string, value: string): Promise<SystemSetting> =>
    (await apiClient.put<SystemSetting>(API_ENDPOINTS.SYSTEM_SETTING(key), { value })).data,
  /** Removes an override, so the deployment's value applies again (audited). */
  resetSystemSetting: async (key: string): Promise<void> => {
    await apiClient.delete(API_ENDPOINTS.SYSTEM_SETTING(key));
  },
};
