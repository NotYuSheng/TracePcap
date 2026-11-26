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
  key: 'reach' | 'key' | 'model' | 'reply' | 'tools' | 'capacity';
  label: string;
  status: 'OK' | 'WARN' | 'FAIL' | 'SKIPPED';
  detail: string;
  ms?: number | null;
}

/** A model the LLM server offers, with its context length when the server says. */
export interface LlmModelOption {
  id: string;
  contextLength?: number | null;
}

export interface LlmModelList {
  ok: boolean;
  baseUrl: string;
  models: LlmModelOption[];
  /** Why they couldn't be listed, or that the server doesn't list them. */
  detail?: string | null;
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
  /** The server's models for these values (blank = current), to pick one before saving. */
  listLlmModels: async (candidate: { baseUrl?: string; apiKey?: string } = {}): Promise<LlmModelList> =>
    (await apiClient.post<LlmModelList>(API_ENDPOINTS.LLM_MODELS, candidate)).data,
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
  /** Overrides several together, all or none (each audited): for settings that only work as a set. */
  setSystemSettings: async (values: Record<string, string>): Promise<SystemSetting[]> =>
    (await apiClient.patch<SystemSetting[]>(API_ENDPOINTS.SYSTEM_SETTINGS, { values })).data,
  /** Removes an override, so the deployment's value applies again (audited). */
  resetSystemSetting: async (key: string): Promise<void> => {
    await apiClient.delete(API_ENDPOINTS.SYSTEM_SETTING(key));
  },
};
