import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** One deploy-time setting (#915 phase 1). Mirrors SystemSettingDto. */
export interface SystemSetting {
  key: string;
  label: string;
  group: 'INFRASTRUCTURE' | 'MEMORY' | 'POLICY';
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
  lockedReason?: string | null;
  description?: string | null;
}

export const settingsService = {
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
