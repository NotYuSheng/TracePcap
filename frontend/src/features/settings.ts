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
  editable: boolean;
  lockedReason?: string | null;
  description?: string | null;
}

export const settingsService = {
  getSystemSettings: async (): Promise<SystemSetting[]> =>
    (await apiClient.get<SystemSetting[]>(API_ENDPOINTS.SYSTEM_SETTINGS)).data,
};
