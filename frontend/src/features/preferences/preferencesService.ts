import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { ThemeMode } from '@/store';
import type { NodeLabelConfig } from '@/store/slices/nodeLabelSlice';

/**
 * Personal preferences (#915 phase 2). Null means "the app default". With login off, `shared` is
 * true: everyone using the install reads and updates the same set.
 */
export interface Preferences {
  themeMode?: ThemeMode | null;
  nodeLabelConfig?: NodeLabelConfig | null;
  conversationColumns?: string[] | null;
  shared?: boolean;
}

export const preferencesService = {
  get: async (): Promise<Preferences> => (await apiClient.get<Preferences>(API_ENDPOINTS.PREFERENCES)).data,
  put: async (p: Preferences): Promise<Preferences> =>
    (await apiClient.put<Preferences>(API_ENDPOINTS.PREFERENCES, p)).data,
};
