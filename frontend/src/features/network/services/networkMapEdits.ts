import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** The analyst's edits to a capture's network map (#649). Mirrors NetworkMapEdits. */
export interface NetworkMapEdits {
  /** Device (graph node id) → the group it was moved to. */
  placements: Record<string, string>;
}

export const networkMapEditsService = {
  get: async (fileId: string): Promise<NetworkMapEdits> =>
    (await apiClient.get<{ edits: NetworkMapEdits }>(API_ENDPOINTS.FILE_NETWORK_MAP_EDITS(fileId))).data.edits,
  save: async (fileId: string, edits: NetworkMapEdits): Promise<NetworkMapEdits> =>
    (await apiClient.put<{ edits: NetworkMapEdits }>(API_ENDPOINTS.FILE_NETWORK_MAP_EDITS(fileId), edits)).data.edits,
  reset: async (fileId: string): Promise<void> => {
    await apiClient.delete(API_ENDPOINTS.FILE_NETWORK_MAP_EDITS(fileId));
  },
};
