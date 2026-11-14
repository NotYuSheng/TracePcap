import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** The analyst's edits to a capture's network map (#649). Mirrors NetworkMapEdits. */
export interface NetworkMapEdits {
  /** Device (graph node id) → the group it was moved to. */
  placements: Record<string, string>;
  /** The analyst's own groups, each inside a group of the map. */
  groups: { id: string; name: string; parentId: string }[];
  /** Group id → the name the analyst gave it. */
  names: Record<string, string>;
  /** Group id → the analyst's note. */
  notes: Record<string, string>;
}

export const EMPTY_MAP_EDITS: NetworkMapEdits = { placements: {}, groups: [], names: {}, notes: {} };

/** Fills parts an older document doesn't have. */
export function normalizeMapEdits(e: Partial<NetworkMapEdits> | null | undefined): NetworkMapEdits {
  return { placements: e?.placements ?? {}, groups: e?.groups ?? [], names: e?.names ?? {}, notes: e?.notes ?? {} };
}

/** The grouping options for these edits. */
export function groupingEdits(e: NetworkMapEdits) {
  return { placements: e.placements, userGroups: e.groups, names: e.names, notes: e.notes };
}

export const networkMapEditsService = {
  get: async (fileId: string): Promise<NetworkMapEdits> =>
    normalizeMapEdits((await apiClient.get<{ edits: NetworkMapEdits }>(API_ENDPOINTS.FILE_NETWORK_MAP_EDITS(fileId))).data.edits),
  save: async (fileId: string, edits: NetworkMapEdits): Promise<NetworkMapEdits> =>
    normalizeMapEdits((await apiClient.put<{ edits: NetworkMapEdits }>(API_ENDPOINTS.FILE_NETWORK_MAP_EDITS(fileId), edits)).data.edits),
  reset: async (fileId: string): Promise<void> => {
    await apiClient.delete(API_ENDPOINTS.FILE_NETWORK_MAP_EDITS(fileId));
  },
};
