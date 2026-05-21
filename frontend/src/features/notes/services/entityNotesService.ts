import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

export type EntityType = 'IP' | 'DEVICE' | 'PROTOCOL' | 'APPLICATION';

export interface EntityNote {
  entityType: EntityType;
  entityKey: string;
  note: string;
  createdAt: string;
  updatedAt: string;
}

export interface EntityHistoryEntry {
  fileId: string;
  fileName: string;
  startTime: string | null;
  endTime: string | null;
  packetCount: number | null;
  totalBytes: number | null;
}

export const entityNotesService = {
  async getNote(entityType: EntityType, entityKey: string): Promise<EntityNote | null> {
    try {
      const res = await apiClient.get<EntityNote>(
        API_ENDPOINTS.ENTITY_NOTE(entityType, entityKey)
      );
      return res.data;
    } catch (err: unknown) {
      if ((err as { response?: { status?: number } })?.response?.status === 204) return null;
      return null;
    }
  },

  async upsertNote(entityType: EntityType, entityKey: string, note: string): Promise<EntityNote> {
    const res = await apiClient.put<EntityNote>(API_ENDPOINTS.ENTITY_NOTE_UPSERT, {
      entityType,
      entityKey,
      note,
    });
    return res.data;
  },

  async deleteNote(entityType: EntityType, entityKey: string): Promise<void> {
    await apiClient.delete(API_ENDPOINTS.ENTITY_NOTE(entityType, entityKey));
  },

  async getHistory(
    entityType: EntityType,
    entityKey: string
  ): Promise<EntityHistoryEntry[]> {
    const res = await apiClient.get<EntityHistoryEntry[]>(
      API_ENDPOINTS.ENTITY_NOTE_HISTORY(entityType, entityKey)
    );
    return res.data;
  },
};
