import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';

/** "Keep N days longer" choices. */
export const EXTEND_DAYS = [1, 7, 30];
/** The furthest a capture can be kept by date (the backend refuses more); past it, keep it forever. */
export const MAX_KEEP_MS = 366 * 24 * 3600_000;

/**
 * The new deletion time for "keep N days longer": N days past whichever is later, now or when it
 * would be deleted, so extending twice adds up. Capped at the backend's limit.
 */
export function extendedTo(current: number | null, days: number, now: number): number {
  const from = Math.max(now, current ?? now);
  return Math.min(from + days * 24 * 3600_000, now + MAX_KEEP_MS - 60_000);
}

/** A capture's own deletion time, from the API's date form; null when the retention window applies. */
export function ownExpiry(expiresAt: string | number | number[] | null | undefined): number | null {
  if (expiresAt == null) return null;
  if (typeof expiresAt === 'number') return expiresAt;
  return parseDateTime(expiresAt);
}

export const captureKeepService = {
  /** Marks or unmarks one of the caller's favourites (personal, per account). */
  setFavourite: async (fileId: string, on: boolean): Promise<void> => {
    if (on) await apiClient.put(API_ENDPOINTS.FILE_FAVOURITE(fileId));
    else await apiClient.delete(API_ENDPOINTS.FILE_FAVOURITE(fileId));
  },

  /**
   * When a capture is deleted: kept forever, kept until `expiresAt` (epoch ms), or, with neither,
   * back to the retention window.
   */
  setExpiry: async (
    fileId: string,
    change: { keepForever: boolean; expiresAt?: number | null }
  ): Promise<{ keepForever: boolean; expiresAt: number | null }> => {
    const r = await apiClient.put<{ keepForever: boolean; expiresAt?: string | number[] | null }>(
      API_ENDPOINTS.FILE_EXPIRY(fileId),
      { keepForever: change.keepForever, expiresAt: change.expiresAt ?? null }
    );
    return { keepForever: r.data.keepForever, expiresAt: ownExpiry(r.data.expiresAt) };
  },
};
