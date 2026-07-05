import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { EntityType } from '@/features/notes/services/entityNotesService';
import type { EntityStats } from '../types';

/** Server-computed aggregate stats for an APPLICATION/PROTOCOL entity (#436). */
interface EntityStatsApiResponse {
  conversationCount: number;
  packetCount: number;
  totalBytes: number;
  topPeers: { ip: string; bytes: number }[];
}

/**
 * Aggregate stats (conversation/packet/byte totals + top peer IPs) for
 * APPLICATION/PROTOCOL entities. The backend aggregates across ALL matching
 * conversations, so the numbers stay internally consistent regardless of
 * conversation count and the client never fans out page-by-page (#436).
 */
export function useEntityStats(entityType: EntityType, entityKey: string, fileId: string) {
  const [stats, setStats] = useState<EntityStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(false);
  const [statsError, setStatsError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    // Reset so a previous entity's stats/flags can't leak when the modal is reused.
    setStats(null);
    setStatsLoading(false);
    setStatsError(null);
    if (!fileId || (entityType !== 'APPLICATION' && entityType !== 'PROTOCOL')) return;
    setStatsLoading(true);
    const param = entityType === 'APPLICATION' ? 'app' : 'l7Protocol';
    apiClient
      .get<EntityStatsApiResponse>(
        `${API_ENDPOINTS.ENTITY_STATS(fileId)}?${param}=${encodeURIComponent(entityKey)}`
      )
      .then(res => {
        if (!active) return;
        const d = res.data;
        setStats({
          conversationCount: d.conversationCount,
          packetCount: d.packetCount,
          totalBytes: d.totalBytes,
          topPeers: d.topPeers,
        });
      })
      .catch(() => { if (active) setStatsError('Failed to load details'); })
      .finally(() => { if (active) setStatsLoading(false); });
    return () => { active = false; };
  }, [fileId, entityType, entityKey]);

  return { stats, statsLoading, statsError };
}
