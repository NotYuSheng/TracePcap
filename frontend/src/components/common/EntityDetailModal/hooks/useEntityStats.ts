import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import type { EntityType } from '@/features/notes/services/entityNotesService';
import type { EntityStats } from '../types';

interface ConvRow {
  srcIp: string;
  dstIp: string;
  packetCount: number;
  totalBytes: number;
}

interface ConvApiResponse {
  data: ConvRow[];
  total: number;
}

/**
 * Aggregate stats (conversation/packet/byte totals + top peer IPs) for
 * APPLICATION/PROTOCOL entities, derived from the conversations API.
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
    const param = entityType === 'APPLICATION' ? `apps=${encodeURIComponent(entityKey)}` : `l7Protocols=${encodeURIComponent(entityKey)}`;
    apiClient
      .get<ConvApiResponse>(`/conversations/${fileId}?${param}&pageSize=500&page=1`)
      .then(res => {
        if (!active) return;
        const rows = res.data.data;
        const total = res.data.total;
        const packets = rows.reduce((s, r) => s + r.packetCount, 0);
        const bytes = rows.reduce((s, r) => s + r.totalBytes, 0);
        // Aggregate bytes per peer IP
        const peerBytes = new Map<string, number>();
        for (const r of rows) {
          peerBytes.set(r.srcIp, (peerBytes.get(r.srcIp) ?? 0) + r.totalBytes);
          peerBytes.set(r.dstIp, (peerBytes.get(r.dstIp) ?? 0) + r.totalBytes);
        }
        const topPeers = Array.from(peerBytes.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([ip, b]) => ({ ip, bytes: b }));
        setStats({ conversationCount: total, packetCount: packets, totalBytes: bytes, topPeers });
      })
      .catch(() => { if (active) setStatsError('Failed to load details'); })
      .finally(() => { if (active) setStatsLoading(false); });
    return () => { active = false; };
  }, [fileId, entityType, entityKey]);

  return { stats, statsLoading, statsError };
}
