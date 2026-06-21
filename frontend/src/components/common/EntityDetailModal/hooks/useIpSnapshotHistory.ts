import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import type { EntityType } from '@/features/notes/services/entityNotesService';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import type { HostClassification, IpSnapshotEntry } from '../types';

/**
 * Per-snapshot MAC/device/protocol history for an IP across a Monitor network's
 * snapshots (only the snapshots where the IP actually appeared).
 */
export function useIpSnapshotHistory(entityType: EntityType, entityKey: string, snapshots?: NetworkSnapshot[]) {
  const [ipSnapHistory, setIpSnapHistory] = useState<IpSnapshotEntry[]>([]);
  const [ipHistoryLoading, setIpHistoryLoading] = useState(false);

  useEffect(() => {
    // Reset so a previous entity's history can't leak when the modal is reused.
    setIpSnapHistory([]);
    if (entityType !== 'IP' || !snapshots || snapshots.length === 0) return;
    // `active` guards against stale responses applying after the entity changes/unmounts.
    let active = true;
    setIpHistoryLoading(true);
    const sorted = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);
    Promise.all(
      sorted.map(snap =>
        apiClient
          .get<HostClassification[]>(`/files/${snap.fileId}/host-classifications`)
          .then(r => ({ snap, host: r.data.find(h => h.ip === entityKey) ?? null }))
          .catch(() => ({ snap, host: null }))
      )
    ).then(results => {
      if (!active) return;
      // Only keep snapshots where this IP appeared
      const seen = results.filter(r => r.host !== null);
      if (seen.length === 0) { setIpSnapHistory([]); setIpHistoryLoading(false); return; }
      // Fetch conversations for protocols/apps per seen snapshot
      return Promise.all(
        seen.map(({ snap, host }) =>
          apiClient
            .get<{ data: { appName: string | null; tsharkProtocol: string | null }[] }>(
              `/conversations/${snap.fileId}?ip=${encodeURIComponent(entityKey)}&pageSize=10000`
            )
            .then(r => ({
              snap,
              host,
              apps: [...new Set(r.data.data.map(c => c.appName).filter(Boolean) as string[])].sort(),
              protocols: [...new Set(r.data.data.map(c => c.tsharkProtocol).filter(Boolean) as string[])].sort(),
            }))
            .catch(() => ({ snap, host, apps: [], protocols: [] }))
        )
      ).then(entries => {
        if (!active) return;
        setIpSnapHistory(entries);
        setIpHistoryLoading(false);
      });
    }).catch(() => { if (active) setIpHistoryLoading(false); });
    return () => { active = false; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityType, entityKey, snapshots?.map(s => s.id).join(',')]);

  return { ipSnapHistory, ipHistoryLoading };
}
