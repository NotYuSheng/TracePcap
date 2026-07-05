import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import { insightsService } from '@/features/insights/services/insightsService';
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
  const [reloadKey, setReloadKey] = useState(0);
  const reload = () => setReloadKey(k => k + 1);

  useEffect(() => {
    // Reset so a previous entity's history can't leak when the modal is reused.
    setIpSnapHistory([]);
    setIpHistoryLoading(false);
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
          Promise.all([
            apiClient
              .get<{ data: { appName: string | null; tsharkProtocol: string | null }[] }>(
                `/conversations/${snap.fileId}?ip=${encodeURIComponent(entityKey)}&pageSize=10000`
              )
              .catch(() => ({ data: { data: [] } })),
            insightsService.getNodeRole('IP', entityKey, snap.fileId).catch(() => null),
            // Distinct MACs observed for this IP in the snapshot — >1 means an overlap/conflict.
            apiClient
              .get<{ ip: string; macs: string[] }[]>(`/files/${snap.fileId}/ip-mac-observations`)
              .then(r => r.data.find(o => o.ip === entityKey)?.macs ?? [])
              .catch(() => [] as string[]),
          ]).then(([conv, role, macs]) => ({
            snap,
            host,
            apps: [...new Set((conv?.data?.data ?? []).map(c => c.appName).filter(Boolean) as string[])].sort(),
            protocols: [...new Set((conv?.data?.data ?? []).map(c => c.tsharkProtocol).filter(Boolean) as string[])].sort(),
            roleLabel: role?.roleLabel ?? null,
            roleOrigin: role?.origin ?? null,
            roleStale: !!role?.staleSince,
            // Fall back to the single classification MAC if no observations were recorded (pre-#461 files).
            macs: macs.length > 0 ? macs : host?.mac ? [host.mac] : [],
          }))
        )
      ).then(entries => {
        if (!active) return;
        setIpSnapHistory(entries);
        setIpHistoryLoading(false);
      });
    }).catch(() => { if (active) setIpHistoryLoading(false); });
    return () => { active = false; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityType, entityKey, snapshots?.map(s => s.id)?.join(','), reloadKey]);

  return { ipSnapHistory, ipHistoryLoading, reload };
}
