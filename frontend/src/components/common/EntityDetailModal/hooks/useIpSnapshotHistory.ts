import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import { insightsService } from '@/features/insights/services/insightsService';
import type { EntityType } from '@/features/notes/services/entityNotesService';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import type { HostClassification, IpSnapshotEntry } from '../types';

/**
 * Per-snapshot history for an IP or DEVICE (MAC) across a Monitor network's snapshots (only the
 * snapshots where the entity actually appeared).
 *
 * <p>For an <b>IP</b>: per snapshot, the MAC(s) that claimed it (>1 ⇒ overlap conflict), device
 * type, protocols and role. For a <b>DEVICE</b> (MAC): the IP(s) that MAC used (>1 ⇒ the MAC claimed
 * multiple addresses), device type, protocols and role. The two are mirror images built from the same
 * {@code ip_mac_observations} data.
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
    if ((entityType !== 'IP' && entityType !== 'DEVICE') || !snapshots || snapshots.length === 0) return;
    const isDevice = entityType === 'DEVICE';
    const macKey = entityKey.toLowerCase();
    // `active` guards against stale responses applying after the entity changes/unmounts.
    let active = true;
    setIpHistoryLoading(true);
    const sorted = [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder);
    Promise.all(
      sorted.map(snap =>
        apiClient
          .get<HostClassification[]>(`/files/${snap.fileId}/host-classifications`)
          .then(r => ({
            snap,
            host: isDevice
              ? r.data.find(h => (h.mac ?? '').toLowerCase() === macKey) ?? null
              : r.data.find(h => h.ip === entityKey) ?? null,
          }))
          .catch(() => ({ snap, host: null }))
      )
    ).then(results => {
      if (!active) return;
      // Keep snapshots where the entity appeared. A device may appear only in observations (an IP it
      // claimed via ARP) without a host_classifications row, so for DEVICE we resolve presence below.
      const candidates = isDevice ? results : results.filter(r => r.host !== null);
      if (candidates.length === 0) { setIpSnapHistory([]); setIpHistoryLoading(false); return; }
      return Promise.all(
        candidates.map(({ snap, host }) =>
          Promise.all([
            // ip-mac-observations for the whole file — used both to invert (MAC→IPs for a device)
            // and to find the MACs claiming an IP.
            apiClient
              .get<{ ip: string; macs: string[] }[]>(`/files/${snap.fileId}/ip-mac-observations`)
              .then(r => r.data)
              .catch(() => [] as { ip: string; macs: string[] }[]),
            insightsService.getNodeRole(isDevice ? 'DEVICE' : 'IP', entityKey, snap.fileId).catch(() => null),
          ]).then(([obs, role]) => {
            // Device: the IPs this MAC claimed in the snapshot. IP: the MACs that claimed this IP.
            const ips = isDevice
              ? obs.filter(o => o.macs.some(m => m.toLowerCase() === macKey)).map(o => o.ip)
              : [];
            const macs = isDevice
              ? host?.mac ? [host.mac] : []
              : (obs.find(o => o.ip === entityKey)?.macs ?? (host?.mac ? [host.mac] : []));
            // The IP whose conversations we summarise: the entity itself (IP), or the device's IP.
            const convIp = isDevice ? (ips[0] ?? host?.ip ?? null) : entityKey;
            return { snap, host, role, ips, macs, convIp };
          })
        )
      ).then(async partials => {
        if (!active) return;
        // For DEVICE, drop snapshots where the MAC neither classified nor claimed any IP.
        const seen = isDevice ? partials.filter(p => p.host !== null || p.ips.length > 0) : partials;
        const entries = await Promise.all(
          seen.map(async ({ snap, host, role, ips, macs, convIp }) => {
            const conv = convIp
              ? await apiClient
                  .get<{ data: { appName: string | null; tsharkProtocol: string | null }[] }>(
                    `/conversations/${snap.fileId}?ip=${encodeURIComponent(convIp)}&pageSize=10000`
                  )
                  .catch(() => ({ data: { data: [] } }))
              : { data: { data: [] } };
            return {
              snap,
              host,
              apps: [...new Set((conv?.data?.data ?? []).map(c => c.appName).filter(Boolean) as string[])].sort(),
              protocols: [...new Set((conv?.data?.data ?? []).map(c => c.tsharkProtocol).filter(Boolean) as string[])].sort(),
              roleLabel: role?.roleLabel ?? null,
              roleOrigin: role?.origin ?? null,
              roleStale: !!role?.staleSince,
              macs,
              ips,
            };
          })
        );
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
