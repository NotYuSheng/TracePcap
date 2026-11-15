import { useEffect, useMemo, useState } from 'react';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { conversationService } from '@/features/conversation/services/conversationService';
import { isPrivateIp } from '@/utils/ipClassification';
import type { GraphNode } from '@/features/network/types';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';

/** Every device of the capture before, not just the 50 the map draws. */
const ALL_NODES = 100_000;

/**
 * The local devices of the capture before that this capture no longer has, as that capture's graph
 * nodes (so they can be drawn, faded, where they were). The backend records no removal events.
 * A device counts as still here if either its MAC or its address is: one capture can know a MAC
 * where the other only saw the IP, and a device that only changed address hasn't left.
 */
export function useGoneDevices(
  networkId: string,
  snapshot: NetworkSnapshot,
  previous: NetworkSnapshot | null
): GraphNode[] {
  const before = useNetworkData(previous?.fileId ?? '', undefined, ALL_NODES, networkId);
  const [present, setPresent] = useState<{ fileId: string; macs: Set<string>; ips: Set<string> } | null>(null);
  useEffect(() => {
    if (!previous) return;
    let alive = true;
    conversationService
      .getHostClassifications(snapshot.fileId)
      .then(hosts => {
        if (!alive) return;
        setPresent({
          fileId: snapshot.fileId,
          macs: new Set(hosts.map(h => h.mac).filter((m): m is string => !!m)),
          ips: new Set(hosts.map(h => h.ip)),
        });
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [snapshot.fileId, previous]);

  return useMemo(() => {
    if (!previous || present?.fileId !== snapshot.fileId) return [];
    return [...before.nodes, ...before.hiddenNodesList].filter(
      n =>
        (n.data.isL2 || isPrivateIp(n.data.ip)) &&
        !(n.data.mac && present.macs.has(n.data.mac)) &&
        !(n.data.ip && present.ips.has(n.data.ip))
    );
  }, [previous, present, snapshot.fileId, before.nodes, before.hiddenNodesList]);
}
