import { clusterApi } from '@/features/cluster/services/clusterApi';
import { customPrivateRangeService } from '@/features/cluster/services/customPrivateRangeService';
import type { CustomPrivateRange } from '@/features/cluster/types/customPrivateRange.types';
import { dnsNamesByIp } from '@/features/network/services/networkGroups';
import {
  EMPTY_MAP_EDITS,
  networkMapEditsService,
  type NetworkMapEdits,
} from '@/features/network/services/networkMapEdits';
import {
  networkSegmentService,
  unansweredNames,
  type NetworkSegment,
} from '@/features/networkSegments/networkSegmentService';
import type { GraphNode } from '@/features/network/types';

export interface Grouping {
  networkSegments: NetworkSegment[];
  customPrivateRanges: CustomPrivateRange[];
  dnsNames?: Map<string, string>;
  mapEdits: NetworkMapEdits;
  askedNames: Map<string, string>;
}

/** What the Network tab groups by, each part best-effort as it is there. */
export async function loadGrouping(fileId: string): Promise<Grouping> {
  const [segments, ranges, dns, edits] = await Promise.all([
    networkSegmentService.get(fileId).catch(() => null),
    customPrivateRangeService.list().catch(() => [] as CustomPrivateRange[]),
    clusterApi
      .getDnsServers(fileId)
      .then(servers => Promise.all(servers.map(s => clusterApi.getDnsQueryLog(fileId, s.serverIp))))
      .then(logs => dnsNamesByIp(logs))
      .catch(() => undefined),
    networkMapEditsService.get(fileId).catch(() => EMPTY_MAP_EDITS),
  ]);
  return {
    networkSegments: segments?.segments ?? [],
    customPrivateRanges: ranges,
    dnsNames: dns,
    mapEdits: edits,
    askedNames: segments ? unansweredNames(segments) : new Map(),
  };
}

/** The names clients nobody answered asked under, on their MAC-only nodes, as the Network tab does. */
export function withAskedNames(nodes: GraphNode[], asked: Map<string, string>): GraphNode[] {
  if (asked.size === 0) return nodes;
  return nodes.map(n => {
    const name = n.data.isL2 ? asked.get(n.id.toLowerCase()) : undefined;
    if (!name || n.data.hostname) return n;
    return { ...n, label: name, data: { ...n.data, hostname: name, hostnameSource: 'dhcp' as const } };
  });
}

