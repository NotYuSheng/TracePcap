import { useEffect, useMemo, useState } from 'react';
import type { AnalysisSummary } from '@/types';
import { useNetworkData } from './useNetworkData';
import { buildGroupTree, dnsNamesByIp, type GroupNode } from '../services/networkGroups';
import {
  EMPTY_MAP_EDITS,
  groupingEdits,
  networkMapEditsService,
  type NetworkMapEdits,
} from '../services/networkMapEdits';
import {
  networkSegmentService,
  type NetworkSegment,
} from '@/features/networkSegments/networkSegmentService';
import { customPrivateRangeService } from '@/features/cluster/services/customPrivateRangeService';
import type { CustomPrivateRange } from '@/features/cluster/types/customPrivateRange.types';
import { clusterApi } from '@/features/cluster/services/clusterApi';

/** Devices in a group, at any depth. */
export function groupSize(g: GroupNode): number {
  return g.nodeIds.length + g.children.reduce((n, c) => n + groupSize(c), 0);
}

/**
 * The network map's own groups for a capture (segments, internal ranges, DNS names and the
 * analyst's map edits), so the overview's "Where the hosts are" says what the map shows.
 */
export function useHostGroups(
  fileId: string,
  summary?: AnalysisSummary
): { tops: GroupNode[]; loading: boolean } {
  const { nodes, loading } = useNetworkData(fileId, summary);
  const [segments, setSegments] = useState<NetworkSegment[]>([]);
  const [ranges, setRanges] = useState<CustomPrivateRange[]>([]);
  const [dnsNames, setDnsNames] = useState<Map<string, string> | undefined>(undefined);
  const [edits, setEdits] = useState<NetworkMapEdits>(EMPTY_MAP_EDITS);
  useEffect(() => {
    let live = true;
    networkSegmentService
      .get(fileId)
      .then(r => live && setSegments(r.segments))
      .catch(() => {});
    customPrivateRangeService
      .list()
      .then(r => live && setRanges(r))
      .catch(() => {});
    clusterApi
      .getDnsServers(fileId)
      .then(servers => Promise.all(servers.map(s => clusterApi.getDnsQueryLog(fileId, s.serverIp))))
      .then(logs => live && setDnsNames(dnsNamesByIp(logs)))
      .catch(() => {});
    networkMapEditsService
      .get(fileId)
      .then(e => live && setEdits(e))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [fileId]);
  const tops = useMemo(
    () =>
      buildGroupTree(nodes, { segments, customRanges: ranges, dnsNames, ...groupingEdits(edits) }),
    [nodes, segments, ranges, dnsNames, edits]
  );
  return { tops, loading };
}
