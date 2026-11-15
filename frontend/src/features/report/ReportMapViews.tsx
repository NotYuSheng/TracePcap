import { useEffect, useMemo, useRef } from 'react';
import { NetworkGraph } from '@/components/network/NetworkGraph/NetworkGraph';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import type { DeviceLink, GraphEdge, GraphNode } from '@/features/network/types';
import type { AnalysisSummary } from '@/types';
import { withAskedNames, type Grouping } from './reportMapGrouping';

/** The two ways the report's map is drawn: from nodes given, or from the whole capture. */
interface MapProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  deviceLinks?: DeviceLink[];
  grouping: Grouping;
  onReady: () => void;
  onEmpty: () => void;
}

export function GroupedMap({ nodes, edges, deviceLinks, grouping, onReady, onEmpty }: MapProps) {
  const named = useMemo(() => withAskedNames(nodes, grouping.askedNames), [nodes, grouping.askedNames]);
  const links = useMemo(() => {
    const ids = new Set(named.map(n => n.id));
    return (deviceLinks ?? []).filter(l => ids.has(l.from) && ids.has(l.to));
  }, [deviceLinks, named]);
  useEffect(() => {
    if (named.length === 0) onEmpty();
  }, [named.length, onEmpty]);
  if (named.length === 0) return null;
  return (
    <NetworkGraph
      nodes={named}
      edges={edges}
      layoutType="grouped"
      networkSegments={grouping.networkSegments}
      customPrivateRanges={grouping.customPrivateRanges}
      dnsNames={grouping.dnsNames}
      mapEdits={grouping.mapEdits}
      deviceLinks={links}
      onLayoutComplete={onReady}
      forceLight
    />
  );
}

interface WholeProps {
  fileId: string;
  summary?: AnalysisSummary;
  networkId?: string;
  grouping: Grouping;
  onReady: () => void;
  onEmpty: () => void;
  onError: (e: Error) => void;
}

export function WholeCaptureMap({ fileId, summary, networkId, grouping, onReady, onEmpty, onError }: WholeProps) {
  const { nodes, edges, deviceLinks, loading, error } = useNetworkData(fileId, summary, Infinity, networkId);
  const failed = useRef(false);
  useEffect(() => {
    if (error && !failed.current) {
      failed.current = true;
      onError(new Error(error));
    }
  }, [error, onError]);
  if (loading || error) return null;
  return (
    <GroupedMap
      nodes={nodes}
      edges={edges}
      deviceLinks={deviceLinks}
      grouping={grouping}
      onReady={onReady}
      onEmpty={onEmpty}
    />
  );
}

