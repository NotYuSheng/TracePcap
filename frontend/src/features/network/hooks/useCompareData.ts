import { useState, useEffect, useMemo } from 'react';
import { conversationService } from '@/features/conversation/services/conversationService';
import { networkService, selectSignificantNodes } from '../services/networkService';
import { mergeGraphs } from '../services/mergeGraphs';
import type { GraphNode, GraphEdge } from '../types';

const MAX_CONVERSATIONS = 500;

export interface CompareStats {
  totalNodes: number;
  totalEdges: number;
  totalPackets: number;
  totalBytes: number;
}

export interface FileStats {
  label: string;
  stats: CompareStats;
}

export interface UseCompareDataReturn {
  mergedNodes: GraphNode[];
  mergedEdges: GraphEdge[];
  totalNodes: number;
  hiddenNodes: number;
  perFileStats: FileStats[];
  labels: string[];
  loading: boolean;
  error: string | null;
}

async function fetchGraphForFile(fileId: string) {
  const [response, hostClassifications] = await Promise.all([
    conversationService.getConversations(fileId, {
      ip: '',
      port: '',
      payloadContains: '',
      protocols: [],
      l7Protocols: [],
      apps: [],
      categories: [],
      hasRisks: false,
      fileTypes: [],
      riskTypes: [],
      customSignatures: [],
      deviceTypes: [],
      countries: [],
      sortBy: '',
      sortDir: 'asc',
      page: 1,
      pageSize: 10000,
    }),
    conversationService.getHostClassifications(fileId).catch(() => undefined),
  ]);

  return networkService.buildNetworkGraph(
    response.data,
    undefined,
    MAX_CONVERSATIONS,
    hostClassifications,
    0 // no per-file limit — significance filtering is applied after merge
  );
}

export function useCompareData(
  fileIds: string[],
  labels: string[],
  nodeLimit: number
): UseCompareDataReturn {
  const [allMergedNodes, setAllMergedNodes] = useState<GraphNode[]>([]);
  const [allMergedEdges, setAllMergedEdges] = useState<GraphEdge[]>([]);
  const [perFileStats, setPerFileStats] = useState<FileStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Stable keys to avoid re-fetching on every render
  const fileIdsKey = fileIds.join(',');
  const labelsKey = labels.join(',');

  useEffect(() => {
    let active = true;

    const run = async () => {
      // Wait until labels are resolved — empty labels means filenames haven't loaded yet
      if (labels.length === 0) return;

      setLoading(true);
      setError(null);

      try {
        const graphs = await Promise.all(fileIds.map(id => fetchGraphForFile(id)));

        if (!active) return;

        const merged = mergeGraphs(graphs, labels);

        setAllMergedNodes(merged.nodes);
        setAllMergedEdges(merged.edges);
        setPerFileStats(
          graphs.map((g, i) => ({
            label: labels[i],
            stats: {
              totalNodes: g.stats.totalNodes,
              totalEdges: g.stats.totalEdges,
              totalPackets: g.stats.totalPackets,
              totalBytes: g.stats.totalBytes,
            },
          }))
        );
      } catch (err) {
        if (!active) return;
        setError(err instanceof Error ? err.message : 'Failed to load comparison data');
      } finally {
        if (active) setLoading(false);
      }
    };

    run();
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileIdsKey, labelsKey]);

  const { mergedNodes, mergedEdges, hiddenNodes } = useMemo(() => {
    const { significantNodes, hiddenCount } = selectSignificantNodes(
      allMergedNodes,
      allMergedEdges,
      nodeLimit
    );
    const sigIds = new Set(significantNodes.map(n => n.id));
    const visibleEdges = allMergedEdges.filter(
      e => sigIds.has(e.source) && sigIds.has(e.target)
    );
    return { mergedNodes: significantNodes, mergedEdges: visibleEdges, hiddenNodes: hiddenCount };
  }, [allMergedNodes, allMergedEdges, nodeLimit]);

  return {
    mergedNodes,
    mergedEdges,
    totalNodes: allMergedNodes.length,
    hiddenNodes,
    perFileStats,
    labels,
    loading,
    error,
  };
}
