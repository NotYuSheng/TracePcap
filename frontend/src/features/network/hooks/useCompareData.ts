import { useState, useEffect } from 'react';
import { conversationService } from '@/features/conversation/services/conversationService';
import { networkService } from '../services/networkService';
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
    hostClassifications
  );
}

export function useCompareData(
  fileIds: string[],
  labels: string[]
): UseCompareDataReturn {
  const [mergedNodes, setMergedNodes] = useState<GraphNode[]>([]);
  const [mergedEdges, setMergedEdges] = useState<GraphEdge[]>([]);
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

        setMergedNodes(merged.nodes);
        setMergedEdges(merged.edges);
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

  return { mergedNodes, mergedEdges, perFileStats, labels, loading, error };
}
