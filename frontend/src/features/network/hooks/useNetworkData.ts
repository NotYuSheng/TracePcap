import { useState, useEffect } from 'react';
import { conversationService } from '@/features/conversation/services/conversationService';
import { networkService } from '../services/networkService';
import type { GraphNode, GraphEdge, NetworkStats } from '../types';

export const MAX_DIAGRAM_NODES = 50;
import type { AnalysisSummary } from '@/types';

interface UseNetworkDataReturn {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: NetworkStats;
  loading: boolean;
  error: string | null;
  refetch: () => void;
  hiddenNodes: number;
  hiddenNodesList: GraphNode[];
  crossEdges: GraphEdge[];
}

export const CONVERSATION_LIMIT_ENABLED =
  import.meta.env.VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT !== 'false';
const MAX_CONVERSATIONS = 500;

/**
 * Custom hook for fetching and transforming network data into graph format
 * Follows the same pattern as useAnalysisData
 * @param fileId - The file ID to fetch conversations for
 * @param analysisSummary - Optional analysis summary for anomaly detection
 */
export function useNetworkData(
  fileId: string,
  analysisSummary?: AnalysisSummary,
  maxNodes: number = MAX_DIAGRAM_NODES
): UseNetworkDataReturn {
  const maxConversations = CONVERSATION_LIMIT_ENABLED ? MAX_CONVERSATIONS : Infinity;
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [hiddenNodes, setHiddenNodes] = useState(0);
  const [hiddenNodesList, setHiddenNodesList] = useState<GraphNode[]>([]);
  const [crossEdges, setCrossEdges] = useState<GraphEdge[]>([]);
  const [stats, setStats] = useState<NetworkStats>({
    totalNodes: 0,
    totalEdges: 0,
    totalPackets: 0,
    totalBytes: 0,
    protocolBreakdown: {},
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    if (!fileId) {
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);

      // Fetch conversations from API
      // For network visualization, fetch all conversations (use large page size)
      const response = await conversationService.getConversations(fileId, {
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
      });
      const conversations = response.data;

      // Fetch host classifications in parallel with conversation fetch (best-effort)
      let hostClassifications;
      try {
        hostClassifications = await conversationService.getHostClassifications(fileId);
      } catch {
        // If the endpoint isn't available (e.g. older analysis), silently skip
      }

      // Transform to graph data with conversation limit and node significance cap
      const graphData = networkService.buildNetworkGraph(
        conversations,
        analysisSummary,
        maxConversations,
        hostClassifications,
        maxNodes
      );

      setNodes(graphData.nodes);
      setEdges(graphData.edges);
      setHiddenNodes(graphData.hiddenNodes ?? 0);
      setHiddenNodesList(graphData.hiddenNodesList ?? []);
      setCrossEdges(graphData.crossEdges ?? []);
      setStats({
        ...graphData.stats,
        isLimited: graphData.isLimited,
        totalConversations: graphData.totalConversations,
        displayedConversations: graphData.displayedConversations,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load network data';
      setError(errorMessage);
      console.error('Error fetching network data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileId, maxNodes]);

  return {
    nodes,
    edges,
    stats,
    loading,
    error,
    refetch: fetchData,
    hiddenNodes,
    hiddenNodesList,
    crossEdges,
  };
}
