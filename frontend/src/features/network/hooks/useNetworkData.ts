import { useState, useEffect, useRef } from 'react';
import { conversationService } from '@/features/conversation/services/conversationService';
import { networkService } from '../services/networkService';
import type { GraphNode, GraphEdge, NetworkStats } from '../types';
import type { Conversation, HostClassification, HostIdentity } from '@/types';
import type { NodeRole } from '@/features/insights/types/insights.types';
import { insightsService } from '@/features/insights/services/insightsService';
import type { AnalysisSummary } from '@/types';
import { env } from '@/config/env';

export const MAX_DIAGRAM_NODES = 50;

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

export const CONVERSATION_LIMIT_ENABLED = env.NETWORK_DIAGRAM_CONVERSATION_LIMIT;
const MAX_CONVERSATIONS = 500;

/**
 * Custom hook for fetching and transforming network data into graph format.
 *
 * Fetch and transform are intentionally split:
 *  - Raw conversations + host classifications are fetched once per fileId change.
 *  - buildNetworkGraph (pure transformation) re-runs client-side whenever
 *    maxNodes or analysisSummary changes, avoiding redundant network requests.
 */
export function useNetworkData(
  fileId: string,
  analysisSummary?: AnalysisSummary,
  maxNodes: number = MAX_DIAGRAM_NODES
): UseNetworkDataReturn {
  const maxConversations = CONVERSATION_LIMIT_ENABLED ? MAX_CONVERSATIONS : Infinity;

  // Raw data cached after the initial fetch — transform re-runs without re-fetching
  const conversationsRef = useRef<Conversation[]>([]);
  const hostClassificationsRef = useRef<HostClassification[] | undefined>(undefined);
  const hostIdentitiesRef = useRef<HostIdentity[] | undefined>(undefined);
  const nodeRolesRef = useRef<NodeRole[] | undefined>(undefined);

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

  /** Apply buildNetworkGraph to the currently cached raw data. */
  const applyTransform = (
    conversations: Conversation[],
    hostClassifications: HostClassification[] | undefined,
    summary: AnalysisSummary | undefined,
    limit: number,
    hostIdentities?: HostIdentity[],
    nodeRoles?: NodeRole[]
  ) => {
    const graphData = networkService.buildNetworkGraph(
      conversations,
      summary,
      maxConversations,
      hostClassifications,
      limit,
      hostIdentities,
      nodeRoles
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
  };

  /** Full fetch + transform — runs when fileId changes. */
  const fetchData = async () => {
    if (!fileId) {
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);

      // Conversations are required; the other three are best-effort enrichments (older analyses
      // may predate their endpoints). All depend only on fileId, so they run concurrently.
      const [response, classificationsRes, identitiesRes, rolesRes] = await Promise.allSettled([
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
          suricataAlerts: [],
          deviceTypes: [],
          countries: [],
          sortBy: '',
          sortDir: 'asc',
          page: 1,
          pageSize: 10000,
        }),
        conversationService.getHostClassifications(fileId),
        conversationService.getHostIdentities(fileId),
        insightsService.listNodeRoles(fileId),
      ]);
      if (response.status === 'rejected') throw response.reason;
      const conversations = response.value.data;

      const hostClassifications: HostClassification[] | undefined =
        classificationsRes.status === 'fulfilled' ? classificationsRes.value : undefined;
      // Adjudicated identities (#512 slice 5) — files analysed before the adjudicator existed
      // simply have none, and the display falls back to raw classification.
      const hostIdentities: HostIdentity[] | undefined =
        identitiesRes.status === 'fulfilled' ? identitiesRes.value : undefined;
      // Analyst-assigned role labels — for the node-label lines.
      const nodeRoles: NodeRole[] | undefined =
        rolesRes.status === 'fulfilled' ? rolesRes.value : undefined;

      conversationsRef.current = conversations;
      hostClassificationsRef.current = hostClassifications;
      hostIdentitiesRef.current = hostIdentities;
      nodeRolesRef.current = nodeRoles;

      applyTransform(conversations, hostClassifications, analysisSummary, maxNodes, hostIdentities, nodeRoles);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load network data';
      setError(errorMessage);
      console.error('Error fetching network data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Re-fetch only when the file changes
  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileId]);

  // Re-transform (no network request) when maxNodes or analysisSummary changes
  useEffect(() => {
    if (conversationsRef.current.length === 0) return;
    applyTransform(
      conversationsRef.current,
      hostClassificationsRef.current,
      analysisSummary,
      maxNodes,
      hostIdentitiesRef.current,
      nodeRolesRef.current
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [maxNodes, analysisSummary]);

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
