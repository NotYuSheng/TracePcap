import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

export type GroupBy = 'asn' | 'country' | 'city' | 'subnet24' | 'subnet16' | 'deviceType' | 'customOrg';
export type SortBy = 'bytes' | 'packets' | 'conversations' | 'risks';

export interface ClusterNode {
  id: string;
  label: string;
  groupType: string;
  hostCount: number;
  totalBytes: number;
  totalPackets: number;
  conversationCount: number;
  riskCount: number;
  dominantProtocols: string[];
  sampleIps: string[];
  topRiskTypes: string[];
  ipBytes: Record<string, number>;
  ipConversations: Record<string, number>;
  ipRisks: Record<string, number>;
  ipPeers: Record<string, number>;
  lat: number | null;
  lon: number | null;
  geoSource: string | null;
}

export interface ClusterEdge {
  sourceId: string;
  targetId: string;
  totalBytes: number;
  conversationCount: number;
  dominantProtocol: string | null;
}

export interface ClusterGraphResponse {
  groupType: string;
  clusters: ClusterNode[];
  edges: ClusterEdge[];
  hiddenClusters: number;
}

export interface HostSummary {
  ip: string;
  hostname: string | null;
  totalBytes: number;
  packetCount: number;
  conversationCount: number;
  riskCount: number;
  deviceType: string | null;
  country: string | null;
  org: string | null;
  role: string;
  geoSource: string | null;
}

export interface TopHostsResponse {
  hosts: HostSummary[];
}

export const intelligenceService = {
  async getClusters(fileId: string, groupBy: GroupBy): Promise<ClusterGraphResponse> {
    const res = await apiClient.get<ClusterGraphResponse>(
      API_ENDPOINTS.NETWORK_INTELLIGENCE_CLUSTERS(fileId, groupBy)
    );
    return res.data;
  },

  async getTopHosts(
    fileId: string,
    sortBy: SortBy = 'bytes',
    limit = 100
  ): Promise<TopHostsResponse> {
    const res = await apiClient.get<TopHostsResponse>(
      API_ENDPOINTS.NETWORK_INTELLIGENCE_TOP_HOSTS(fileId, sortBy, limit)
    );
    return res.data;
  },
};
