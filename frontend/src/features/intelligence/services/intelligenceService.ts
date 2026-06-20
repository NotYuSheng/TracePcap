import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

export type GroupBy = 'asn' | 'country' | 'city' | 'subnet24' | 'subnet16' | 'deviceType' | 'customOrg';
export type SortBy = 'bytes' | 'packets' | 'conversations' | 'risks';

export interface IntelClusterFilters {
  ip?: string;
  port?: string;
  protocols?: string[];
  l7Protocols?: string[];
  apps?: string[];
  categories?: string[];
  hasRisks?: boolean;
  fileTypes?: string[];
  riskTypes?: string[];
  customSignatures?: string[];
  deviceTypes?: string[];
  countries?: string[];
  networkLabels?: string[];
}

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
  hostnameSource: string | null;
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

/** Role-agnostic summary of a host acting as a service server (DNS today; web servers later). */
export interface ServiceServerSummary {
  serverIp: string;
  hostname: string | null;
  role: string;
  totalRequests: number;
  okCount: number;
  failedCount: number;
  anomalyRatio: number;
  suspicious: boolean;
}

export interface DnsQueryEntry {
  queryName: string;
  queryType: string | null;
  responseCode: string | null;
  resolvedIps: string[];
  queryCount: number;
  resolvable: boolean;
  frame: number | null;
}

export interface DnsQueryLogResponse {
  serverIp: string;
  hostname: string | null;
  resolvedCount: number;
  failedCount: number;
  nxdomainRatio: number;
  suspicious: boolean;
  entries: DnsQueryEntry[];
}

export interface HttpEndpoint {
  method: string | null;
  path: string;
  topStatus: number | null;
  requestCount: number;
  successCount: number;
  clientErrorCount: number;
  serverErrorCount: number;
  contentType: string | null;
  requestFrame: number | null;
  responseFrame: number | null;
}

export interface PacketLocation {
  conversationId: string;
  packetNumber: number;
}

export interface TlsInfo {
  subject: string | null;
  issuer: string | null;
  ja3s: string | null;
  sniNames: string[];
  notBefore: string | null;
  notAfter: string | null;
}

export interface WebServerDetail {
  serverIp: string;
  hostname: string | null;
  api: boolean;
  totalRequests: number;
  successCount: number;
  clientErrorCount: number;
  serverErrorCount: number;
  clientErrorRatio: number;
  suspicious: boolean;
  serverSoftware: string | null;
  contentTypes: string[];
  tls: TlsInfo | null;
  endpoints: HttpEndpoint[];
}

export const intelligenceService = {
  async getClusters(fileId: string, groupBy: GroupBy, filters?: IntelClusterFilters): Promise<ClusterGraphResponse> {
    // Start from the canonical endpoint (includes ?groupBy=X) and append extra filter params
    const base = API_ENDPOINTS.NETWORK_INTELLIGENCE_CLUSTERS(fileId, groupBy);
    const params = new URLSearchParams();
    if (filters) {
      if (filters.ip) params.set('ip', filters.ip);
      if (filters.port) params.set('port', filters.port);
      if (filters.protocols?.length) params.set('protocols', filters.protocols.join(','));
      if (filters.l7Protocols?.length) params.set('l7Protocols', filters.l7Protocols.join(','));
      if (filters.apps?.length) params.set('apps', filters.apps.join(','));
      if (filters.categories?.length) params.set('categories', filters.categories.join(','));
      if (filters.hasRisks) params.set('hasRisks', 'true');
      if (filters.fileTypes?.length) params.set('fileTypes', filters.fileTypes.join(','));
      if (filters.riskTypes?.length) params.set('riskTypes', filters.riskTypes.join(','));
      if (filters.customSignatures?.length) params.set('customSignatures', filters.customSignatures.join(','));
      if (filters.deviceTypes?.length) params.set('deviceTypes', filters.deviceTypes.join(','));
      if (filters.countries?.length) params.set('countries', filters.countries.join(','));
      if (filters.networkLabels?.length) params.set('networkLabels', filters.networkLabels.join(','));
    }
    const qs = params.toString();
    const res = await apiClient.get<ClusterGraphResponse>(qs ? `${base}&${qs}` : base);
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

  async getDnsServers(fileId: string): Promise<ServiceServerSummary[]> {
    const res = await apiClient.get<ServiceServerSummary[]>(
      API_ENDPOINTS.NETWORK_INTELLIGENCE_DNS_SERVERS(fileId)
    );
    return res.data;
  },

  async getDnsQueryLog(fileId: string, serverIp: string): Promise<DnsQueryLogResponse> {
    const res = await apiClient.get<DnsQueryLogResponse>(
      API_ENDPOINTS.NETWORK_INTELLIGENCE_DNS_LOG(fileId, serverIp)
    );
    return res.data;
  },

  async getWebServers(fileId: string): Promise<ServiceServerSummary[]> {
    const res = await apiClient.get<ServiceServerSummary[]>(
      API_ENDPOINTS.NETWORK_INTELLIGENCE_WEB_SERVERS(fileId)
    );
    return res.data;
  },

  async getWebServerDetail(fileId: string, serverIp: string): Promise<WebServerDetail> {
    const res = await apiClient.get<WebServerDetail>(
      API_ENDPOINTS.NETWORK_INTELLIGENCE_WEB_DETAIL(fileId, serverIp)
    );
    return res.data;
  },

  /** Resolves a packet frame number to the conversation that contains it (null if not found). */
  async getPacketLocation(fileId: string, packetNumber: number): Promise<PacketLocation | null> {
    try {
      const res = await apiClient.get<PacketLocation>(
        API_ENDPOINTS.NETWORK_INTELLIGENCE_PACKET_LOCATION(fileId, packetNumber)
      );
      return res.data;
    } catch {
      return null;
    }
  },
};
