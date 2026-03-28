import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';
import type { Conversation, NetworkEndpoint, Protocol, PaginatedResponse, Packet } from '@/types';
import type { ConversationFilters } from '../types';

// Backend response types
interface ConversationApiResponse {
  conversationId: string;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  protocol: string;
  appName?: string | null;
  category?: string | null;
  hostname?: string | null;
  ja3Client?: string | null;
  ja3Server?: string | null;
  tlsIssuer?: string | null;
  tlsSubject?: string | null;
  tlsNotBefore?: string | number[] | null;
  tlsNotAfter?: string | number[] | null;
  flowRisks?: string[] | null;
  packetCount: number;
  totalBytes: number;
  startTime: string | number[];
  endTime: string | number[];
  durationMs: number;
}

interface PacketApiResponse {
  id: string;
  packetNumber: number;
  timestamp: string | number[];
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  protocol: string;
  packetSize: number;
  info: string | null;
  payload: string | null;
  detectedFileType?: string | null;
}

interface ConversationDetailApiResponse extends ConversationApiResponse {
  packets: PacketApiResponse[];
}

function getProtocol(protocolName: string): Protocol {
  const name = protocolName.toUpperCase();
  const layer =
    name === 'TCP' || name === 'UDP' ? 'transport' : name === 'ICMP' ? 'network' : 'application';
  return { layer: layer as Protocol['layer'], name };
}

function transformConversation(
  apiData: ConversationApiResponse,
  packets: Packet[] = []
): Conversation {
  const srcEndpoint: NetworkEndpoint = { ip: apiData.srcIp, port: apiData.srcPort ?? 0 };
  const dstEndpoint: NetworkEndpoint = { ip: apiData.dstIp, port: apiData.dstPort ?? 0 };

  return {
    id: apiData.conversationId,
    endpoints: [srcEndpoint, dstEndpoint],
    protocol: getProtocol(apiData.protocol),
    appName: apiData.appName ?? undefined,
    category: apiData.category ?? undefined,
    hostname: apiData.hostname ?? undefined,
    ja3Client: apiData.ja3Client ?? undefined,
    ja3Server: apiData.ja3Server ?? undefined,
    tlsIssuer: apiData.tlsIssuer ?? undefined,
    tlsSubject: apiData.tlsSubject ?? undefined,
    tlsNotBefore: apiData.tlsNotBefore != null ? parseDateTime(apiData.tlsNotBefore) : undefined,
    tlsNotAfter: apiData.tlsNotAfter != null ? parseDateTime(apiData.tlsNotAfter) : undefined,
    flowRisks: apiData.flowRisks ?? [],
    startTime: parseDateTime(apiData.startTime),
    endTime: parseDateTime(apiData.endTime),
    packetCount: apiData.packetCount,
    totalBytes: apiData.totalBytes,
    packets,
    direction: 'bidirectional',
  };
}

function transformPacket(apiData: PacketApiResponse, protocol: Protocol): Packet {
  return {
    id: apiData.id,
    timestamp: parseDateTime(apiData.timestamp),
    source: { ip: apiData.srcIp, port: apiData.srcPort ?? 0 },
    destination: { ip: apiData.dstIp, port: apiData.dstPort ?? 0 },
    protocol,
    size: apiData.packetSize,
    info: apiData.info ?? undefined,
    payload: apiData.payload ?? '',
    detectedFileType: apiData.detectedFileType ?? undefined,
    flags: [],
  };
}

export const conversationService = {
  /**
   * Get conversations for a PCAP file with structured filtering, sorting, and pagination.
   */
  getConversations: async (
    fileId: string,
    filters: ConversationFilters
  ): Promise<PaginatedResponse<Conversation>> => {
    const params: Record<string, string> = {
      page: String(filters.page),
      pageSize: String(filters.pageSize),
    };
    if (filters.ip) params.ip = filters.ip;
    if (filters.port) params.port = filters.port;
    if (filters.protocols.length > 0) params.protocols = filters.protocols.join(',');
    if (filters.apps.length > 0) params.apps = filters.apps.join(',');
    if (filters.categories.length > 0) params.categories = filters.categories.join(',');
    if (filters.hasRisks) params.hasRisks = 'true';
    if (filters.fileTypes.length > 0) params.fileTypes = filters.fileTypes.join(',');
    if (filters.riskTypes.length > 0) params.riskTypes = filters.riskTypes.join(',');
    if (filters.sortBy) params.sortBy = filters.sortBy;
    if (filters.sortBy) params.sortDir = filters.sortDir;

    const response = await apiClient.get<{
      data: ConversationApiResponse[];
      page: number;
      pageSize: number;
      total: number;
      totalPages: number;
    }>(API_ENDPOINTS.CONVERSATIONS(fileId), { params });

    return {
      data: response.data.data.map(c => transformConversation(c)),
      page: response.data.page,
      pageSize: response.data.pageSize,
      total: response.data.total,
      totalPages: response.data.totalPages,
    };
  },

  /**
   * Build a URL for the CSV export endpoint with the current filters.
   */
  getExportUrl: (fileId: string, filters: ConversationFilters): string => {
    const params = new URLSearchParams();
    if (filters.ip) params.set('ip', filters.ip);
    if (filters.port) params.set('port', filters.port);
    if (filters.protocols.length > 0) params.set('protocols', filters.protocols.join(','));
    if (filters.apps.length > 0) params.set('apps', filters.apps.join(','));
    if (filters.categories.length > 0) params.set('categories', filters.categories.join(','));
    if (filters.hasRisks) params.set('hasRisks', 'true');
    if (filters.fileTypes.length > 0) params.set('fileTypes', filters.fileTypes.join(','));
    if (filters.riskTypes.length > 0) params.set('riskTypes', filters.riskTypes.join(','));
    if (filters.sortBy) params.set('sortBy', filters.sortBy);
    if (filters.sortBy) params.set('sortDir', filters.sortDir);
    const qs = params.toString();
    return `/api/conversations/${fileId}/export${qs ? '?' + qs : ''}`;
  },

  /**
   * Returns distinct nDPI risk type strings present in at-risk conversations for the given file.
   */
  getRiskTypes: async (fileId: string): Promise<string[]> => {
    const response = await apiClient.get<string[]>(API_ENDPOINTS.RISK_TYPES(fileId));
    return response.data;
  },

  /**
   * Returns distinct detected file types present in packets for the given file.
   */
  getFileTypes: async (fileId: string): Promise<string[]> => {
    const response = await apiClient.get<string[]>(`/conversations/${fileId}/file-types`);
    return response.data;
  },

  /**
   * Get detailed conversation info including the full packet stream.
   */
  getConversationDetail: async (conversationId: string): Promise<Conversation> => {
    const response = await apiClient.get<ConversationDetailApiResponse>(
      API_ENDPOINTS.CONVERSATION_DETAIL(conversationId)
    );

    const apiData = response.data;
    const protocol = getProtocol(apiData.protocol);
    const packets = (apiData.packets ?? []).map(p => transformPacket(p, protocol));
    return transformConversation(apiData, packets);
  },
};
