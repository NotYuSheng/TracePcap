import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { Conversation, NetworkEndpoint, Protocol, PaginatedResponse, Packet } from '@/types';

// Backend response types
interface ConversationApiResponse {
  conversationId: string;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  protocol: string;
  appName?: string | null;
  packetCount: number;
  totalBytes: number;
  startTime: string | number[]; // LocalDateTime can be array or ISO string
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
}

interface ConversationDetailApiResponse extends ConversationApiResponse {
  packets: PacketApiResponse[];
}

// Convert LocalDateTime array [year, month, day, hour, min, sec, nano] or ISO string to timestamp
const parseDateTime = (dt: string | number[]): number => {
  if (typeof dt === 'string') {
    return new Date(dt).getTime();
  }
  if (Array.isArray(dt) && dt.length >= 6) {
    return new Date(dt[0], dt[1] - 1, dt[2], dt[3], dt[4], dt[5]).getTime();
  }
  return 0;
};

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
    payload: '',
    flags: [],
  };
}

export const conversationService = {
  /**
   * Get conversations for a PCAP file with pagination
   */
  getConversations: async (
    fileId: string,
    page: number = 1,
    pageSize: number = 25
  ): Promise<PaginatedResponse<Conversation>> => {
    const response = await apiClient.get<{
      data: ConversationApiResponse[];
      page: number;
      pageSize: number;
      total: number;
      totalPages: number;
    }>(API_ENDPOINTS.CONVERSATIONS(fileId), {
      params: { page, pageSize },
    });

    return {
      data: response.data.data.map(c => transformConversation(c)),
      page: response.data.page,
      pageSize: response.data.pageSize,
      total: response.data.total,
      totalPages: response.data.totalPages,
    };
  },

  /**
   * Get detailed conversation info including the full packet stream
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
