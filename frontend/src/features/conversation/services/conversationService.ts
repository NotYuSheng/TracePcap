import { apiClient } from '@/services/api/client'
import { API_ENDPOINTS } from '@/services/api/endpoints'
import type { Conversation, Session, NetworkEndpoint, Protocol } from '@/types'
import { mockConversations, mockSessions, getConversationById } from '@/mocks/mockConversationData'

const USE_MOCK = import.meta.env.VITE_USE_MOCK_DATA === 'true'

// Backend response type (what the API actually returns)
interface ConversationApiResponse {
  conversationId: string
  srcIp: string
  srcPort: number | null
  dstIp: string
  dstPort: number | null
  protocol: string
  packetCount: number
  totalBytes: number
  startTime: string | number[] // LocalDateTime can be array or ISO string
  endTime: string | number[]
  durationMs: number
}

// Transform backend response to frontend format
function transformConversation(apiData: ConversationApiResponse): Conversation {
  const srcEndpoint: NetworkEndpoint = {
    ip: apiData.srcIp,
    port: apiData.srcPort ?? 0,
  }

  const dstEndpoint: NetworkEndpoint = {
    ip: apiData.dstIp,
    port: apiData.dstPort ?? 0,
  }

  // Convert LocalDateTime array [year, month, day, hour, min, sec, nano] to timestamp
  const parseDateTime = (dt: string | number[]): number => {
    if (typeof dt === 'string') {
      return new Date(dt).getTime()
    }
    if (Array.isArray(dt) && dt.length >= 6) {
      // [year, month (1-12), day, hour, min, sec, nano]
      return new Date(dt[0], dt[1] - 1, dt[2], dt[3], dt[4], dt[5]).getTime()
    }
    return Date.now()
  }

  // Map protocol string to Protocol object
  const protocolName = apiData.protocol.toUpperCase()
  const protocolLayer =
    protocolName === 'TCP' || protocolName === 'UDP' ? 'transport' :
    protocolName === 'ICMP' ? 'network' :
    'application'

  return {
    id: apiData.conversationId,
    endpoints: [srcEndpoint, dstEndpoint],
    protocol: {
      layer: protocolLayer as Protocol['layer'],
      name: protocolName,
    },
    startTime: parseDateTime(apiData.startTime),
    endTime: parseDateTime(apiData.endTime),
    packetCount: apiData.packetCount,
    totalBytes: apiData.totalBytes,
    packets: [], // Packets would need separate endpoint
    direction: 'bidirectional', // Backend doesn't track this yet
  }
}

export const conversationService = {
  /**
   * Get all conversations for a PCAP file
   * @param fileId - The file ID to get conversations for
   * @returns List of conversations
   */
  getConversations: async (fileId: string): Promise<Conversation[]> => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 600))
      return mockConversations
    }

    const response = await apiClient.get<ConversationApiResponse[]>(API_ENDPOINTS.CONVERSATIONS(fileId))

    // Transform backend response to frontend format
    return response.data.map(transformConversation)
  },

  /**
   * Get detailed information about a specific conversation
   * @param conversationId - The conversation ID
   * @returns Detailed conversation data including all packets
   */
  getConversationDetail: async (conversationId: string): Promise<Conversation> => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 400))
      const conversation = getConversationById(conversationId)
      if (!conversation) {
        throw new Error('Conversation not found')
      }
      return conversation
    }

    const response = await apiClient.get<Conversation>(
      API_ENDPOINTS.CONVERSATION_DETAIL(conversationId)
    )
    return response.data
  },

  /**
   * Get sessions (grouped conversations) for a file
   * @param fileId - The file ID
   * @returns List of sessions
   */
  getSessions: async (fileId: string): Promise<Session[]> => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 500))
      return mockSessions
    }

    // This endpoint would need to be added to the backend
    const response = await apiClient.get<Session[]>(`/sessions/${fileId}`)
    return response.data
  },
}
