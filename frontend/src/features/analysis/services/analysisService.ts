import { apiClient } from '@/services/api/client'
import { API_ENDPOINTS } from '@/services/api/endpoints'
import type { AnalysisSummary, ProtocolStats, FiveWsAnalysis, KillChainPhase } from '@/types'
import { generateMockAnalysis, mockAnalysisSummary } from '@/mocks/mockAnalysisData'

const USE_MOCK = import.meta.env.VITE_USE_MOCK_DATA === 'true'

export const analysisService = {
  /**
   * Get analysis summary for a PCAP file
   * @param fileId - The file ID to analyze
   * @returns Analysis summary with statistics and metadata
   */
  getAnalysisSummary: async (fileId: string): Promise<AnalysisSummary> => {
    if (USE_MOCK) {
      // Simulate network delay
      await new Promise((resolve) => setTimeout(resolve, 800))

      // Return mock data (you can customize based on fileId if needed)
      return generateMockAnalysis(fileId, 'free5gc.pcap')
    }

    // Fetch analysis summary (now includes all data we need)
    const summaryRes = await apiClient.get(API_ENDPOINTS.ANALYSIS_SUMMARY(fileId))
    const summary = summaryRes.data

    // Transform backend response to frontend format
    // Backend already returns Unix timestamps in milliseconds
    const startTime = summary.timeRange?.[0] || Date.now()
    const endTime = summary.timeRange?.[1] || Date.now()

    // Use protocol distribution from summary (already in the correct format)
    const protocolDistribution = summary.protocolDistribution || []

    // Use top conversations from summary (already provided by backend)
    const topConversations = (summary.topConversations || []).map((conv: any) => ({
      id: conv.id,
      endpoints: [
        { ip: conv.srcIp, port: conv.srcPort || 0 },
        { ip: conv.dstIp, port: conv.dstPort || 0 },
      ],
      protocol: { name: conv.protocol, layer: 'Transport' },
      packetCount: conv.packetCount || 0,
      totalBytes: conv.totalBytes || 0,
      startTime: conv.startTime || startTime,
      endTime: conv.endTime || endTime,
    }))

    // Use unique hosts from summary (already provided by backend)
    const uniqueHosts = (summary.uniqueHosts || []).map((host: any) => ({
      ip: host.ip,
      port: host.port || 0,
      hostname: host.hostname,
    }))

    return {
      fileId: summary.fileId,
      fileName: summary.fileName || 'unknown.pcap',
      fileSize: summary.fileSize || 0,
      uploadTime: summary.uploadTime || Date.now(),
      totalPackets: summary.totalPackets || 0,
      timeRange: [startTime, endTime],
      protocolDistribution,
      topConversations,
      uniqueHosts,
    }
  },

  /**
   * Get protocol statistics for a PCAP file
   * @param fileId - The file ID to analyze
   * @returns Protocol distribution statistics
   */
  getProtocolStats: async (fileId: string): Promise<ProtocolStats[]> => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 500))
      return mockAnalysisSummary.protocolDistribution
    }

    const response = await apiClient.get<ProtocolStats[]>(
      API_ENDPOINTS.PROTOCOL_STATS(fileId)
    )
    return response.data
  },

  /**
   * Get Five W's analysis for a PCAP file
   * @param fileId - The file ID to analyze
   * @returns Five W's analysis (Who, What, When, Where, Why)
   */
  getFiveWs: async (fileId: string): Promise<FiveWsAnalysis> => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 500))
      return mockAnalysisSummary.fiveWs!
    }

    const response = await apiClient.get<FiveWsAnalysis>(API_ENDPOINTS.FIVE_WS(fileId))
    return response.data
  },

  /**
   * Get Cyber Kill Chain analysis for a PCAP file
   * @param fileId - The file ID to analyze
   * @returns Kill chain phases with indicators
   */
  getKillChain: async (fileId: string): Promise<KillChainPhase[]> => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 500))
      // Return empty array for now (can add mock kill chain data later)
      return []
    }

    const response = await apiClient.get<KillChainPhase[]>(
      API_ENDPOINTS.KILL_CHAIN(fileId)
    )
    return response.data
  },
}
