import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { AnalysisSummary, ProtocolStats, FiveWsAnalysis, KillChainPhase } from '@/types';

export const analysisService = {
  /**
   * Get analysis summary for a PCAP file
   */
  getAnalysisSummary: async (fileId: string): Promise<AnalysisSummary> => {
    const summaryRes = await apiClient.get(API_ENDPOINTS.ANALYSIS_SUMMARY(fileId));
    const summary = summaryRes.data;

    const startTime = summary.timeRange?.[0] || Date.now();
    const endTime = summary.timeRange?.[1] || Date.now();

    const protocolDistribution = summary.protocolDistribution || [];

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
    }));

    const uniqueHosts = (summary.uniqueHosts || []).map((host: any) => ({
      ip: host.ip,
      port: host.port || 0,
      hostname: host.hostname,
    }));

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
    };
  },

  /**
   * Get protocol statistics for a PCAP file
   */
  getProtocolStats: async (fileId: string): Promise<ProtocolStats[]> => {
    const response = await apiClient.get<ProtocolStats[]>(API_ENDPOINTS.PROTOCOL_STATS(fileId));
    return response.data;
  },

  /**
   * Get Five W's analysis for a PCAP file
   */
  getFiveWs: async (fileId: string): Promise<FiveWsAnalysis> => {
    const response = await apiClient.get<FiveWsAnalysis>(API_ENDPOINTS.FIVE_WS(fileId));
    return response.data;
  },

  /**
   * Get Cyber Kill Chain analysis for a PCAP file
   */
  getKillChain: async (fileId: string): Promise<KillChainPhase[]> => {
    const response = await apiClient.get<KillChainPhase[]>(API_ENDPOINTS.KILL_CHAIN(fileId));
    return response.data;
  },
};
