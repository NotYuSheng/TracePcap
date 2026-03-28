import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';
import type { Conversation } from '@/types';

// Re-use the same API response shape as conversations
interface SecurityAlertApiResponse {
  conversationId: string;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  protocol: string;
  appName?: string | null;
  flowRisks: string[];
  packetCount: number;
  totalBytes: number;
  startTime: string | number[];
  endTime: string | number[];
  durationMs: number;
}

export const securityService = {
  getSecurityAlerts: async (fileId: string): Promise<Conversation[]> => {
    const response = await apiClient.get<SecurityAlertApiResponse[]>(
      API_ENDPOINTS.SECURITY_ALERTS(fileId)
    );

    return response.data.map(item => ({
      id: item.conversationId,
      endpoints: [
        { ip: item.srcIp, port: item.srcPort ?? 0 },
        { ip: item.dstIp, port: item.dstPort ?? 0 },
      ],
      protocol: {
        layer: item.protocol === 'TCP' || item.protocol === 'UDP' ? 'transport' : 'application',
        name: item.protocol.toUpperCase(),
      },
      appName: item.appName ?? undefined,
      flowRisks: item.flowRisks ?? [],
      startTime: parseDateTime(item.startTime),
      endTime: parseDateTime(item.endTime),
      packetCount: item.packetCount,
      totalBytes: item.totalBytes,
      packets: [],
      direction: 'bidirectional',
    }));
  },
};
