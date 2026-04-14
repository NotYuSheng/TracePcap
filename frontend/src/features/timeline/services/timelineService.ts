import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';
import type { TimelineDataPoint } from '@/types';

// Backend response type (what the API actually returns)
interface TimelineApiResponse {
  timestamp: string | number[]; // LocalDateTime as ISO string or array
  packetCount: number;
  bytes: number;
  protocols: { [key: string]: number };
}

function transformTimelineData(apiData: TimelineApiResponse): TimelineDataPoint {
  return {
    timestamp: parseDateTime(apiData.timestamp),
    packetCount: apiData.packetCount,
    bytes: apiData.bytes,
    protocols: apiData.protocols,
  };
}

export const timelineService = {
  /**
   * Get timeline data for a PCAP file
   */
  getTimelineData: async (
    fileId: string,
    interval?: number,
    maxDataPoints?: number
  ): Promise<TimelineDataPoint[]> => {
    const response = await apiClient.get<TimelineApiResponse[]>(
      API_ENDPOINTS.TIMELINE_DATA(fileId),
      { params: { interval, maxDataPoints } }
    );
    return response.data.map(transformTimelineData);
  },

  /**
   * Get timeline data for a specific time range
   */
  getTimelineRange: async (
    fileId: string,
    start: number,
    end: number,
    maxDataPoints?: number
  ): Promise<TimelineDataPoint[]> => {
    const startISO = new Date(start).toISOString();
    const endISO = new Date(end).toISOString();

    const response = await apiClient.get<TimelineApiResponse[]>(`/api/timeline/${fileId}/range`, {
      params: { start: startISO, end: endISO, maxDataPoints },
    });
    return response.data.map(transformTimelineData);
  },
};
