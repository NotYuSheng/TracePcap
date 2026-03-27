import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { TimelineDataPoint } from '@/types';

// Backend response type (what the API actually returns)
interface TimelineApiResponse {
  timestamp: string | number[]; // LocalDateTime as ISO string or array
  packetCount: number;
  bytes: number;
  protocols: { [key: string]: number };
}

// Convert LocalDateTime array [year, month, day, hour, min, sec, nano] to timestamp
const parseDateTime = (dt: string | number[]): number => {
  if (typeof dt === 'string') {
    return new Date(dt).getTime();
  }
  if (Array.isArray(dt) && dt.length >= 6) {
    return new Date(dt[0], dt[1] - 1, dt[2], dt[3], dt[4], dt[5]).getTime();
  }
  return Date.now();
};

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
    maxDataPoints?: number
  ): Promise<TimelineDataPoint[]> => {
    const response = await apiClient.get<TimelineApiResponse[]>(
      API_ENDPOINTS.TIMELINE_DATA(fileId),
      { params: { maxDataPoints } }
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

    const response = await apiClient.get<TimelineApiResponse[]>(
      `/api/timeline/${fileId}/range`,
      {
        params: { start: startISO, end: endISO, maxDataPoints },
      }
    );
    return response.data.map(transformTimelineData);
  },
};
