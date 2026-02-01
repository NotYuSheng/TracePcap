import { apiClient } from '@/services/api/client'
import { API_ENDPOINTS } from '@/services/api/endpoints'
import type { TimelineDataPoint } from '@/types'
import { mockTimelineData, generateTimelineForRange } from '@/mocks/mockTimelineData'

const USE_MOCK = import.meta.env.VITE_USE_MOCK_DATA === 'true'

// Backend response type (what the API actually returns)
interface TimelineApiResponse {
  timestamp: string | number[]  // LocalDateTime as ISO string or array
  packetCount: number
  bytes: number
  protocols: { [key: string]: number }
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

// Transform backend response to frontend format
function transformTimelineData(apiData: TimelineApiResponse): TimelineDataPoint {
  return {
    timestamp: parseDateTime(apiData.timestamp),
    packetCount: apiData.packetCount,
    bytes: apiData.bytes,
    protocols: apiData.protocols,
  }
}

export const timelineService = {
  /**
   * Get timeline data for a PCAP file
   * @param fileId - The file ID to get timeline for
   * @returns Timeline data points
   */
  getTimelineData: async (fileId: string): Promise<TimelineDataPoint[]> => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 700))
      return mockTimelineData
    }

    const response = await apiClient.get<TimelineApiResponse[]>(
      API_ENDPOINTS.TIMELINE_DATA(fileId)
    )

    // Transform backend response to frontend format
    return response.data.map(transformTimelineData)
  },

  /**
   * Get timeline data for a specific time range
   * @param fileId - The file ID
   * @param start - Start timestamp
   * @param end - End timestamp
   * @returns Timeline data points for the specified range
   */
  getTimelineRange: async (
    fileId: string,
    start: number,
    end: number
  ): Promise<TimelineDataPoint[]> => {
    if (USE_MOCK) {
      await new Promise((resolve) => setTimeout(resolve, 500))
      return generateTimelineForRange(start, end)
    }

    // Convert timestamps to ISO format for backend
    const startISO = new Date(start).toISOString()
    const endISO = new Date(end).toISOString()

    const response = await apiClient.get<TimelineApiResponse[]>(
      `/api/timeline/${fileId}/range?start=${startISO}&end=${endISO}`
    )

    // Transform backend response to frontend format
    return response.data.map(transformTimelineData)
  },
}
