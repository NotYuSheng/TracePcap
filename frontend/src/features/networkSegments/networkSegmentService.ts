import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** Mirrors NetworkSegmentsResponse.Segment (#462). */
export interface NetworkSegment {
  key: string;
  label: string;
  vlanId?: number | null;
  serverMac?: string | null;
  serverIds: string[];
  routers: string[];
  domains: string[];
  leaseSeconds: number[];
  cidr?: string | null;
  clients: { ip: string; mac: string; hostname?: string | null }[];
}

export interface NetworkSegmentOverlap {
  cidr?: string | null;
  segmentKeys: string[];
  sharedAddresses: string[];
}

export interface NetworkSegments {
  segments: NetworkSegment[];
  overlaps: NetworkSegmentOverlap[];
}

export const networkSegmentService = {
  get: async (fileId: string): Promise<NetworkSegments> =>
    (await apiClient.get<NetworkSegments>(API_ENDPOINTS.FILE_NETWORK_SEGMENTS(fileId))).data,
};
