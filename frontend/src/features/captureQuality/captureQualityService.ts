import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** One plain-language note on how complete a capture is (#1268). */
export interface CaptureQualityNote {
  /** midstream | gaps | invalid | memcap | depth */
  kind: string;
  /** warning: answers may be missing; info: worth knowing. */
  level: 'warning' | 'info' | string;
  text: string;
}

/** Mirrors CaptureQualityResponse (#1268). */
export interface CaptureQuality {
  verdict: 'complete' | 'notes' | string;
  notes: CaptureQualityNote[];
  tcpConversations: number;
  tcpWithoutHandshake: number;
  packets?: number | null;
  reassemblyGaps?: number | null;
  streamDepthReached?: number | null;
}

export const captureQualityService = {
  get: async (fileId: string): Promise<CaptureQuality> =>
    (await apiClient.get<CaptureQuality>(API_ENDPOINTS.CAPTURE_QUALITY(fileId))).data,
};
