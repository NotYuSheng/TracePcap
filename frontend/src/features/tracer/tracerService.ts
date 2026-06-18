import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

export interface TracerStep {
  stepIndex: number;
  packetNumber: number;
  timestamp: string | null;
  direction: 'CLIENT' | 'SERVER';
  protocol: string;
  size: number;
  info: string | null;
  payloadHex: string | null;
}

export interface TracerStepsResponse {
  conversationId: string;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  protocol: string;
  appName: string | null;
  steps: TracerStep[];
}

export interface TracerPeer {
  ip: string;
  conversationId: string;
  protocol: string;
  packetCount: number;
  responded: boolean;
}

export interface TracerPeersResponse {
  conversationId: string;
  hostIp: string;
  peers: TracerPeer[];
}

export interface StepExplanation {
  stepIndex: number;
  explanation: string;
}

export interface TracerExplainResponse {
  conversationId: string;
  explanations: StepExplanation[];
  error?: string;
}

export const tracerService = {
  async getSteps(conversationId: string): Promise<TracerStepsResponse> {
    const res = await apiClient.get<TracerStepsResponse>(
      API_ENDPOINTS.TRACER_STEPS(conversationId)
    );
    return res.data;
  },

  async getPeers(conversationId: string): Promise<TracerPeersResponse> {
    const res = await apiClient.get<TracerPeersResponse>(
      API_ENDPOINTS.TRACER_PEERS(conversationId)
    );
    return res.data;
  },

  async explain(conversationId: string): Promise<TracerExplainResponse> {
    const res = await apiClient.post<TracerExplainResponse>(
      API_ENDPOINTS.TRACER_EXPLAIN(conversationId)
    );
    return res.data;
  },
};
