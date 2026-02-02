import type { AnalysisSummary, ProtocolStats, FiveWsAnalysis, KillChainPhase } from '@/types';

// Re-export common types for convenience
export type { AnalysisSummary, ProtocolStats, FiveWsAnalysis, KillChainPhase };

// Analysis API Response Types
export interface AnalysisResponse {
  success: boolean;
  data: AnalysisSummary;
  timestamp: number;
}

export interface ProtocolStatsResponse {
  success: boolean;
  data: ProtocolStats[];
  timestamp: number;
}

// Analysis State Types
export interface AnalysisState {
  currentFileId: string | null;
  summary: AnalysisSummary | null;
  isLoading: boolean;
  error: AnalysisError | null;
}

export interface AnalysisError {
  code: string;
  message: string;
  details?: unknown;
}
