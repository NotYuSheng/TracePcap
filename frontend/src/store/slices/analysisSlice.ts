import type { StateCreator } from 'zustand';
import type { AnalysisSummary } from '@/types';

export interface AnalysisSlice {
  currentFileId: string | null;
  analysisSummaries: { [fileId: string]: AnalysisSummary };
  setCurrentFileId: (fileId: string) => void;
  setAnalysisSummary: (fileId: string, summary: AnalysisSummary) => void;
  clearAnalysis: () => void;
}

export const createAnalysisSlice: StateCreator<AnalysisSlice> = set => ({
  currentFileId: null,
  analysisSummaries: {},
  setCurrentFileId: fileId => set({ currentFileId: fileId }),
  setAnalysisSummary: (fileId, summary) =>
    set(state => ({
      analysisSummaries: {
        ...state.analysisSummaries,
        [fileId]: summary,
      },
    })),
  clearAnalysis: () => set({ currentFileId: null, analysisSummaries: {} }),
});
