import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { createUploadSlice } from './slices/uploadSlice';
import type { UploadSlice } from './slices/uploadSlice';
import { createAnalysisSlice } from './slices/analysisSlice';
import type { AnalysisSlice } from './slices/analysisSlice';

type StoreState = UploadSlice & AnalysisSlice;

export const useStore = create<StoreState>()(
  devtools(
    persist(
      (...a) => ({
        ...createUploadSlice(...a),
        ...createAnalysisSlice(...a),
      }),
      {
        name: 'tracepcap-storage',
        partialize: state => ({
          // Only persist certain parts of state
          recentFiles: state.recentFiles,
          analysisSummaries: state.analysisSummaries,
        }),
      }
    ),
    {
      name: 'TracePcap Store',
    }
  )
);
