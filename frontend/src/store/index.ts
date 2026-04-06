import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { createUploadSlice } from './slices/uploadSlice';
import type { UploadSlice } from './slices/uploadSlice';
import { createAnalysisSlice } from './slices/analysisSlice';
import type { AnalysisSlice } from './slices/analysisSlice';
import { createThemeSlice } from './slices/themeSlice';
import type { ThemeSlice, ThemeMode } from './slices/themeSlice';

export type { ThemeMode };

type StoreState = UploadSlice & AnalysisSlice & ThemeSlice;

export const useStore = create<StoreState>()(
  devtools(
    persist(
      (...a) => ({
        ...createUploadSlice(...a),
        ...createAnalysisSlice(...a),
        ...createThemeSlice(...a),
      }),
      {
        name: 'tracepcap-storage',
        partialize: state => ({
          // Only persist certain parts of state
          recentFiles: state.recentFiles,
          analysisSummaries: state.analysisSummaries,
          themeMode: state.themeMode,
        }),
      }
    ),
    {
      name: 'TracePcap Store',
    }
  )
);
