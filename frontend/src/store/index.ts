import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { createUploadSlice } from './slices/uploadSlice';
import type { UploadSlice } from './slices/uploadSlice';
import { createAnalysisSlice } from './slices/analysisSlice';
import type { AnalysisSlice } from './slices/analysisSlice';
import { createThemeSlice } from './slices/themeSlice';
import type { ThemeSlice, ThemeMode } from './slices/themeSlice';
import { createNodeLabelSlice } from './slices/nodeLabelSlice';
import type { NodeLabelSlice } from './slices/nodeLabelSlice';

export type { ThemeMode };

type StoreState = UploadSlice & AnalysisSlice & ThemeSlice & NodeLabelSlice;

export const useStore = create<StoreState>()(
  devtools(
    persist(
      (...a) => ({
        ...createUploadSlice(...a),
        ...createAnalysisSlice(...a),
        ...createThemeSlice(...a),
        ...createNodeLabelSlice(...a),
      }),
      {
        name: 'tracepcap-storage',
        partialize: state => ({
          // Only persist certain parts of state
          recentFiles: state.recentFiles,
          analysisSummaries: state.analysisSummaries,
          themeMode: state.themeMode,
          nodeLabelConfig: state.nodeLabelConfig,
        }),
      }
    ),
    {
      name: 'TracePcap Store',
    }
  )
);
