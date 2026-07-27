import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { createUploadSlice } from './slices/uploadSlice';
import type { UploadSlice } from './slices/uploadSlice';
import { createAnalysisSlice } from './slices/analysisSlice';
import type { AnalysisSlice } from './slices/analysisSlice';
import { createThemeSlice } from './slices/themeSlice';
import type { ThemeSlice, ThemeMode } from './slices/themeSlice';
import { createNodeLabelSlice, normalizeNodeLabelConfig } from './slices/nodeLabelSlice';
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
        // Coerce any legacy persisted shape (customText was a string; fields added since the
        // config was saved) into the current shape. Done in merge — which produces the hydrated
        // state — rather than by mutating the store afterwards, which would bypass subscribers.
        merge: (persisted, current) => {
          const p = (persisted ?? {}) as Partial<StoreState>;
          const merged = { ...current, ...p };
          if (p.nodeLabelConfig) {
            merged.nodeLabelConfig = normalizeNodeLabelConfig(p.nodeLabelConfig);
          }
          return merged;
        },
      }
    ),
    {
      name: 'TracePcap Store',
    }
  )
);
