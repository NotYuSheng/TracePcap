import type { StateCreator } from 'zustand';

export interface RecentFile {
  id: string;
  name: string;
  size: number;
  uploadedAt: number;
}

export interface UploadSlice {
  recentFiles: RecentFile[];
  addRecentFile: (file: RecentFile) => void;
  removeRecentFile: (fileId: string) => void;
  clearRecentFiles: () => void;
}

export const createUploadSlice: StateCreator<UploadSlice> = set => ({
  recentFiles: [],
  addRecentFile: file =>
    set(state => ({
      recentFiles: [file, ...state.recentFiles].slice(0, 10), // Keep only last 10 files
    })),
  removeRecentFile: fileId =>
    set(state => ({
      recentFiles: state.recentFiles.filter(f => f.id !== fileId),
    })),
  clearRecentFiles: () => set({ recentFiles: [] }),
});
