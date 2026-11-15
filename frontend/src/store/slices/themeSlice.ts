import type { StateCreator } from 'zustand';

export type ThemeMode = 'light' | 'dark' | 'system';

export interface ThemeSlice {
  themeMode: ThemeMode;
  cycleTheme: () => void;
  setThemeMode: (mode: ThemeMode) => void;
}

const CYCLE: ThemeMode[] = ['light', 'dark', 'system'];

export const createThemeSlice: StateCreator<ThemeSlice> = set => ({
  themeMode: 'system',
  setThemeMode: mode => set({ themeMode: mode }),
  cycleTheme: () =>
    set(state => ({
      themeMode: CYCLE[(CYCLE.indexOf(state.themeMode) + 1) % CYCLE.length],
    })),
});
