import type { StateCreator } from 'zustand';

export type ThemeMode = 'light' | 'dark' | 'system';

export interface ThemeSlice {
  themeMode: ThemeMode;
  cycleTheme: () => void;
}

const CYCLE: ThemeMode[] = ['light', 'dark', 'system'];

export const createThemeSlice: StateCreator<ThemeSlice> = set => ({
  themeMode: 'system',
  cycleTheme: () =>
    set(state => ({
      themeMode: CYCLE[(CYCLE.indexOf(state.themeMode) + 1) % CYCLE.length],
    })),
});
