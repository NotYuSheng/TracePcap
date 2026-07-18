import { useState, useEffect } from 'react';
import { useStore } from '@/store';

/**
 * Resolves the user's theme preference ('light' | 'dark' | 'system') into a
 * concrete boolean, following the OS setting live while in system mode.
 *
 * The same logic was previously inlined in `MainLayout` and `NetworkGraph`;
 * anything that needs to pick theme-aware colours in JS (rather than CSS) should
 * use this instead of re-deriving it.
 */
export function useResolvedDark(): boolean {
  const themeMode = useStore(s => s.themeMode);
  const [sysDark, setSysDark] = useState(
    () => window.matchMedia('(prefers-color-scheme: dark)').matches
  );

  useEffect(() => {
    if (themeMode !== 'system') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => setSysDark(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [themeMode]);

  if (themeMode === 'light') return false;
  if (themeMode === 'dark') return true;
  return sysDark;
}
