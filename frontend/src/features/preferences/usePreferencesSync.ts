import { useEffect, useRef } from 'react';
import { useStore } from '@/store';
import { normalizeNodeLabelConfig } from '@/store/slices/nodeLabelSlice';
import {
  COLUMNS_APPLIED_EVENT,
  COLUMNS_SAVED_EVENT,
  COLUMN_STORAGE_KEY,
  storedVisibleColumns,
} from '@/features/conversation/constants';
import { preferencesService, type Preferences } from './preferencesService';

const SAVE_DELAY_MS = 600;

function currentPreferences(): Preferences {
  const s = useStore.getState();
  return {
    themeMode: s.themeMode,
    nodeLabelConfig: s.nodeLabelConfig,
    conversationColumns: storedVisibleColumns(),
  };
}

/**
 * Keeps personal preferences on the server (#915 phase 2), so they follow the account with login
 * on, and are one shared set with login off. The browser keeps a local copy as a cache, so the app
 * still works offline from the backend.
 *
 * - On load: server values win. If the server has none yet, this browser's existing preferences
 *   are uploaded once, so nobody's setup is lost by the move.
 * - On change (theme, node labels, table columns): saved to the server, debounced.
 */
export function usePreferencesSync(): void {
  const ready = useRef(false);
  const applying = useRef(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let active = true;
    const save = () => {
      if (!ready.current || applying.current) return;
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        preferencesService.put(currentPreferences()).catch(() => {
          /* offline or not allowed: the local copy still applies */
        });
      }, SAVE_DELAY_MS);
    };

    preferencesService
      .get()
      .then(p => {
        if (!active) return;
        const hasServerValues = !!(p.themeMode || p.nodeLabelConfig || p.conversationColumns);
        if (hasServerValues) {
          applying.current = true;
          const store = useStore.getState();
          if (p.themeMode) store.setThemeMode(p.themeMode);
          if (p.nodeLabelConfig) store.setNodeLabelConfig(normalizeNodeLabelConfig(p.nodeLabelConfig));
          if (p.conversationColumns) {
            try {
              localStorage.setItem(COLUMN_STORAGE_KEY, JSON.stringify(p.conversationColumns));
            } catch {
              /* ignore */
            }
            window.dispatchEvent(new Event(COLUMNS_APPLIED_EVENT));
          }
          applying.current = false;
          ready.current = true;
        } else {
          ready.current = true;
          preferencesService.put(currentPreferences()).catch(() => {});
        }
      })
      .catch(() => {
        // Backend unreachable: keep working from the local copy, and don't try to save.
      });

    const unsubscribe = useStore.subscribe((s, prev) => {
      if (s.themeMode !== prev.themeMode || s.nodeLabelConfig !== prev.nodeLabelConfig) save();
    });
    window.addEventListener(COLUMNS_SAVED_EVENT, save);
    return () => {
      active = false;
      unsubscribe();
      window.removeEventListener(COLUMNS_SAVED_EVENT, save);
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);
}
