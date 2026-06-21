import { useEffect, useState } from 'react';
import {
  entityNotesService,
  type EntityHistoryEntry,
  type EntityType,
} from '@/features/notes/services/entityNotesService';

/**
 * Capture history: which uploaded files this entity appeared in.
 */
export function useEntityHistory(entityType: EntityType, entityKey: string) {
  const [history, setHistory] = useState<EntityHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    // Reset so a previous entity's history can't leak when the modal is reused.
    setHistory([]);
    setHistoryLoading(true);
    setHistoryError(null);
    entityNotesService
      .getHistory(entityType, entityKey)
      .then(entries => { if (active) setHistory(entries); })
      .catch(() => { if (active) setHistoryError('Failed to load history'); })
      .finally(() => { if (active) setHistoryLoading(false); });
    return () => { active = false; };
  }, [entityType, entityKey]);

  return { history, historyLoading, historyError };
}
