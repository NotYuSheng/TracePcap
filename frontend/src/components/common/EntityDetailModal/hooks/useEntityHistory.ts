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
    if (history.length > 0 || historyLoading) return;
    setHistoryLoading(true);
    setHistoryError(null);
    entityNotesService
      .getHistory(entityType, entityKey)
      .then(entries => setHistory(entries))
      .catch(() => setHistoryError('Failed to load history'))
      .finally(() => setHistoryLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityType, entityKey]);

  return { history, historyLoading, historyError };
}
