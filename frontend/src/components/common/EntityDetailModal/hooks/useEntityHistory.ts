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
    // Reset so a previous entity's history can't leak when the modal is reused.
    setHistory([]);
    setHistoryLoading(true);
    setHistoryError(null);
    entityNotesService
      .getHistory(entityType, entityKey)
      .then(entries => setHistory(entries))
      .catch(() => setHistoryError('Failed to load history'))
      .finally(() => setHistoryLoading(false));
  }, [entityType, entityKey]);

  return { history, historyLoading, historyError };
}
