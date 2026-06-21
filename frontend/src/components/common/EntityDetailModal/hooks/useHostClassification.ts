import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import type { EntityType } from '@/features/notes/services/entityNotesService';
import type { HostClassification } from '../types';

/**
 * Host classification signals (manufacturer/device type/TTL/confidence) for an IP
 * in the current file.
 */
export function useHostClassification(entityType: EntityType, entityKey: string, fileId: string) {
  const [hostClass, setHostClass] = useState<HostClassification | null>(null);

  useEffect(() => {
    let active = true;
    // Reset so a previous entity's classification can't leak when the modal is reused.
    setHostClass(null);
    if (entityType !== 'IP' || !fileId) return;
    apiClient
      .get<HostClassification[]>(`/files/${fileId}/host-classifications`)
      .then(r => {
        if (!active) return;
        const match = r.data.find(h => h.ip === entityKey);
        setHostClass(match ?? null);
      })
      .catch(() => {});
    return () => { active = false; };
  }, [entityType, entityKey, fileId]);

  return hostClass;
}
