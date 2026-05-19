import { apiClient } from '@/services/api/client';
import { MONITOR_ENDPOINTS } from '@/services/api/endpoints';
import type {
  Network,
  NetworkSnapshot,
  ChangeEvent,
  BaselineDefinition,
  BaselineEntryType,
} from '../types/monitor.types';

export const monitorService = {
  // ── Networks ────────────────────────────────────────────────────────────────

  listNetworks: (): Promise<Network[]> =>
    apiClient.get<Network[]>(MONITOR_ENDPOINTS.NETWORKS).then(r => r.data),

  getNetwork: (id: string): Promise<Network> =>
    apiClient.get<Network>(MONITOR_ENDPOINTS.NETWORK(id)).then(r => r.data),

  createNetwork: (name: string, description?: string): Promise<Network> =>
    apiClient
      .post<Network>(MONITOR_ENDPOINTS.NETWORKS, { name, description })
      .then(r => r.data),

  deleteNetwork: (id: string): Promise<void> =>
    apiClient.delete(MONITOR_ENDPOINTS.NETWORK(id)).then(() => undefined),

  // ── Snapshots ───────────────────────────────────────────────────────────────

  listSnapshots: (networkId: string): Promise<NetworkSnapshot[]> =>
    apiClient
      .get<NetworkSnapshot[]>(MONITOR_ENDPOINTS.SNAPSHOTS(networkId))
      .then(r => r.data),

  addSnapshot: (networkId: string, fileId: string): Promise<NetworkSnapshot> =>
    apiClient
      .post<NetworkSnapshot>(MONITOR_ENDPOINTS.SNAPSHOTS(networkId), { fileId })
      .then(r => r.data),

  removeSnapshot: (networkId: string, snapshotId: string): Promise<void> =>
    apiClient
      .delete(MONITOR_ENDPOINTS.SNAPSHOT(networkId, snapshotId))
      .then(() => undefined),

  // ── Change Events ───────────────────────────────────────────────────────────

  listChanges: (
    networkId: string,
    changeType?: string,
    severity?: string,
  ): Promise<ChangeEvent[]> => {
    const params = new URLSearchParams();
    if (changeType) params.set('changeType', changeType);
    if (severity) params.set('severity', severity);
    const query = params.toString();
    const url = query
      ? `${MONITOR_ENDPOINTS.CHANGES(networkId)}?${query}`
      : MONITOR_ENDPOINTS.CHANGES(networkId);
    return apiClient.get<ChangeEvent[]>(url).then(r => r.data);
  },

  patchChange: (
    networkId: string,
    eventId: string,
    patch: { reviewed?: boolean; notes?: string | null },
  ): Promise<ChangeEvent> =>
    apiClient
      .patch<ChangeEvent>(MONITOR_ENDPOINTS.CHANGE(networkId, eventId), patch)
      .then(r => r.data),

  // ── Baseline Definitions ────────────────────────────────────────────────────

  listDefinitions: (networkId: string): Promise<BaselineDefinition[]> =>
    apiClient
      .get<BaselineDefinition[]>(MONITOR_ENDPOINTS.BASELINE_DEFINITIONS(networkId))
      .then(r => r.data),

  createDefinition: (
    networkId: string,
    entryType: BaselineEntryType,
    entityKey: string,
    entityValue?: string,
    notes?: string,
  ): Promise<BaselineDefinition> =>
    apiClient
      .post<BaselineDefinition>(MONITOR_ENDPOINTS.BASELINE_DEFINITIONS(networkId), {
        entryType,
        entityKey,
        entityValue,
        notes,
      })
      .then(r => r.data),

  deleteDefinition: (networkId: string, id: string): Promise<void> =>
    apiClient
      .delete(`${MONITOR_ENDPOINTS.BASELINE_DEFINITIONS(networkId)}/${id}`)
      .then(() => undefined),
};
