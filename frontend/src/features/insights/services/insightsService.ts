import { apiClient } from '@/services/api/client';
import { INSIGHTS_ENDPOINTS, MONITOR_ENDPOINTS } from '@/services/api/endpoints';
import type {
  NodeRole,
  NetworkExternalEvent,
  NetworkAnnotation,
  NetworkInsight,
  InsightOptions,
} from '../types/insights.types';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';

export const insightsService = {
  // ── Node Roles ───────────────────────────────────────────────────────────────

  getNodeRole: (entityType: string, entityKey: string): Promise<NodeRole | null> =>
    apiClient
      .get<NodeRole>(INSIGHTS_ENDPOINTS.NODE_ROLE(entityType, entityKey))
      .then(r => r.data)
      .catch(err => {
        if (err?.response?.status === 204 || err?.response?.status === 404) return null;
        throw err;
      }),

  upsertNodeRole: (
    entityType: string,
    entityKey: string,
    roleLabel: string,
    roleDescription: string,
    confirmedByHuman: boolean,
  ): Promise<NodeRole> =>
    apiClient
      .put<NodeRole>(INSIGHTS_ENDPOINTS.NODE_ROLE_UPSERT, {
        entityType,
        entityKey,
        roleLabel,
        roleDescription,
        confirmedByHuman,
      })
      .then(r => r.data),

  suggestNodeRole: async (
    entityType: string,
    entityKey: string,
    fileId: string,
  ): Promise<NodeRole> => {
    try {
      const r = await apiClient.post<NodeRole>(INSIGHTS_ENDPOINTS.NODE_ROLE_SUGGEST(entityType, entityKey, fileId));
      return r.data;
    } catch (err: unknown) {
      const axiosErr = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosErr?.response?.status === 422) {
        throw new Error(axiosErr.response.data?.error ?? 'Insufficient evidence for a role suggestion.');
      }
      throw err;
    }
  },

  deleteNodeRole: (entityType: string, entityKey: string): Promise<void> =>
    apiClient
      .delete(INSIGHTS_ENDPOINTS.NODE_ROLE_DELETE(entityType, entityKey))
      .then(() => undefined),

  // ── External Events ──────────────────────────────────────────────────────────

  listExternalEvents: (networkId: string): Promise<NetworkExternalEvent[]> =>
    apiClient
      .get<NetworkExternalEvent[]>(MONITOR_ENDPOINTS.EXTERNAL_EVENTS(networkId))
      .then(r => r.data),

  createExternalEvent: (
    networkId: string,
    eventTime: string,
    title: string,
    description?: string,
  ): Promise<NetworkExternalEvent> =>
    apiClient
      .post<NetworkExternalEvent>(MONITOR_ENDPOINTS.EXTERNAL_EVENTS(networkId), {
        eventTime,
        title,
        description,
      })
      .then(r => r.data),

  deleteExternalEvent: (networkId: string, eventId: string): Promise<void> =>
    apiClient
      .delete(MONITOR_ENDPOINTS.EXTERNAL_EVENT(networkId, eventId))
      .then(() => undefined),

  // ── Annotations ──────────────────────────────────────────────────────────────

  listAnnotations: (networkId: string): Promise<NetworkAnnotation[]> =>
    apiClient
      .get<NetworkAnnotation[]>(MONITOR_ENDPOINTS.ANNOTATIONS(networkId))
      .then(r => r.data),

  createAnnotation: (
    networkId: string,
    body: string,
    snapshotId?: string,
  ): Promise<NetworkAnnotation> =>
    apiClient
      .post<NetworkAnnotation>(MONITOR_ENDPOINTS.ANNOTATIONS(networkId), { body, snapshotId })
      .then(r => r.data),

  updateAnnotation: (networkId: string, annotationId: string, body: string): Promise<NetworkAnnotation> =>
    apiClient
      .patch<NetworkAnnotation>(MONITOR_ENDPOINTS.ANNOTATION(networkId, annotationId), { body })
      .then(r => r.data),

  deleteAnnotation: (networkId: string, annotationId: string): Promise<void> =>
    apiClient
      .delete(MONITOR_ENDPOINTS.ANNOTATION(networkId, annotationId))
      .then(() => undefined),

  // ── Snapshot context & per-snapshot insights ─────────────────────────────

  patchSnapshot: (
    networkId: string,
    snapshotId: string,
    patch: { context?: string; notes?: string },
  ): Promise<NetworkSnapshot> =>
    apiClient
      .patch<NetworkSnapshot>(MONITOR_ENDPOINTS.SNAPSHOT_PATCH(networkId, snapshotId), patch)
      .then(r => r.data),

  getSnapshotInsight: (networkId: string, snapshotId: string): Promise<NetworkInsight | null> =>
    apiClient
      .get<NetworkInsight>(MONITOR_ENDPOINTS.SNAPSHOT_INSIGHT_LATEST(networkId, snapshotId))
      .then(r => r.data)
      .catch(err => {
        if (err?.response?.status === 204 || err?.response?.status === 404) return null;
        throw err;
      }),

  generateSnapshotInsight: (networkId: string, snapshotId: string, options?: InsightOptions): Promise<NetworkInsight> =>
    apiClient
      .post<NetworkInsight>(MONITOR_ENDPOINTS.SNAPSHOT_INSIGHT_GENERATE(networkId, snapshotId), options ?? {})
      .then(r => r.data),

  // ── Insights ─────────────────────────────────────────────────────────────────

  getLatestInsight: (networkId: string): Promise<NetworkInsight | null> =>
    apiClient
      .get<NetworkInsight>(MONITOR_ENDPOINTS.INSIGHTS_LATEST(networkId))
      .then(r => r.data)
      .catch(err => {
        if (err?.response?.status === 204 || err?.response?.status === 404) return null;
        throw err;
      }),

  generateInsights: (networkId: string, options?: InsightOptions): Promise<NetworkInsight> =>
    apiClient
      .post<NetworkInsight>(MONITOR_ENDPOINTS.INSIGHTS_GENERATE(networkId), options ?? {})
      .then(r => r.data),
};
