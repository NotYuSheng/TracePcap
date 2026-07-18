import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** A persisted human override of an adjudicated question, with its audit trail. */
export interface AdjudicationOverride {
  question: string;
  entityKey: string;
  label: string;
  rationale: string | null;
  /** Who overrode: username, or "system" when auth is off. */
  actor: string;
  createdAt: string;
  updatedAt: string;
  /** Set when this carried-forward override drifted in monitor mode (#499); null when current. */
  staleSince?: string | null;
  /** The changes that made it stale; empty/absent when current. */
  staleFields?: string[] | null;
}

/** A piece of analyst-appended evidence, with its audit trail. */
export interface AdjudicationEvidence {
  id: number;
  question: string;
  entityKey: string;
  label: string;
  weight: number;
  reason: string;
  /** Who added it: username, or "system" when auth is off. */
  actor: string;
  createdAt: string;
}

/**
 * Generic human-override client for any adjudicated question. The `question` is the backend
 * `Adjudicator.question()` key (e.g. "host-identity") — the same call works for every question,
 * which is the point of the shared table.
 */
export const adjudicationService = {
  /** The current override for a question about an entity, or null if none is set. */
  getOverride: (
    fileId: string,
    question: string,
    entityKey: string,
  ): Promise<AdjudicationOverride | null> =>
    apiClient
      .get<AdjudicationOverride>(API_ENDPOINTS.ADJUDICATION_OVERRIDE(fileId, question, entityKey))
      .then(r => r.data)
      .catch(err => {
        if (err?.response?.status === 204 || err?.response?.status === 404) return null;
        throw err;
      }),

  /** Set or replace the human override; the backend re-runs adjudication and stamps the actor. */
  setOverride: (
    fileId: string,
    question: string,
    entityKey: string,
    label: string,
    rationale?: string,
  ): Promise<AdjudicationOverride> =>
    apiClient
      .put<AdjudicationOverride>(
        API_ENDPOINTS.ADJUDICATION_OVERRIDE(fileId, question, entityKey),
        { label, rationale: rationale ?? null },
      )
      .then(r => r.data),

  /** Clear the human override, letting the machine vote decide again. */
  clearOverride: (fileId: string, question: string, entityKey: string): Promise<void> =>
    apiClient
      .delete(API_ENDPOINTS.ADJUDICATION_OVERRIDE(fileId, question, entityKey))
      .then(() => undefined),

  /** Analyst evidence appended for a question about an entity, newest first. */
  listEvidence: (
    fileId: string,
    question: string,
    entityKey: string,
  ): Promise<AdjudicationEvidence[]> =>
    apiClient
      .get<AdjudicationEvidence[]>(API_ENDPOINTS.ADJUDICATION_EVIDENCE(fileId, question, entityKey))
      .then(r => r.data),

  /** Append weighted evidence toward a candidate; the backend re-runs adjudication. */
  appendEvidence: (
    fileId: string,
    question: string,
    entityKey: string,
    label: string,
    weight: number,
    reason: string,
  ): Promise<AdjudicationEvidence> =>
    apiClient
      .post<AdjudicationEvidence>(
        API_ENDPOINTS.ADJUDICATION_EVIDENCE(fileId, question, entityKey),
        { label, weight, reason },
      )
      .then(r => r.data),

  /** Edit your own evidence (author-only; 403 otherwise). Backend re-runs adjudication. */
  updateEvidence: (
    fileId: string,
    question: string,
    entityKey: string,
    evidenceId: number,
    label: string,
    weight: number,
    reason: string,
  ): Promise<AdjudicationEvidence> =>
    apiClient
      .put<AdjudicationEvidence>(
        API_ENDPOINTS.ADJUDICATION_EVIDENCE_ITEM(fileId, question, entityKey, evidenceId),
        { label, weight, reason },
      )
      .then(r => r.data),

  /** Delete your own evidence (author-only; 403 otherwise). Backend re-runs adjudication. */
  deleteEvidence: (
    fileId: string,
    question: string,
    entityKey: string,
    evidenceId: number,
  ): Promise<void> =>
    apiClient
      .delete(API_ENDPOINTS.ADJUDICATION_EVIDENCE_ITEM(fileId, question, entityKey, evidenceId))
      .then(() => undefined),
};
