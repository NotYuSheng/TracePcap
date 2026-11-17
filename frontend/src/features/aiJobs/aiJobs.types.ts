/** AI work running in the background (GET /ai-jobs): one job at a time for the model. */
export type AiJobKind =
  | 'STORY'
  | 'INSIGHTS'
  | 'SNAPSHOT_INSIGHTS'
  | 'ROLE_SUGGESTION'
  | 'ROLE_PREVIEW'
  | 'SUBNET_LABEL'
  | 'TRACE_EXPLANATIONS';
export type AiJobStatus = 'WAITING' | 'RUNNING' | 'DONE' | 'FAILED' | 'CANCELLED';

export interface AiJobError {
  message?: string | null;
  /** e.g. CONTEXT_LENGTH_EXCEEDED, LLM_TIMEOUT, LLM_UNREACHABLE. */
  errorCode?: string | null;
  promptText?: string | null;
  promptTokens?: number | null;
  contextLength?: number | null;
}

export interface AiJob {
  id: string;
  kind: AiJobKind | string;
  /** Where the answer lands (a capture, a network); null for a conversation's explanations. */
  subjectId?: string | null;
  /** Something finer within it: one host (IP:10.0.0.5), subnet or conversation. */
  subjectKey?: string | null;
  subjectName?: string | null;
  /** USER when someone asked for it, UPLOAD when an upload option did. */
  trigger: 'USER' | 'UPLOAD' | string;
  requestedBy?: string | null;
  status: AiJobStatus;
  /** While waiting: its place in line, 1 being next. */
  position?: number | null;
  createdAt: string;
  startedAt?: string | null;
  finishedAt?: string | null;
  /** How long this kind usually takes here, when the backend has seen a few. */
  typicalMs?: number | null;
  /** The kind's own result once DONE (a story, an insight); absent from the list. */
  result?: unknown;
  error?: AiJobError | null;
}

export const isActive = (job: AiJob | null | undefined): job is AiJob =>
  !!job && (job.status === 'WAITING' || job.status === 'RUNNING');
