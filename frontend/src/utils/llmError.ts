/**
 * Whether a 502 came from nginx because the backend itself is down.
 *
 * The backend sends every LLM failure as a 502 with an errorCode, including ones where the LLM
 * answered (timed out, output cut off, rejected the request), so the status alone says nothing
 * about the LLM. A 502 with no errorCode never went through the backend's error handler.
 */
function isBackendUnreachable(status: number | undefined, errorCode: unknown): boolean {
  return status === 502 && !errorCode;
}

const BACKEND_UNREACHABLE_MESSAGE =
  'The backend is not responding. Make sure the backend service is running, then try again.';

const LLM_UNREACHABLE_MESSAGE =
  'The LLM server is not responding. Make sure the LLM service is running and reachable, then try again.';

function formatDuration(ms: number): string {
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds} second${seconds !== 1 ? 's' : ''}`;
  const minutes = Math.round(seconds / 60);
  return `${minutes} minute${minutes !== 1 ? 's' : ''}`;
}

export interface LlmErrorOptions {
  /** What timed out, as it should read at the start of a sentence. */
  subject: string;
  timeoutMs: number;
  /** Finishes "try again or ...". */
  timeoutHint: string;
  /** Shown when the failure carries no message of its own. */
  fallback: string;
}

/** The message to show for a failed request to an LLM-backed endpoint. */
export function describeLlmError(err: unknown, options: LlmErrorOptions): string {
  const { response, code } = (err ?? {}) as {
    response?: { status?: number; data?: { errorCode?: unknown; message?: string } };
    code?: string;
  };
  const errorCode = response?.data?.errorCode;

  if (isBackendUnreachable(response?.status, errorCode)) return BACKEND_UNREACHABLE_MESSAGE;
  if (errorCode === 'LLM_UNREACHABLE') return LLM_UNREACHABLE_MESSAGE;
  if (errorCode === 'LLM_TIMEOUT' || code === 'ECONNABORTED') {
    return (
      `${options.subject} timed out after ${formatDuration(options.timeoutMs)}. ` +
      `The LLM is responding but took too long — try again or ${options.timeoutHint}.`
    );
  }
  return response?.data?.message || (err instanceof Error && err.message) || options.fallback;
}
