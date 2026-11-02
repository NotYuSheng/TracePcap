/**
 * Whether a failed LLM request means the server could not be reached.
 *
 * The backend sends every LLM failure as a 502 with an errorCode, including ones where the LLM
 * answered (timed out, output cut off, empty reply), so the status alone says nothing. A 502 with
 * no errorCode did not come from the backend's handler: nginx could not reach the backend.
 */
export function isLlmUnreachable(status: number | undefined, errorCode: unknown): boolean {
  return errorCode === 'LLM_UNREACHABLE' || (status === 502 && !errorCode);
}
