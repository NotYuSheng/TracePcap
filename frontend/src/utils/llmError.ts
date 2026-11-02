/**
 * Whether a 502 came from nginx because the backend itself is down.
 *
 * The backend sends every LLM failure as a 502 with an errorCode, including ones where the LLM
 * answered (timed out, output cut off, rejected the request), so the status alone says nothing
 * about the LLM. A 502 with no errorCode never went through the backend's error handler.
 */
export function isBackendUnreachable(status: number | undefined, errorCode: unknown): boolean {
  return status === 502 && !errorCode;
}

export const BACKEND_UNREACHABLE_MESSAGE =
  'The backend is not responding. Make sure the backend service is running, then try again.';
