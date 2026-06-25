/**
 * Tiny in-memory bridge between the OIDC auth context (React) and the axios client (non-React).
 *
 * The {@link AuthGate} keeps this in sync with the current access token; the axios request
 * interceptor reads it to attach the `Authorization` header. When auth is disabled the token stays
 * `null` and the interceptor falls back to its previous `localStorage` behaviour.
 */
let accessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}
