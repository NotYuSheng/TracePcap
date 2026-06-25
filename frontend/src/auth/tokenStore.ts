import { env } from '@/config/env';

/**
 * Bridge between the OIDC session and the axios client (which lives outside React).
 *
 * Rather than mirroring the token into a module variable from a React render/effect (which would be
 * an impure side effect and is subject to child-before-parent effect ordering), this reads the
 * active token straight from where oidc-client-ts persists it: localStorage under the key
 * `oidc.user:<authority>:<client_id>`. That makes it available synchronously to the very first
 * request after a page load, and it returns `null` the moment the user is cleared (e.g. logout).
 *
 * When auth is disabled it always returns `null`, so the interceptor keeps its legacy behaviour.
 */
export function getAccessToken(): string | null {
  if (!env.AUTH_ENABLED) return null;
  const authority = env.OIDC_AUTHORITY || `${window.location.origin}/realms/${env.OIDC_REALM}`;
  const raw = localStorage.getItem(`oidc.user:${authority}:${env.OIDC_CLIENT_ID}`);
  if (!raw) return null;
  try {
    return (JSON.parse(raw).access_token as string) ?? null;
  } catch {
    return null;
  }
}
