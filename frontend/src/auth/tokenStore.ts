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
function oidcUserKey(): string {
  const authority = env.OIDC_AUTHORITY || `${window.location.origin}/realms/${env.OIDC_REALM}`;
  return `oidc.user:${authority}:${env.OIDC_CLIENT_ID}`;
}

export function getAccessToken(): string | null {
  if (!env.AUTH_ENABLED) return null;
  const raw = localStorage.getItem(oidcUserKey());
  if (!raw) return null;
  try {
    return (JSON.parse(raw).access_token as string) ?? null;
  } catch {
    return null;
  }
}

/**
 * The current user's username, matching the server-side actor on records they create (backend
 * `CurrentActor` prefers `preferred_username`). Returns "system" when auth is disabled — mirroring
 * the backend so author checks (e.g. edit-your-own-evidence) work in the auth-off path too. Read
 * from storage rather than a hook so it's usable outside an AuthProvider.
 */
export function currentUsername(): string {
  if (!env.AUTH_ENABLED) return 'system';
  const raw = localStorage.getItem(oidcUserKey());
  if (!raw) return 'system';
  try {
    const profile = JSON.parse(raw).profile ?? {};
    return profile.preferred_username ?? profile.sub ?? 'system';
  } catch {
    return 'system';
  }
}

/**
 * Re-login handler registered by the auth provider (which owns the OIDC userManager). The axios
 * client lives outside React, so on a 401 it calls this to hand control back to the OIDC layer for a
 * fresh signin. Null when auth is disabled or the provider hasn't mounted yet.
 */
let reauthHandler: (() => void) | null = null;

export function setReauthHandler(fn: (() => void) | null): void {
  reauthHandler = fn;
}

/**
 * Called by the axios response interceptor on a 401 when auth is enabled. Drops the stale OIDC user
 * so `isAuthenticated` flips false (a token stale from e.g. a Keycloak restart otherwise leaves the
 * AuthGate rendering the app forever), then triggers a fresh signin. Guarded so a burst of 401s from
 * parallel requests only kicks off one redirect.
 */
let reauthInFlight = false;

export function handleUnauthorized(): void {
  if (!env.AUTH_ENABLED || reauthInFlight) return;
  reauthInFlight = true;
  // A successful re-auth navigates away, so this never normally runs. If the redirect fails
  // (e.g. IdP briefly unreachable) we are still here — release the latch so a later 401 can
  // retry instead of being silently ignored forever.
  window.setTimeout(() => {
    reauthInFlight = false;
  }, 10_000);
  localStorage.removeItem(oidcUserKey());
  if (reauthHandler) {
    reauthHandler();
  } else {
    // Provider not mounted (or a plain page load): a reload re-runs the AuthGate, which redirects to
    // Keycloak now that the stale user is gone.
    window.location.reload();
  }
}
