import { WebStorageStateStore } from 'oidc-client-ts';
import type { AuthProviderProps } from 'react-oidc-context';
import { env } from '@/config/env';

/**
 * Resolve the OIDC issuer/authority. By default it's derived from the current page origin — Keycloak
 * is proxied same-origin by nginx (see nginx.conf.template), so the browser reaches the IdP at the
 * exact host:port it loaded the app from, regardless of whether that's localhost, a LAN IP, or a
 * Tailscale address. An explicit `VITE_OIDC_AUTHORITY` (a full issuer URL) overrides this when
 * Keycloak is hosted elsewhere.
 */
function resolveAuthority(): string {
  if (env.OIDC_AUTHORITY) return env.OIDC_AUTHORITY;
  return `${window.location.origin}/realms/${env.OIDC_REALM}`;
}

/**
 * OIDC settings for react-oidc-context. Authorization Code + PKCE against the configured Keycloak
 * realm. The redirect URI is the app origin; `onSigninCallback` strips the `?code`/`?state` params
 * after a successful login so the address bar stays clean and no extra router route is needed.
 */
export const oidcConfig: AuthProviderProps = {
  authority: resolveAuthority(),
  client_id: env.OIDC_CLIENT_ID,
  redirect_uri: `${window.location.origin}/`,
  post_logout_redirect_uri: `${window.location.origin}/`,
  response_type: 'code',
  scope: 'openid profile email',
  automaticSilentRenew: true,
  userStore: new WebStorageStateStore({ store: window.localStorage }),
  onSigninCallback: () => {
    window.history.replaceState({}, document.title, window.location.pathname);
  },
};
