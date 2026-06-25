import { type ReactNode, useEffect } from 'react';
import { useAuth } from 'react-oidc-context';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Button } from '@govtechsg/sgds-react';
import { setAccessToken } from './tokenStore';

function FullScreen({ children }: { children: ReactNode }) {
  return (
    <div
      className="d-flex flex-column align-items-center justify-content-center gap-3 text-muted"
      style={{ minHeight: '100vh' }}
    >
      {children}
    </div>
  );
}

/**
 * Wraps the app when auth is enabled. Redirects unauthenticated users to Keycloak, shows a loading
 * state during the round-trip, surfaces errors with a retry, and mirrors the access token into the
 * {@link setAccessToken token store} so the axios client can attach it. Renders children only once
 * the user is authenticated.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const auth = useAuth();

  // Sync the axios token bridge synchronously DURING render — not in an effect. Child effects (the
  // pages' data fetches) run before a parent's effect, so an effect here would leave the first
  // requests after a full page load without a token (→ 401). Setting it in render guarantees the
  // token is present before any descendant mounts and fetches. Idempotent, so safe to repeat.
  setAccessToken(auth.user?.access_token ?? null);

  // Kick off login once the initial state has settled and we're not already mid-flight.
  useEffect(() => {
    if (!auth.isLoading && !auth.isAuthenticated && !auth.activeNavigator && !auth.error) {
      void auth.signinRedirect();
    }
  }, [auth.isLoading, auth.isAuthenticated, auth.activeNavigator, auth.error, auth]);

  if (auth.error) {
    return (
      <FullScreen>
        <p className="mb-0 fw-semibold">Sign-in failed</p>
        <small>{auth.error.message}</small>
        <Button size="sm" variant="primary" onClick={() => void auth.signinRedirect()}>
          Try again
        </Button>
      </FullScreen>
    );
  }

  if (auth.isAuthenticated) {
    return <>{children}</>;
  }

  return (
    <FullScreen>
      <Spinner animation="border" className="text-primary" />
      <small>Redirecting to sign in…</small>
    </FullScreen>
  );
}
