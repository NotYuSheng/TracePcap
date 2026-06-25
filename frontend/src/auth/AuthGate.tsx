import { type ReactNode, useEffect } from 'react';
import { useAuth } from 'react-oidc-context';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Button } from '@govtechsg/sgds-react';

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
 * state during the round-trip, and surfaces errors with a retry. Renders children only once the user
 * is authenticated. (The axios client reads the token directly from storage — see tokenStore.)
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const auth = useAuth();

  // Kick off login once the initial state has settled and we're not already mid-flight. The current
  // path+query is passed as `state` so onSigninCallback can return the user to their deep link.
  useEffect(() => {
    if (!auth.isLoading && !auth.isAuthenticated && !auth.activeNavigator && !auth.error) {
      void auth.signinRedirect({ state: window.location.pathname + window.location.search });
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
