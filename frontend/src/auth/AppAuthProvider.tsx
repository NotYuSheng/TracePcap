import { type ReactNode, useEffect } from 'react';
import { AuthProvider, useAuth } from 'react-oidc-context';
import { oidcConfig } from './oidcConfig';
import { AuthGate } from './AuthGate';
import { setReauthHandler } from './tokenStore';

/**
 * Bridges the OIDC layer to the axios client (which lives outside React): registers a re-login
 * callback the response interceptor invokes on a 401. Preserves the deep link so the user returns to
 * the page they were on after signing back in.
 */
function ReauthBridge() {
  const auth = useAuth();
  useEffect(() => {
    setReauthHandler(() =>
      void auth.signinRedirect({ state: window.location.pathname + window.location.search }),
    );
    return () => setReauthHandler(null);
  }, [auth]);
  return null;
}

/**
 * Top-level auth wrapper, mounted only when {@code env.AUTH_ENABLED} is true (see `main.tsx`).
 * Provides the OIDC context and gates the app behind a successful login.
 */
export function AppAuthProvider({ children }: { children: ReactNode }) {
  return (
    <AuthProvider {...oidcConfig}>
      <ReauthBridge />
      <AuthGate>{children}</AuthGate>
    </AuthProvider>
  );
}
