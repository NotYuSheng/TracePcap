import type { ReactNode } from 'react';
import { AuthProvider } from 'react-oidc-context';
import { oidcConfig } from './oidcConfig';
import { AuthGate } from './AuthGate';

/**
 * Top-level auth wrapper, mounted only when {@code env.AUTH_ENABLED} is true (see `main.tsx`).
 * Provides the OIDC context and gates the app behind a successful login.
 */
export function AppAuthProvider({ children }: { children: ReactNode }) {
  return (
    <AuthProvider {...oidcConfig}>
      <AuthGate>{children}</AuthGate>
    </AuthProvider>
  );
}
