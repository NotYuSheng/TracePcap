import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router-dom';
import { router } from '@/router';
import { env } from '@/config/env';
import { AppAuthProvider } from '@/auth/AppAuthProvider';
import '@/assets/styles/index.css';

// Gate the whole app behind OIDC login only when auth is enabled at build time. When it's off, the
// router renders directly with no auth context — identical to the pre-auth behaviour.
const app = env.AUTH_ENABLED ? (
  <AppAuthProvider>
    <RouterProvider router={router} />
  </AppAuthProvider>
) : (
  <RouterProvider router={router} />
);

createRoot(document.getElementById('root')!).render(<StrictMode>{app}</StrictMode>);
