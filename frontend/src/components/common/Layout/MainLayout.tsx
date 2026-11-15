import { Spinner } from '@components/common/Spinner/Spinner';
import { useEffect, useRef, useState } from 'react';
import { Link, Outlet, useLocation } from 'react-router-dom';
import { Button, Container, Navbar, Nav } from '@govtechsg/sgds-react';
import { Activity } from 'lucide-react';
import { usePreferencesSync } from '@/features/preferences/usePreferencesSync';
import { AuthMenu } from '@/auth/AuthMenu';
import { getAccessToken } from '@/auth/tokenStore';
import { env } from '@/config/env';
import { directApiUrl } from '@/services/api/directUrl';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { useEscapeLayerRoot } from '@/utils/useEscapeLayer';
import { useStore } from '@/store';
import type { ThemeMode } from '@/store';

function useBackendReady() {
  const [ready, setReady] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timerId: number;

    async function check() {
      try {
        // Carry the OIDC token when present so the probe is an authorized round-trip. Any HTTP
        // response means the backend is reachable — under auth a tokenless (or not-yet-synced)
        // probe may return 401, which still proves it's up; real content calls use the axios client.
        const token = getAccessToken();
        const res = await fetch(directApiUrl(API_ENDPOINTS.SYSTEM_LIMITS), {
          headers: token ? { Authorization: `Bearer ${token}` } : undefined,
        });
        // A 401/403 still proves the backend is reachable (auth-gated, tokenless probe); other 4xx
        // would indicate a broken contract and should keep the startup gate closed.
        if (res.ok || res.status === 401 || res.status === 403) {
          if (!cancelled) setReady(true);
          return;
        }
      } catch {
        // network error — backend not up yet
      }
      if (!cancelled) {
        setReady(false);
        timerId = window.setTimeout(check, 3000);
      }
    }

    check();
    return () => {
      cancelled = true;
      clearTimeout(timerId);
    };
  }, []);

  return ready;
}

const THEME_ICONS: Record<ThemeMode, string> = {
  light: 'bi-sun',
  dark: 'bi-moon-stars',
  system: 'bi-circle-half',
};

const THEME_LABELS: Record<ThemeMode, string> = {
  light: 'Light mode — click for dark',
  dark: 'Dark mode — click for system',
  system: 'System mode — click for light',
};

function useResolvedDark(themeMode: ThemeMode): boolean {
  const [sysDark, setSysDark] = useState(
    () => window.matchMedia('(prefers-color-scheme: dark)').matches
  );
  useEffect(() => {
    if (themeMode !== 'system') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => setSysDark(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [themeMode]);
  if (themeMode === 'light') return false;
  if (themeMode === 'dark') return true;
  return sysDark;
}

export const MainLayout = () => {
  // Personal preferences live on the server (#915): per account with login on, shared when off.
  usePreferencesSync();
  const backendReady = useBackendReady();
  const themeMode = useStore(s => s.themeMode);
  const cycleTheme = useStore(s => s.cycleTheme);
  const isDark = useResolvedDark(themeMode);
  const location = useLocation();
  const isMonitorActive = location.pathname.startsWith('/monitor');
  const isSystemActive = location.pathname.startsWith('/settings') || location.pathname.startsWith('/system');
  // Pages with a section rail (a capture's analysis, a monitored network) run edge to edge: the
  // rail sits flush against the window's left side, under the header.
  const isFlush = /^\/(analysis|monitor)\/[^/]+/.test(location.pathname);

  // The header's height, so a sticky rail can sit right under it whatever the header wraps to.
  const headerRef = useRef<HTMLElement>(null);
  useEffect(() => {
    const el = headerRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const set = () => document.documentElement.style.setProperty('--tp-header-h', `${el.offsetHeight}px`);
    set();
    const ro = new ResizeObserver(set);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Keeps the shared Escape coordinator alive for the whole session (#535).
  useEscapeLayerRoot();

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  }, [isDark]);

  const mainContent =
    backendReady === true ? (
      <Outlet />
    ) : (
      <div className="d-flex flex-column align-items-center justify-content-center gap-3 py-5 text-muted">
        <Spinner animation="border" className="text-primary" />
        <div className="text-center">
          <p className="mb-1 fw-semibold">Backend is starting up…</p>
          <small>This may take up to a minute on first launch.</small>
        </div>
      </div>
    );

  const isAnalyseActive = !isMonitorActive && !isSystemActive;

  return (
    <div className="main-layout">
      <header className="main-header" ref={headerRef}>
        <Navbar expand="lg" hasBorderBottom className="main-navbar">
          <Container fluid className="main-navbar-inner">
            <Navbar.Brand as={Link} to="/" className="main-brand">
              <Activity size={22} className="text-primary" aria-hidden="true" />
              <span>TracePcap</span>
            </Navbar.Brand>

            <Navbar.Toggle />
            <Navbar.Collapse className="align-items-center">
              <Nav className="me-auto">
                <Nav.Link as={Link} to="/" active={isAnalyseActive}>
                  <i className="bi bi-search me-1"></i>Analyse
                </Nav.Link>
                <Nav.Link as={Link} to="/monitor" active={isMonitorActive}>
                  <i className="bi bi-activity me-1"></i>Monitor
                </Nav.Link>
              </Nav>

              <div className="d-flex align-items-center gap-2 ms-auto">
                <Button
                  type="button"
                  size="sm"
                  variant="outline-secondary"
                  onClick={cycleTheme}
                  aria-label={THEME_LABELS[themeMode]}
                  title={THEME_LABELS[themeMode]}
                >
                  <i className={`bi ${THEME_ICONS[themeMode]}`}></i>
                </Button>
                {/* Settings: a page (your own, and the install's), opened from the gear on the right. */}
                <Link
                  to="/settings"
                  className={`btn btn-sm ${isSystemActive ? 'btn-secondary' : 'btn-outline-secondary'}`}
                  aria-label="Settings"
                  title="Settings"
                  aria-current={isSystemActive ? 'page' : undefined}
                >
                  <i className="bi bi-gear" aria-hidden="true"></i>
                </Link>
                {env.AUTH_ENABLED && <AuthMenu />}
              </div>
            </Navbar.Collapse>
          </Container>
        </Navbar>
      </header>
      <main className={`main-content${isFlush ? ' main-content-flush' : ''}`}>{mainContent}</main>
      <footer className="main-footer mt-auto">
        <Container fluid className="main-navbar-inner d-flex justify-content-between flex-wrap gap-2 text-muted">
          <span>TracePcap · network traffic analysis</span>
          <span className="opacity-75">{__APP_VERSION__}</span>
        </Container>
      </footer>
    </div>
  );
};
