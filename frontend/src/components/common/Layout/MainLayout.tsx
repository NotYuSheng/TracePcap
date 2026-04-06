import { useState, useEffect } from 'react';
import { Link, Outlet } from 'react-router-dom';
import { Container, Row, Col } from '@govtechsg/sgds-react';
import { Activity } from 'lucide-react';
import { SignaturesModal } from '@components/signatures/SignaturesModal';
import { useStore } from '@/store';
import type { ThemeMode } from '@/store';

function useBackendReady() {
  const [ready, setReady] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timerId: number;

    async function check() {
      try {
        const res = await fetch('/api/system/limits');
        if (res.ok) {
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
  const [showSignatures, setShowSignatures] = useState(false);
  const backendReady = useBackendReady();
  const themeMode = useStore(s => s.themeMode);
  const cycleTheme = useStore(s => s.cycleTheme);
  const isDark = useResolvedDark(themeMode);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  }, [isDark]);

  const mainContent =
    backendReady === true ? (
      <Outlet />
    ) : (
      <div className="d-flex flex-column align-items-center justify-content-center gap-3 py-5 text-muted">
        <div className="spinner-border text-primary" role="status" aria-hidden="true" />
        <div className="text-center">
          <p className="mb-1 fw-semibold">Backend is starting up…</p>
          <small>This may take up to a minute on first launch.</small>
        </div>
      </div>
    );

  return (
    <div className="main-layout">
      <header className="main-header">
        <Container>
          <div className="d-flex align-items-center justify-content-between py-3">
            <Link to="/" style={{ textDecoration: 'none', color: 'inherit' }}>
              <div className="d-flex align-items-center gap-3">
                <Activity size={32} className="text-primary" />
                <div>
                  <h4 className="mb-0">TracePcap</h4>
                  <small className="text-muted">Network Analysis</small>
                </div>
              </div>
            </Link>
            <div className="d-flex align-items-center gap-2">
              <button
                type="button"
                className="btn btn-sm btn-outline-secondary"
                onClick={cycleTheme}
                aria-label={THEME_LABELS[themeMode]}
                title={THEME_LABELS[themeMode]}
              >
                <i className={`bi ${THEME_ICONS[themeMode]}`}></i>
              </button>
              <button
                type="button"
                className="btn btn-sm btn-outline-secondary"
                onClick={() => setShowSignatures(true)}
              >
                <i className="bi bi-shield-check me-1"></i>Custom Detection Rules
              </button>
            </div>
          </div>
        </Container>
      </header>
      <SignaturesModal show={showSignatures} onHide={() => setShowSignatures(false)} />
      <main className="main-content">{mainContent}</main>
      <footer className="main-footer mt-auto py-4">
        <Container>
          <Row>
            <Col className="text-center text-muted">
              <small>TracePcap &copy; 2026 - Network Traffic Analysis and Visualization Tool</small>
            </Col>
          </Row>
        </Container>
      </footer>
    </div>
  );
};
