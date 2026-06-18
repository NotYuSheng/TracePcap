import { Button, Container } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { isRouteErrorResponse, useRouteError, useNavigate } from 'react-router-dom';
import './RouteErrorBoundary.css';

/**
 * Catch-all error UI rendered by React Router (`errorElement`) whenever a route
 * component throws during render, or a loader/action rejects. Without this, an
 * uncaught render error unmounts the whole React tree and the user is left
 * staring at a blank white screen with no explanation. This guarantees an error
 * is always shown instead.
 */
export const RouteErrorBoundary = () => {
  const error = useRouteError();
  const navigate = useNavigate();

  let title = 'Something went wrong';
  let message =
    'An unexpected error occurred and this view could not be displayed. Try reloading the page.';

  if (isRouteErrorResponse(error)) {
    title = `${error.status} ${error.statusText}`.trim();
    if (typeof error.data === 'string' && error.data.trim()) {
      message = error.data;
    } else if (error.data && typeof error.data === 'object') {
      const data = error.data as Record<string, unknown>;
      if (typeof data.message === 'string') message = data.message;
      else if (typeof data.error === 'string') message = data.error;
    }
  }

  const detail =
    error instanceof Error
      ? error.stack || error.message
      : typeof error === 'string'
        ? error
        : undefined;

  return (
    <Container className="route-error-boundary">
      <Alert variant="danger" role="alert">
        <div className="route-error-icon">
          <i className="bi bi-exclamation-octagon-fill"></i>
        </div>
        <div className="route-error-content">
          <h5 className="route-error-title">{title}</h5>
          <p className="route-error-text">{message}</p>
          {detail && import.meta.env.DEV && (
            <pre className="route-error-detail">{detail}</pre>
          )}
          <div className="route-error-actions">
            <Button size="sm" variant="danger" onClick={() => window.location.reload()}>
              <i className="bi bi-arrow-clockwise"></i> Reload page
            </Button>
            <Button size="sm" variant="outline-danger" onClick={() => navigate('/')}>
              <i className="bi bi-house"></i> Go to home
            </Button>
          </div>
        </div>
      </Alert>
    </Container>
  );
};
