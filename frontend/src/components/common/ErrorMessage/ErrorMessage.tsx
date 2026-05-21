import { Alert, Button } from '@govtechsg/sgds-react';
import './ErrorMessage.css';

interface ErrorMessageProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorMessage = ({ title = 'Error', message, onRetry }: ErrorMessageProps) => {
  return (
    <div className="error-message-container">
      <Alert variant="danger" role="alert">
        <div className="error-icon">
          <i className="bi bi-exclamation-triangle-fill"></i>
        </div>
        <div className="error-content">
          <h5 className="error-title">{title}</h5>
          <p className="error-text">{message}</p>
          {onRetry && (
            <Button size="sm" variant="outline-danger" onClick={onRetry}>
              <i className="bi bi-arrow-clockwise"></i> Retry
            </Button>
          )}
        </div>
      </Alert>
    </div>
  );
};
