import './ErrorMessage.css';

interface ErrorMessageProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorMessage = ({ title = 'Error', message, onRetry }: ErrorMessageProps) => {
  return (
    <div className="error-message-container">
      <div className="alert alert-danger" role="alert">
        <div className="error-icon">
          <i className="bi bi-exclamation-triangle-fill"></i>
        </div>
        <div className="error-content">
          <h5 className="error-title">{title}</h5>
          <p className="error-text">{message}</p>
          {onRetry && (
            <button type="button" className="btn btn-sm btn-outline-danger" onClick={onRetry}>
              <i className="bi bi-arrow-clockwise"></i> Retry
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
