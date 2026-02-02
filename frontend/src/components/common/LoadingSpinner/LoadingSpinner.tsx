import './LoadingSpinner.css';

interface LoadingSpinnerProps {
  size?: 'small' | 'medium' | 'large';
  message?: string;
  fullPage?: boolean;
}

export const LoadingSpinner = ({
  size = 'medium',
  message,
  fullPage = false,
}: LoadingSpinnerProps) => {
  const sizeClass = `spinner-${size}`;

  if (fullPage) {
    return (
      <div className="loading-spinner-fullpage">
        <div className={`spinner-border text-primary ${sizeClass}`} role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
        {message && <p className="loading-message">{message}</p>}
      </div>
    );
  }

  return (
    <div className="loading-spinner">
      <div className={`spinner-border text-primary ${sizeClass}`} role="status">
        <span className="visually-hidden">Loading...</span>
      </div>
      {message && <p className="loading-message">{message}</p>}
    </div>
  );
};
