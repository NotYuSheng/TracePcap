import './UploadProgress.css';

interface UploadProgressProps {
  fileName: string;
  progress: number;
  isUploading: boolean;
  error?: string;
  onAnalyze?: () => void;
}

export const UploadProgress = ({
  fileName,
  progress,
  isUploading,
  error,
  onAnalyze,
}: UploadProgressProps) => {
  const isProcessing = progress === 100 && isUploading;
  const isDone = progress === 100 && !isUploading && !error;

  const statusText = error
    ? 'Upload failed'
    : isProcessing
      ? 'Processing…'
      : isDone
        ? 'Complete'
        : `Uploading ${progress}%`;

  const stateClass = error ? 'error' : isDone ? 'success' : '';

  return (
    <div className={`upload-status-card ${stateClass}`}>
      {/* Icon */}
      <div className="usc-icon">
        <i className={`bi ${error ? 'bi-file-earmark-x' : isDone ? 'bi-file-earmark-check' : 'bi-file-earmark-arrow-up'}`}></i>
      </div>

      {/* File name + progress bar */}
      <div className="usc-body">
        <div className="usc-filename" title={fileName}>{fileName}</div>
        <div className="progress usc-bar">
          <div
            className={`progress-bar ${
              error
                ? 'bg-danger'
                : isProcessing
                  ? 'progress-bar-striped progress-bar-animated bg-warning'
                  : 'bg-primary'
            }`}
            role="progressbar"
            style={{ width: `${isProcessing ? 100 : progress}%` }}
            aria-valuenow={isProcessing ? 100 : progress}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        </div>
        <div className="usc-status">{statusText}</div>
        {error && <div className="usc-error">{error}</div>}
      </div>

      {/* Action */}
      <div className="usc-action">
        {isDone && onAnalyze && (
          <button className="btn btn-sm btn-primary" onClick={onAnalyze}>
            <i className="bi bi-graph-up me-1"></i>
            Analyze
          </button>
        )}
        {isDone && !onAnalyze && (
          <i className="bi bi-check-circle-fill text-success usc-icon-lg"></i>
        )}
        {error && <i className="bi bi-x-circle-fill text-danger usc-icon-lg"></i>}
      </div>
    </div>
  );
};
