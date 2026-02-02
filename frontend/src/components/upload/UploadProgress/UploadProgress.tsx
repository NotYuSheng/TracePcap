import './UploadProgress.css';

interface UploadProgressProps {
  fileName: string;
  progress: number;
  isUploading: boolean;
  error?: string;
  onCancel?: () => void;
}

export const UploadProgress = ({
  fileName,
  progress,
  isUploading,
  error,
  onCancel,
}: UploadProgressProps) => {
  const getStatusText = () => {
    if (error) return 'Upload failed';
    if (progress === 100 && isUploading) return 'Processing...';
    if (progress === 100) return 'Upload complete';
    return 'Uploading...';
  };

  const getStatusClass = () => {
    if (error) return 'error';
    if (progress === 100) return 'success';
    return 'uploading';
  };

  return (
    <div className={`upload-progress ${getStatusClass()}`}>
      <div className="upload-progress-header">
        <div className="file-info">
          <i className="bi bi-file-earmark-binary"></i>
          <span className="file-name">{fileName}</span>
        </div>
        <div className="upload-actions">
          {isUploading && progress < 100 && onCancel && (
            <button type="button" className="btn btn-sm btn-outline-danger" onClick={onCancel}>
              Cancel
            </button>
          )}
          {!isUploading && progress === 100 && !error && (
            <i className="bi bi-check-circle-fill text-success"></i>
          )}
          {error && <i className="bi bi-x-circle-fill text-danger"></i>}
        </div>
      </div>

      <div className="upload-progress-bar">
        <div className="progress">
          <div
            className={`progress-bar ${error ? 'bg-danger' : 'bg-primary'}`}
            role="progressbar"
            style={{ width: `${progress}%` }}
            aria-valuenow={progress}
            aria-valuemin={0}
            aria-valuemax={100}
          >
            {progress}%
          </div>
        </div>
      </div>

      <div className="upload-status">
        <span className="status-text">{getStatusText()}</span>
        {error && <span className="error-text">{error}</span>}
      </div>
    </div>
  );
};
