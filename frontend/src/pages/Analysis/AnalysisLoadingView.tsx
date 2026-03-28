import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

interface FileMetadata {
  fileName: string;
  fileSize: number;
}

interface Props {
  fileId: string;
}

// Rough estimate: ~0.75 seconds per MB for parsing + DB insert pipeline
const SECONDS_PER_MB = 0.75;
const MIN_ESTIMATE_S = 10;

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

export const AnalysisLoadingView = ({ fileId }: Props) => {
  const [fileMeta, setFileMeta] = useState<FileMetadata | null>(null);
  const [elapsed, setElapsed] = useState(0);

  // Fetch file metadata
  useEffect(() => {
    apiClient
      .get(API_ENDPOINTS.FILE_METADATA(fileId))
      .then(res => {
        const d = res.data;
        setFileMeta({ fileName: d.fileName, fileSize: d.fileSize });
      })
      .catch(() => {
        // ignore — we'll render without file details
      });
  }, [fileId]);

  // Running elapsed timer
  useEffect(() => {
    const start = Date.now();
    const id = setInterval(() => {
      setElapsed(Math.floor((Date.now() - start) / 1000));
    }, 1000);
    return () => clearInterval(id);
  }, []);

  const estimatedSeconds = fileMeta
    ? Math.max(MIN_ESTIMATE_S, (fileMeta.fileSize / 1024 / 1024) * SECONDS_PER_MB)
    : null;

  // Progress: clamp to 95% so the bar never reaches 100% while still loading
  const progressPct = estimatedSeconds
    ? Math.min(95, (elapsed / estimatedSeconds) * 100)
    : null;

  const remaining =
    estimatedSeconds != null ? Math.max(0, estimatedSeconds - elapsed) : null;

  return (
    <div className="d-flex justify-content-center align-items-center" style={{ minHeight: '60vh' }}>
      <div className="text-center" style={{ maxWidth: 480, width: '100%' }}>
        {/* Animated icon */}
        <div className="mb-4">
          <i
            className="bi bi-cpu"
            style={{ fontSize: '3rem', color: 'var(--sgds-primary, #5925DC)', opacity: 0.85 }}
          />
        </div>

        <h5 className="mb-1">Analysing file…</h5>

        {fileMeta ? (
          <p className="text-muted mb-4" style={{ fontSize: '0.9rem' }}>
            <i className="bi bi-file-earmark-binary me-1" />
            <strong>{fileMeta.fileName}</strong>
            <span className="ms-2 text-secondary">({formatBytes(fileMeta.fileSize)})</span>
          </p>
        ) : (
          <p className="text-muted mb-4" style={{ fontSize: '0.9rem' }}>
            Fetching file details…
          </p>
        )}

        {/* Progress bar */}
        {progressPct != null && (
          <div className="progress mb-3" style={{ height: 8 }}>
            <div
              className="progress-bar progress-bar-striped progress-bar-animated"
              role="progressbar"
              style={{ width: `${progressPct}%` }}
            />
          </div>
        )}

        {/* Timer row */}
        <div className="d-flex justify-content-between text-muted" style={{ fontSize: '0.82rem' }}>
          <span>
            <i className="bi bi-stopwatch me-1" />
            Elapsed: <strong className="text-body">{formatDuration(elapsed)}</strong>
          </span>
          {remaining != null && remaining > 0 && (
            <span>
              Est. remaining: <strong className="text-body">~{formatDuration(remaining)}</strong>
            </span>
          )}
          {remaining != null && remaining <= 0 && (
            <span className="text-muted">Almost done…</span>
          )}
        </div>

        {/* Hint */}
        <p className="text-muted mt-4 mb-0" style={{ fontSize: '0.78rem' }}>
          Larger files take longer. You can leave this page and come back — analysis continues in
          the background.
        </p>
      </div>
    </div>
  );
};
