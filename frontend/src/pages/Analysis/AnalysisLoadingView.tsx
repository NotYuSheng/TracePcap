import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { formatBytes } from '@/utils/formatters';

interface FileMetadata {
  fileName: string;
  fileSize: number;
  // Backend stage-weighted estimate: accounts for which analysis stages this file will run
  // (nDPI / Suricata / file extraction), not just its size. Null when size is unknown.
  estimatedAnalysisSeconds: number | null;
  enableNdpi: boolean;
  enableSuricata: boolean;
  enableFileExtraction: boolean;
}

// Live, backend-reported stage progress (GET /analysis/{id}/progress). `percent` is the weighted
// fraction of work completed before the current stage — it holds steady while an opaque external
// stage (Suricata, nDPI, file extraction) runs, so we animate the bar rather than fake movement.
interface AnalysisProgress {
  stageIndex: number;
  totalStages: number;
  stage: string;
  percent: number;
}

interface Props {
  fileId: string;
}

// Fallback only, used before the first progress report arrives / if progress isn't tracked:
// ~0.5 s/MB (all stages on).
const SECONDS_PER_MB = 0.5;
const MIN_ESTIMATE_S = 10;


function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

export const AnalysisLoadingView = ({ fileId }: Props) => {
  const [fileMeta, setFileMeta] = useState<FileMetadata | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);

  // Fetch file metadata
  useEffect(() => {
    apiClient
      .get(API_ENDPOINTS.FILE_METADATA(fileId))
      .then(res => {
        const d = res.data;
        setFileMeta({
          fileName: d.fileName,
          fileSize: d.fileSize,
          estimatedAnalysisSeconds: d.estimatedAnalysisSeconds ?? null,
          enableNdpi: d.enableNdpi,
          enableSuricata: d.enableSuricata,
          enableFileExtraction: d.enableFileExtraction,
        });
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

  // Poll live backend progress. 204 = nothing tracked (not started / already finishing / dropped on
  // a restart); we keep the last known value on 204 so the bar doesn't flash back to the fallback in
  // the brief window between the pipeline clearing progress and the summary poll flipping to 200.
  useEffect(() => {
    let cancelled = false;
    const poll = () => {
      apiClient
        .get(API_ENDPOINTS.ANALYSIS_PROGRESS(fileId), {
          validateStatus: s => s === 200 || s === 204,
        })
        .then(res => {
          if (cancelled) return;
          if (res.status === 200 && res.data && typeof res.data.percent === 'number') {
            setProgress(res.data);
          }
        })
        .catch(() => {
          // transient error — keep last known progress
        });
    };
    poll();
    const id = setInterval(poll, 2000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [fileId]);

  // Prefer the backend's stage-weighted estimate; fall back to the size-only heuristic.
  const estimatedSeconds = fileMeta
    ? (fileMeta.estimatedAnalysisSeconds ??
        Math.max(MIN_ESTIMATE_S, (fileMeta.fileSize / 1024 / 1024) * SECONDS_PER_MB))
    : null;

  const enabledStages: string[] = [];
  if (fileMeta?.enableNdpi) enabledStages.push('nDPI');
  if (fileMeta?.enableSuricata) enabledStages.push('Suricata');
  if (fileMeta?.enableFileExtraction) enabledStages.push('file extraction');

  // Bar position: prefer real backend stage progress. It advances on true milestones and holds
  // between them (the striped animation conveys ongoing work). Before the first report arrives, fall
  // back to a time-interpolated bar so it isn't empty. A small floor keeps the bar visible at 0%.
  const barPct = progress
    ? Math.max(3, progress.percent)
    : estimatedSeconds
      ? Math.min(95, (elapsed / estimatedSeconds) * 100)
      : null;

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

        {/* Current stage (real backend milestone) */}
        {progress && (
          <p className="mb-2 text-body" style={{ fontSize: '0.85rem' }}>
            <span className="text-secondary">
              Stage {progress.stageIndex} of {progress.totalStages}:
            </span>{' '}
            <strong>{progress.stage}…</strong>
          </p>
        )}

        {/* Progress bar */}
        {barPct != null && (
          <div className="progress mb-3" style={{ height: 8 }}>
            <div
              className="progress-bar progress-bar-striped progress-bar-animated"
              role="progressbar"
              aria-valuenow={Math.round(barPct)}
              aria-valuemin={0}
              aria-valuemax={100}
              style={{ width: `${barPct}%`, transition: 'width 0.4s ease' }}
            />
          </div>
        )}

        {/* Timer row */}
        <div className="d-flex justify-content-between text-muted" style={{ fontSize: '0.82rem' }}>
          <span>
            <i className="bi bi-stopwatch me-1" />
            Elapsed: <strong className="text-body">{formatDuration(elapsed)}</strong>
          </span>
          {estimatedSeconds != null && (
            <span>
              Est. time: <strong className="text-body">~{formatDuration(estimatedSeconds)}</strong>
            </span>
          )}
        </div>

        {/* Stages included in the estimate */}
        {fileMeta && (
          <p className="text-muted mt-2 mb-0" style={{ fontSize: '0.78rem' }}>
            Estimate includes{' '}
            {enabledStages.length > 0 ? (
              <strong className="text-body">{enabledStages.join(', ')}</strong>
            ) : (
              'core parsing only'
            )}
            .
          </p>
        )}

        {/* Hint */}
        <p className="text-muted mt-2 mb-0" style={{ fontSize: '0.78rem' }}>
          Larger files take longer. You can leave this page and come back — analysis continues in
          the background.
        </p>
      </div>
    </div>
  );
};
