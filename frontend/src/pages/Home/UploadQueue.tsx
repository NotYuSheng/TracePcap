import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { UploadEntry } from '@features/upload/hooks/useFileUpload';
import { formatBytes } from '@/utils/formatters';

/** A file the drop zone turned away, with why in plain words. */
export interface Rejected {
  name: string;
  reason: string;
}

interface Progress {
  stageIndex: number;
  totalStages: number;
  stage: string;
  percent: number;
}

type Phase =
  | { kind: 'uploading' }
  | { kind: 'analysing'; progress: Progress | null }
  | { kind: 'ready'; packets: number | null }
  | { kind: 'failed' };

const POLL_MS = 2000;

/** Follows an uploaded capture through analysis until it is ready or fails. */
function useAnalysisPhase(fileId: string | undefined): Phase | null {
  const [phase, setPhase] = useState<Phase | null>(null);
  useEffect(() => {
    if (!fileId) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const { data } = await apiClient.get<{ status: string; packetCount?: number | null }>(
          API_ENDPOINTS.FILE_METADATA(fileId),
        );
        const status = data.status.toUpperCase();
        if (!alive) return;
        if (status === 'COMPLETED') {
          setPhase({ kind: 'ready', packets: data.packetCount ?? null });
          return;
        }
        if (status === 'FAILED') {
          setPhase({ kind: 'failed' });
          return;
        }
        const res = await apiClient.get<Progress>(API_ENDPOINTS.ANALYSIS_PROGRESS(fileId), {
          validateStatus: s => s === 200 || s === 204,
        });
        if (!alive) return;
        setPhase(prev => ({
          kind: 'analysing',
          progress:
            res.status === 200 && typeof res.data?.percent === 'number'
              ? res.data
              : prev?.kind === 'analysing'
                ? prev.progress
                : null,
        }));
      } catch {
        // A blip: try again on the next tick.
      }
      if (alive) timer = setTimeout(poll, POLL_MS);
    };
    poll();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [fileId]);
  return phase;
}

function UploadRow({ u }: { u: UploadEntry }) {
  const analysis = useAnalysisPhase(!u.error && !u.isDuplicate ? u.fileId : undefined);
  const to = u.fileId ? `/analysis/${u.fileId}` : undefined;

  if (u.isDuplicate) {
    return (
      <li className="upload-row upload-row-warn">
        <div className="upload-row-name">{u.fileName}</div>
        <div className="upload-row-meta">Already analysed. Nothing was uploaded again.</div>
        {u.duplicateOfFileId && (
          <Link to={`/analysis/${u.duplicateOfFileId}`} className="upload-row-link">
            Open that analysis
          </Link>
        )}
      </li>
    );
  }
  if (u.error || analysis?.kind === 'failed') {
    return (
      <li className="upload-row upload-row-bad">
        <div className="upload-row-name">{u.fileName}</div>
        <div className="upload-row-meta">
          {u.error ? `Couldn’t upload: ${u.error}` : 'Analysis failed. Open it to see why.'}
        </div>
        {to && !u.error && (
          <Link to={to} className="upload-row-link">
            See why
          </Link>
        )}
      </li>
    );
  }
  if (analysis?.kind === 'ready') {
    return (
      <li className="upload-row upload-row-ok">
        <span className="upload-row-dot" aria-hidden="true" />
        <div className="flex-grow-1 min-w-0">
          <div className="upload-row-name">{u.fileName}</div>
          <div className="upload-row-meta upload-row-meta-ok">
            Ready{analysis.packets != null ? ` · ${analysis.packets.toLocaleString()} packets` : ''}
          </div>
        </div>
        <Link to={to!} className="btn btn-primary btn-sm">
          Open
        </Link>
      </li>
    );
  }

  const uploading = u.isUploading;
  const p = analysis?.kind === 'analysing' ? analysis.progress : null;
  const pct = uploading ? u.progress : (p?.percent ?? 0);
  return (
    <li className="upload-row">
      <div className="d-flex gap-2">
        <div className="upload-row-name flex-grow-1">{u.fileName}</div>
        <span className={uploading ? 'upload-row-meta' : 'upload-row-meta upload-row-meta-busy'}>
          {uploading ? `${u.progress}%` : 'Analysing'}
        </span>
      </div>
      <div
        className="upload-row-bar"
        role="progressbar"
        aria-label={`${uploading ? 'Upload' : 'Analysis'} progress for ${u.fileName}`}
        aria-valuenow={Math.round(pct)}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className={uploading ? 'upload-row-fill' : 'upload-row-fill upload-row-fill-busy'}
          style={{ width: `${Math.max(3, pct)}%` }}
        />
      </div>
      <div className="upload-row-meta">
        {uploading
          ? u.size
            ? `Uploading · ${formatBytes((u.size * u.progress) / 100)} of ${formatBytes(u.size)}`
            : 'Uploading'
          : p
            ? `Stage ${p.stageIndex} of ${p.totalStages}: ${p.stage}`
            : 'Starting the analysis'}
      </div>
    </li>
  );
}

/**
 * The files on their way, in the start panel: each one goes from uploading to analysing to ready
 * and opens from its row. No modal: the rest of the page stays usable.
 */
export function UploadQueue({
  uploads,
  rejected,
  onClear,
}: {
  uploads: UploadEntry[];
  rejected: Rejected[];
  onClear: () => void;
}) {
  if (uploads.length === 0 && rejected.length === 0) return null;
  const busy = uploads.some(u => u.isUploading);
  return (
    <div className="upload-queue">
      <ol className="upload-rows" aria-label="Uploads">
        {uploads.map(u => (
          <UploadRow key={u.id} u={u} />
        ))}
        {rejected.map(r => (
          <li key={`x-${r.name}`} className="upload-row upload-row-bad">
            <div className="upload-row-name">{r.name}</div>
            <div className="upload-row-meta">{r.reason}</div>
          </li>
        ))}
      </ol>
      {!busy && (
        <button type="button" className="btn btn-link btn-sm p-0 align-self-start text-muted" onClick={onClear}>
          Clear these
        </button>
      )}
    </div>
  );
}
