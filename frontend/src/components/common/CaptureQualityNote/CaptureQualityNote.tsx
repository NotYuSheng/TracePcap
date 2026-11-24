import { useEffect, useState } from 'react';
import { captureQualityService, type CaptureQuality } from '@/features/captureQuality/captureQualityService';

/**
 * How complete the capture is (#1268): gaps, connections already open when it began, sessions
 * Suricata stopped inspecting. Shown only when there is something to say, because its job is to
 * stop an absence (no alert, no answer) reading as a clean result.
 */
export function CaptureQualityNote({ fileId }: { fileId: string }) {
  const [q, setQ] = useState<CaptureQuality | null>(null);
  useEffect(() => {
    let live = true;
    captureQualityService
      .get(fileId)
      .then((r) => live && setQ(r))
      .catch(() => live && setQ(null));
    return () => {
      live = false;
    };
  }, [fileId]);
  if (!q || q.notes.length === 0) return null;
  return (
    <div className="small mt-2" data-testid="capture-quality">
      <div className="fw-semibold text-muted mb-1">
        <i className="bi bi-clipboard-pulse me-1" aria-hidden="true" />
        Capture completeness
      </div>
      <ul className="mb-0 ps-3">
        {q.notes.map((n) => (
          <li
            key={n.kind}
            className={n.level === 'warning' ? 'text-warning-emphasis' : 'text-muted'}
            data-testid={`capture-quality-${n.kind}`}
          >
            {n.level === 'warning' && <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />}
            {n.text}
          </li>
        ))}
      </ul>
    </div>
  );
}
