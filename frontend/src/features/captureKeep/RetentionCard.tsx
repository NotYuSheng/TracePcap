import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Button, Card } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';
import { captureKeepService, EXTEND_DAYS, extendedTo, ownExpiry } from './captureKeepService';

interface CaptureFacts {
  fileId: string;
  source?: string;
  uploadedAt: string | number[];
  keepForever?: boolean;
  expiresAt?: string | number[] | null;
}

type Membership = { fileId: string; networkId: string; networkName: string };

function when(ms: number): string {
  return new Date(ms).toLocaleString(undefined, {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * When this capture is deleted, and the controls to change it: keep it a few days longer, keep it
 * forever, or put it back on the retention window. The same choices as the captures list's menu.
 */
export function RetentionCard({ fileId }: { fileId: string }) {
  const [facts, setFacts] = useState<CaptureFacts | null>(null);
  const [retentionHours, setRetentionHours] = useState<number | null>(null);
  const [monitorHours, setMonitorHours] = useState<number | null>(null);
  const [keptWith, setKeptWith] = useState<Membership[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(() => {
    apiClient
      .get<CaptureFacts>(API_ENDPOINTS.FILE_METADATA(fileId))
      .then(r => {
        setFacts(r.data);
        setNow(Date.now());
      })
      .catch(() => setError("Couldn't load when this capture is deleted."));
  }, [fileId]);

  useEffect(() => {
    load();
    apiClient
      .get<{ fileRetentionHours?: number; monitorFileRetentionHours?: number }>(API_ENDPOINTS.SYSTEM_LIMITS)
      .then(r => {
        setRetentionHours(r.data.fileRetentionHours ?? null);
        setMonitorHours(r.data.monitorFileRetentionHours ?? null);
      })
      .catch(() => {});
    apiClient
      .get<Membership[]>(API_ENDPOINTS.NETWORK_MEMBERSHIPS)
      .then(r => setKeptWith(r.data.filter(m => m.fileId === fileId)))
      .catch(() => {});
  }, [fileId, load]);

  if (!facts) {
    return error ? <Alert variant="warning">{error}</Alert> : null;
  }

  const uploaded = parseDateTime(facts.uploadedAt);
  const own = ownExpiry(facts.expiresAt);
  const windowEnd = retentionHours ? uploaded + retentionHours * 3600_000 : null;
  const monitor = facts.source === 'MONITOR' || keptWith.length > 0;
  const deadline = facts.keepForever ? null : (own ?? windowEnd);

  const change = async (c: { keepForever: boolean; expiresAt?: number | null }) => {
    setBusy(true);
    setError(null);
    try {
      await captureKeepService.setExpiry(fileId, c);
      load();
    } catch {
      setError("Couldn't change when this capture is deleted.");
    } finally {
      setBusy(false);
    }
  };

  let summary: React.ReactNode;
  if (facts.keepForever) {
    summary = <>Kept until someone deletes it.</>;
  } else if (monitor) {
    const networks = keptWith.map(m => (
      <Link key={m.networkId} to={`/monitor/${m.networkId}`}>
        {m.networkName}
      </Link>
    ));
    summary =
      keptWith.length > 0 ? (
        <>
          Kept with {networks.reduce<React.ReactNode[]>((a, n, i) => (i ? [...a, ', ', n] : [n]), [])}:{' '}
          {monitorHours ? `deleted ${monitorHours} hours after upload, by the monitor retention` : 'not deleted on a timer'}.
        </>
      ) : (
        <>A monitor upload: {monitorHours ? `deleted ${monitorHours} hours after upload` : 'not deleted on a timer'}.</>
      );
  } else if (!retentionHours) {
    summary = <>Captures aren't deleted on a timer.</>;
  } else if (own != null) {
    summary = (
      <>
        Deleted on <b>{when(own)}</b>, kept past the {retentionHours}-hour retention window.
      </>
    );
  } else {
    summary = (
      <>
        Deleted on <b>{when(windowEnd!)}</b>, {retentionHours} hours after upload (the retention
        window, set in <Link to="/settings?tab=system">Settings</Link>).
      </>
    );
  }
  // Putting a kept capture back on the window deletes it at the next cleanup if the window has passed.
  const backIsPast = windowEnd != null && windowEnd <= now;

  return (
    <Card className="mb-4">
      <Card.Body>
        <h5 className="mb-2">Retention</h5>
        <p className="mb-3">{summary}</p>
        {error && (
          <Alert variant="warning" className="py-2 small">
            {error}
          </Alert>
        )}
        {!monitor && !!retentionHours && (
          <div className="d-flex flex-wrap gap-2 align-items-center">
            {facts.keepForever ? (
              <>
                <Button size="sm" variant="outline-secondary" disabled={busy} onClick={() => change({ keepForever: false })}>
                  Let it expire
                </Button>
                {backIsPast && (
                  <span className="small text-muted">
                    It's past the {retentionHours}-hour window, so the next cleanup would delete it.
                  </span>
                )}
              </>
            ) : (
              <>
                {EXTEND_DAYS.map(d => (
                  <Button
                    key={d}
                    size="sm"
                    variant="outline-primary"
                    disabled={busy}
                    onClick={() => change({ keepForever: false, expiresAt: extendedTo(deadline, d, now) })}
                  >
                    Keep {d} {d === 1 ? 'day' : 'days'} longer
                  </Button>
                ))}
                <Button size="sm" variant="primary" disabled={busy} onClick={() => change({ keepForever: true })}>
                  Keep forever
                </Button>
                {own != null && (
                  <Button size="sm" variant="link" disabled={busy} onClick={() => change({ keepForever: false })}>
                    Back to the retention window
                  </Button>
                )}
              </>
            )}
          </div>
        )}
      </Card.Body>
    </Card>
  );
}
