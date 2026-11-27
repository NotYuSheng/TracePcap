import { useEffect, useState } from 'react';
import type { Honeypots } from '@/types';
import { storyService } from '@/features/story/services/storyService';
import { HoneypotHostBody } from '@components/story/StorySummary/HoneypotLine';

interface Props {
  fileId: string;
  ip: string;
}

/**
 * Is this host a honeypot? Shown for every host, not only the ones the signatures flagged, so an
 * analyst can mark a decoy TracePcap missed (a high-interaction honeypot looks like a real server)
 * or undo an answer they gave from the Story summary.
 */
export function HoneypotRoleSection({ fileId, ip }: Props) {
  // The last read, keyed by the host it was for: a stale one (another ip) shows as loading.
  const [read, setRead] = useState<{ ip: string; honeypots: Honeypots | null } | null>(null);
  // Bumped after an override or evidence change, to re-read the host's role.
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let alive = true;
    storyService
      .getHoneypotRole(fileId, ip)
      .then(r => { if (alive) setRead({ ip, honeypots: r }); })
      .catch(() => { if (alive) setRead({ ip, honeypots: null }); });
    return () => { alive = false; };
  }, [fileId, ip, version]);

  const current = read?.ip === ip ? read : null;
  const failed = !!current && !current.honeypots;
  const honeypots = current?.honeypots ?? null;
  const host = honeypots?.hosts.find(h => h.host === ip) ?? null;
  return (
    <div className="mb-4" data-testid="host-honeypot-role">
      {failed && <p className="text-muted small fst-italic mb-0">Couldn&apos;t read this host&apos;s honeypot role.</p>}
      {!failed && !host && <p className="text-muted small mb-0">Reading its banners and certificates…</p>}
      {!failed && host && honeypots && (
        <HoneypotHostBody
          fileId={fileId}
          honeypots={honeypots}
          host={host}
          onChanged={() => setVersion(v => v + 1)}
          compact
        />
      )}
    </div>
  );
}
