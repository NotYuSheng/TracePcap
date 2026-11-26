import { useEffect, useState } from 'react';
import { suricataService, type SuricataStatus } from './suricataService';

// One request shared by every component on the page; cleared once settled so a later mount sees an
// import that happened since.
let inflight: Promise<SuricataStatus> | null = null;

/** The Suricata ruleset in use (#600), or null while loading or if the request failed. */
export function useSuricataStatus(): SuricataStatus | null {
  const [status, setStatus] = useState<SuricataStatus | null>(null);
  useEffect(() => {
    let active = true;
    if (!inflight) {
      inflight = suricataService.getStatus().finally(() => {
        inflight = null;
      });
    }
    inflight.then(s => active && setStatus(s)).catch(() => active && setStatus(null));
    return () => {
      active = false;
    };
  }, []);
  return status;
}
