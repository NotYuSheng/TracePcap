import { useState } from 'react';

const IPS_SHOWN = 3;

/** Resolved addresses: the first few, the rest behind "+N more" so one big answer doesn't fill the list. */
export function IpList({ ips }: { ips: string[] }) {
  const [open, setOpen] = useState(false);
  const shown = open ? ips : ips.slice(0, IPS_SHOWN);
  const rest = ips.length - IPS_SHOWN;
  return (
    <>
      <span className="font-monospace">{shown.join(', ')}</span>
      {rest > 0 && (
        <button type="button" className="btn btn-link btn-sm p-0 ms-1 svc-more" onClick={() => setOpen(o => !o)} aria-expanded={open}>
          {open ? 'show fewer' : `+${rest} more`}
        </button>
      )}
    </>
  );
}
