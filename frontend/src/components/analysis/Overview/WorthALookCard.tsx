import { Link } from 'react-router-dom';
import { Badge } from '@govtechsg/sgds-react';
import { SourceTag } from './SourceTag';
import type { CategoryStatus } from '@/types';
import { worthALookGroups } from '@/features/insights/categoryStatus';

const STATUS: Record<CategoryStatus['status'], { label: string; bg: string }> = {
  ANSWERED: { label: 'Answered', bg: 'success' },
  RULED_OUT: { label: 'Ruled out', bg: 'secondary' },
  OPEN: { label: 'Open', bg: 'warning' },
  NOT_OBSERVABLE: { label: 'Not observable', bg: 'light' },
};

/**
 * "Worth a look" (#1292): for each investigation category this capture has traffic for, the
 * protocols that speak to it, what they show there, and a link to their conversations, with the
 * category's status from the investigation. Statuses and links come from the backend, which
 * matched them against the capture.
 */
export function WorthALookCard({
  fileId,
  categories,
}: {
  fileId: string;
  /** Every category's status on this capture; null until the investigation is in, or if it failed. */
  categories: CategoryStatus[] | null;
}) {
  const groups = categories ? worthALookGroups(categories) : [];
  if (groups.length === 0) return null;
  return (
    <section className="ov-card" aria-labelledby="ov-worth">
      <div className="ov-head">
        <h2 id="ov-worth">Worth a look</h2>
        <SourceTag id="src-worth" source="this capture's protocols" title="How this is chosen">
          <p className="mb-2">
            Each investigation category has protocols that speak to it: Kerberos and LDAP name who is
            signed in, SMB and DCE-RPC show one machine acting on another, DNS and TLS show the
            servers a host reached. This lists the ones present in this capture, by category.
          </p>
          <p className="mb-0">
            <strong>Answered</strong>: the Investigation Summary has an answer. <strong>Ruled
            out</strong>: candidates were tested and ruled out (listed in the Summary).{' '}
            <strong>Open</strong>: nothing was concluded, so these are where to look. Categories
            without any of their protocols here are left out.
          </p>
        </SourceTag>
      </div>
      <div className="d-flex flex-column gap-3">
        {groups.map(g => {
          const s = STATUS[g.status];
          return (
            <div key={g.key} data-testid={`worth-${g.key}`}>
              <div className="d-flex align-items-center gap-2 mb-1">
                <span className="fw-semibold" style={{ fontSize: '0.85rem' }}>{g.label}</span>
                <Badge bg={s.bg} text={s.bg === 'light' ? 'dark' : undefined} style={{ fontSize: 9 }}>
                  {s.label}
                </Badge>
              </div>
              <ul className="list-unstyled mb-0 ps-4 d-flex flex-column gap-1" style={{ fontSize: '0.8rem' }}>
                {g.leads.map(l => (
                  <li key={l.label}>
                    <Link to={`/analysis/${fileId}/conversations?${l.query}`} className="fw-semibold text-decoration-none">
                      {l.label}
                    </Link>
                    <span className="text-muted"> — {l.shows}</span>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </section>
  );
}
