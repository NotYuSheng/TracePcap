import { Link } from 'react-router-dom';
import { Badge } from '@govtechsg/sgds-react';
import { SourceTag } from './SourceTag';
import { worthALook } from '@/features/insights/protocolInsights';

const STATUS: Record<string, { label: string; bg: string } | undefined> = {
  answered: { label: 'Answered', bg: 'success' },
  'ruled-out': { label: 'Ruled out', bg: 'secondary' },
  open: { label: 'Open', bg: 'warning' },
};

/**
 * "Worth a look" (#1292): the protocols in this capture grouped by the investigation question they
 * help answer, each with what it shows there and a link to its conversations. A question the
 * Investigation Summary already answered says so; an open one points at where to look.
 */
export function WorthALookCard({
  fileId,
  l7Protocols,
  apps,
  answeredQuestions,
  ruledOutQuestions = [],
}: {
  fileId: string;
  l7Protocols: string[];
  apps: string[];
  /** The standard-question keys answered ("c2", "signed-in-user"); null until the investigation is in. */
  answeredQuestions: string[] | null;
  /** The questions with candidates tested and ruled out (#1294). */
  ruledOutQuestions?: string[];
}) {
  const groups = worthALook(l7Protocols, apps, answeredQuestions, ruledOutQuestions);
  if (groups.length === 0) return null;
  return (
    <section className="ov-card" aria-labelledby="ov-worth">
      <div className="ov-head">
        <h2 id="ov-worth">Worth a look</h2>
        <SourceTag id="src-worth" source="this capture's protocols" title="How this is chosen">
          <p className="mb-2">
            Each investigation question has protocols that speak to it: Kerberos and LDAP name who is
            signed in, SMB and DCE-RPC show one machine acting on another, DNS and TLS show the
            servers a host reached. This lists the ones present in this capture, by question.
          </p>
          <p className="mb-0">
            <strong>Answered</strong>: the Investigation Summary has an answer. <strong>Ruled
            out</strong>: candidates were tested and ruled out (listed in the Summary).{' '}
            <strong>Open</strong>: nothing was concluded, so these are where to look. Questions
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
                <i className={`bi ${g.icon} text-muted`} aria-hidden="true" />
                <span className="fw-semibold" style={{ fontSize: '0.85rem' }}>{g.label}</span>
                {s && (
                  <Badge bg={s.bg} style={{ fontSize: 9 }}>
                    {s.label}
                  </Badge>
                )}
              </div>
              <ul className="list-unstyled mb-0 ps-4 d-flex flex-column gap-1" style={{ fontSize: '0.8rem' }}>
                {g.items.map(i => (
                  <li key={i.label}>
                    <Link to={`/analysis/${fileId}/conversations?${i.query}`} className="fw-semibold text-decoration-none">
                      {i.label}
                    </Link>
                    <span className="text-muted"> — {i.shows}</span>
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
