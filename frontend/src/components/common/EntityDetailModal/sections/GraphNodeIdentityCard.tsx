import { useEffect, useState, type ReactNode } from 'react';
import { Button } from '@govtechsg/sgds-react';
import type { GraphNode } from '@/features/network/types';
import type { DeviceType } from '@/types';
import { deviceTypeIcon, deviceTypeLabel, nodeIdentityKey } from '@/utils/deviceType';
import { adjudicationService } from '@/features/insights/services/adjudicationService';
import { HostnameSourceBadge } from '@components/common/HostnameSourceBadge/HostnameSourceBadge';
import { LoggedInUserSourceBadge } from '@components/common/LoggedInUserSourceBadge/LoggedInUserSourceBadge';

interface Props {
  node: GraphNode;
  fileId: string;
  /** The identity key (the bare IP, or `ip@<start>` for a later device on a reused address). */
  identityKey: string;
  /** The heading's id, which labels the dialog. */
  titleId: string;
  /** Extra badges from the caller (monitor status, compare markers). */
  badges?: ReactNode;
  /** The role section, rendered under the facts. */
  role?: ReactNode;
  onShowEvidence: () => void;
  onShowConversations: () => void;
  /** On narrow screens the card stacks on top, so it carries the dialog's close button. */
  onClose: () => void;
}

/**
 * The left half of the node dialog: what the host is, the facts that say so, a one-click confirm
 * when the verdict is a machine guess, and what to do next.
 */
export function GraphNodeIdentityCard({
  node,
  fileId,
  identityKey,
  titleId,
  badges,
  role,
  onShowEvidence,
  onShowConversations,
  onClose,
}: Props) {
  const d = node.data;
  const [confirmed, setConfirmed] = useState<string | null>(
    d.identityBasis === 'HUMAN' ? (d.identityLabel ?? null) : null
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  useEffect(() => {
    setConfirmed(d.identityBasis === 'HUMAN' ? (d.identityLabel ?? null) : null);
    setError(false);
  }, [node.id, d.identityBasis, d.identityLabel]);

  const kind = (confirmed ?? nodeIdentityKey(d)) as DeviceType;
  const candidates = (d.identityCandidates ?? [])
    .slice()
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);
  const isL2 = !!d.isL2;

  const confirm = async (label: string) => {
    setBusy(true);
    setError(false);
    try {
      await adjudicationService.setOverride(
        fileId,
        'host-identity',
        identityKey,
        label,
        'Confirmed from the node dialog'
      );
      setConfirmed(label);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  };

  const state = confirmed
    ? 'confirmed'
    : d.identityContested
      ? 'the signals disagree'
      : 'not confirmed';

  return (
    <aside className="node-card" aria-label="What this host is">
      <div className="node-card-head">
        <div className="node-card-icon" aria-hidden="true">
          <i className={`bi ${deviceTypeIcon(kind)}`} />
        </div>
        <div className="min-w-0">
          <h2 id={titleId} className="node-card-title">
            {d.hostname || (isL2 ? (d.mac ?? d.ip) : d.ip)}
          </h2>
          <div className="node-card-kind">
            {kind === 'UNKNOWN' ? 'Unknown type' : deviceTypeLabel(kind)} ·{' '}
            <span className={confirmed ? 'node-card-confirmed' : 'node-card-unconfirmed'}>
              {state}
            </span>
          </div>
          {badges && <div className="d-flex flex-wrap gap-1 mt-1">{badges}</div>}
        </div>
        <button
          type="button"
          className="btn-close ms-auto align-self-start d-lg-none"
          aria-label="Close (Esc)"
          onClick={onClose}
        />
      </div>

      <dl className="node-card-facts">
        {!isL2 && (
          <>
            <dt>Address</dt>
            <dd className="font-monospace">{d.ip}</dd>
          </>
        )}
        {d.mac && (
          <>
            <dt>MAC</dt>
            <dd className="font-monospace">{d.mac}</dd>
          </>
        )}
        {d.manufacturer && (
          <>
            <dt>Maker</dt>
            <dd>{d.manufacturer}</dd>
          </>
        )}
        {d.hostname && (
          <>
            <dt>Name from</dt>
            <dd>
              <HostnameSourceBadge source={d.hostnameSource} />
            </dd>
          </>
        )}
        {(d.loggedInUserCount ?? 0) > 1 ? (
          <>
            <dt>Accounts</dt>
            <dd>{d.loggedInUserCount} Windows accounts, see Traffic</dd>
          </>
        ) : (
          d.loggedInUser && (
            <>
              {/* "Looked up" for LDAP-only evidence: a lookup isn't proof of a sign-in (#812). */}
              <dt>{d.loggedInUserSource === 'ldap_dn' ? 'Looked up' : 'Signed in'}</dt>
              <dd className="d-flex align-items-center gap-1 flex-wrap">
                <span>{d.loggedInUser}</span>
                <LoggedInUserSourceBadge source={d.loggedInUserSource} />
              </dd>
            </>
          )
        )}
        {d.ttl != null && (
          <>
            <dt>TTL</dt>
            <dd>{d.ttl}</dd>
          </>
        )}
      </dl>

      {!isL2 && !confirmed && (
        <div className="node-card-confirm" data-testid="node-confirm">
          <strong>Confirm what it is</strong>
          <span className="text-muted">
            {candidates.length > 0
              ? candidates
                  .map(c => `${deviceTypeLabel(c.label as DeviceType)} ${Math.round(c.score)}`)
                  .join(' · ')
              : 'TracePcap has no strong guess yet.'}
            {d.identityContested ? '. The signals disagree.' : ''}
          </span>
          <div className="d-flex flex-wrap gap-1">
            {candidates.map(c => (
              <Button
                key={c.label}
                size="sm"
                variant="outline-primary"
                disabled={busy}
                onClick={() => confirm(c.label)}
              >
                {deviceTypeLabel(c.label as DeviceType)}
              </Button>
            ))}
            <Button size="sm" variant="outline-secondary" onClick={onShowEvidence}>
              {candidates.length > 0 ? 'Other…' : 'See the evidence'}
            </Button>
          </div>
          {error && (
            <span className="text-danger">Couldn’t save that. Try again from Identity.</span>
          )}
        </div>
      )}

      {role}

      <div className="node-card-actions">
        {!isL2 && (
          <Button variant="primary" onClick={onShowConversations}>
            <i className="bi bi-chat-dots me-2" aria-hidden="true" />
            Show its conversations
          </Button>
        )}
      </div>
    </aside>
  );
}
