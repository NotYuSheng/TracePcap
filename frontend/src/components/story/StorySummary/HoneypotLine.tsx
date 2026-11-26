import { SideDrawer } from '@components/common/SideDrawer';
import { useState } from 'react';
import { Button } from '@govtechsg/sgds-react';
import type { HoneypotHost, Honeypots } from '@/types';
import { AdjudicationPanel } from '@components/common/AdjudicationPanel/AdjudicationPanel';
import { honeypotGrade, honeypotLines, honeypotText, isHoneypot } from '@/features/insights/honeypots';

interface Props {
  fileId: string;
  honeypots: Honeypots;
  /** Called after an override or evidence change, so the parent re-reads the report. */
  onChanged: () => void;
}

const STRENGTH_LABEL: Record<string, string> = { STRONG: 'strong', MEDIUM: 'medium', WEAK: 'weak' };

/**
 * The hosts that read as honeypots, one line each (docs/architecture/investigation-framework.rst,
 * "Honeypots"). A decoy changes how the rest reads: what reaches it is the attack, and what it
 * downloads is the catch. "Why · change" opens its signals, an override and analyst evidence.
 */
export function HoneypotLine({ fileId, honeypots, onChanged }: Props) {
  const [open, setOpen] = useState<string | null>(null);
  const lines = honeypotLines(honeypots.hosts);
  if (lines.length === 0) return null;
  const shown = honeypots.hosts.find(h => h.host === open) ?? null;
  return (
    <>
      {lines.map(h => (
        <div key={h.host} className="story-summary-context" data-testid={`story-honeypot-${h.host}`}>
          <i className={`bi ${isHoneypot(h) ? 'bi-bug' : h.label ? 'bi-check-circle' : 'bi-question-circle'}`} aria-hidden="true" />
          <span>
            <b>{honeypotText(h)}</b>
            <span className="story-summary-meta"> · {honeypotGrade(h)}</span>
          </span>
          <Button variant="link" size="sm" className="p-0 ms-auto" onClick={() => setOpen(h.host)}>
            Why · change
          </Button>
        </div>
      ))}
      <SideDrawer
        show={!!shown}
        onHide={() => setOpen(null)}
        title={<>Is {shown?.host} a honeypot?</>}
        titleId="honeypot-host-title"
        wide
      >
        {shown && <HostBody fileId={fileId} honeypots={honeypots} host={shown} onChanged={onChanged} />}
      </SideDrawer>
    </>
  );
}

function HostBody({ fileId, honeypots, host, onChanged }: Props & { host: HoneypotHost }) {
  return (
    <>
      <p className="small text-muted">
        A stock honeypot gives itself away: a default banner, a default certificate, a Windows SMB
        server on a Linux stack. One signal is never enough, since a real server can send the same
        banner: TracePcap needs two, one of them a match in its signature file
        {honeypots.signaturesVersion ? ` (version ${honeypots.signaturesVersion})` : ''}. If you
        know better, say so: your answer replaces the inference, and evidence you add counts toward it.
      </p>
      {!host.label && host.reason && (
        <p className="small" data-testid="honeypot-undetermined">
          <b>Not settled:</b> {host.reason}.
        </p>
      )}
      <AdjudicationPanel
        fileId={fileId}
        question={honeypots.question}
        entityKey={host.host}
        title="Honeypot"
        verdict={{
          label: host.label ? (host.honeypot && isHoneypot(host) && host.label === 'Honeypot'
            ? `Honeypot (${host.honeypot})` : host.label) : 'Not settled',
          basis: host.basis,
          confidence: host.label ? host.confidence : undefined,
          contested: host.contested,
          candidates: host.candidates.map(c => ({
            label: c.label,
            source: 'signals',
            score: c.score,
            reasons: c.reasons,
          })),
        }}
        labelOptions={honeypots.options}
        onChanged={onChanged}
      />
      <h6 className="border-bottom pb-1 mb-2">Signals</h6>
      {host.signals.length === 0
        ? <p className="small text-muted mb-0">None: only an analyst&apos;s word.</p>
        : (
          <ul className="small mb-0" data-testid="honeypot-signals">
            {host.signals.map(s => (
              <li key={`${s.source}-${s.id}-${s.text}`}>
                <span className="story-summary-meta">
                  {s.source === 'signature' ? 'Signature' : s.source === 'behaviour' ? 'Behaviour' : 'Analyst'}
                  {s.strength ? `, ${STRENGTH_LABEL[s.strength] ?? s.strength.toLowerCase()}` : ''}
                  {' · '}
                </span>
                {s.text}
              </li>
            ))}
          </ul>
        )}
    </>
  );
}
