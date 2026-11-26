import { SideDrawer } from '@components/common/SideDrawer';
import { useState } from 'react';
import { Button } from '@govtechsg/sgds-react';
import type { CaptureContext } from '@/types';
import { AdjudicationPanel } from '@components/common/AdjudicationPanel/AdjudicationPanel';
import { contextParts, vantageDescribed } from '@/features/insights/captureContext';

interface Props {
  fileId: string;
  context: CaptureContext;
  /** Called after an override or evidence change, so the parent re-reads the context. */
  onChanged: () => void;
}

/**
 * Where the capture was taken, how complete it is and the time it spans, in one line that frames
 * the rest of the summary (docs/architecture/investigation-framework.rst, "Capture context"). The
 * vantage point is inferred, so "Why · change" opens its vote, an override and analyst evidence.
 */
export function CaptureContextLine({ fileId, context, onChanged }: Props) {
  const [open, setOpen] = useState(false);
  const { vantage, grade, rest } = contextParts(context);
  const v = context.vantage;
  return (
    <div className="story-summary-context" data-testid="story-summary-context">
      <i className="bi bi-geo-alt" aria-hidden="true" />
      <span>
        <b>{vantage}</b>
        {grade && <span className="story-summary-meta"> · {grade}</span>}
        {rest.map(r => <span key={r}> · {r}</span>)}
      </span>
      <Button variant="link" size="sm" className="p-0 ms-auto" onClick={() => setOpen(true)}>
        Why · change
      </Button>

      <SideDrawer
        show={open}
        onHide={() => setOpen(false)}
        title="What this capture can show"
        titleId="capture-context-title"
        wide
      >
        <p className="small text-muted">
          Where a capture was taken decides what it can show: traffic between internal hosts never
          crosses an internet uplink, and a sensor sees only what reaches it. TracePcap infers it from
          who talks to whom and who opens the connections. If you know better, say so: your answer
          replaces the inference, and evidence you add counts toward it.
        </p>
        {!v.label && v.reason && (
          <p className="small" data-testid="vantage-undetermined">
            <b>Not determined:</b> {v.reason}.
          </p>
        )}
        <AdjudicationPanel
          fileId={fileId}
          question={v.question}
          entityKey={v.entityKey}
          title="Vantage point"
          verdict={{
            label: vantageDescribed(v) ?? 'Not determined',
            basis: v.basis,
            confidence: v.label ? v.confidence : undefined,
            contested: v.contested,
            candidates: v.candidates.map(c => ({
              label: c.label,
              source: 'address mix',
              score: c.score,
              reasons: c.reasons,
            })),
          }}
          labelOptions={v.options}
          onChanged={onChanged}
        />

        <h6 className="border-bottom pb-1 mb-2">Completeness</h6>
        <p className="small mb-1">{context.completeness.label}</p>
        {context.completeness.notes.length > 0 && (
          <ul className="small text-muted">
            {context.completeness.notes.map(n => <li key={n.kind}>{n.text}</li>)}
          </ul>
        )}

        <h6 className="border-bottom pb-1 mb-2 mt-3">Time span</h6>
        <p className="small mb-0">{context.timeSpan.label ?? 'Not known yet'}</p>
      </SideDrawer>
    </div>
  );
}
