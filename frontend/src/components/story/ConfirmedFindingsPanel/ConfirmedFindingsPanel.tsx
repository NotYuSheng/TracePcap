import { useState } from 'react';
import { Link } from 'react-router-dom';
import { InfoPopover } from '@components/common/InfoPopover';
import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';
import { Button, Card } from '@govtechsg/sgds-react';
import type { Answer, Considered } from '@/types';
import { DerivationModal } from '../DerivationModal/DerivationModal';

interface ConfirmedFindingsPanelProps {
  answers: Answer[];
  loading?: boolean;
  /** Goals the investigation could not close on this capture (e.g. 'C2'), shown as honest gaps. */
  unknowns?: string[];
  /** The capture, so an answer can link to its conversations; links are left out without it. */
  fileId?: string;
  /** Candidates the checks tested and ruled out, with why (#1294). */
  considered?: Considered[];
}

/** Human labels for the standing investigation goals, for the "not established" line. */
const GOAL_LABEL: Record<string, string> = {
  VICTIM: 'victim host',
  USER: 'signed-in user',
  MALWARE: 'malware',
  C2: 'command & control',
};

/** Click-toggled help behind the header's info icon — app convention (no native title tooltip). */
function InvestigationSummaryInfoPopover() {
  const popover = (
    <InfoPopover id="info-investigation-summary" kind="How it works" title="Investigation Summary" source="deterministic checks" docs="features/story-mode">
        <p className="mb-2">
          These are deterministic answers to the standard investigation questions — who the victim
          is, the C2, the malware, the signed-in user — reached by checks over the extracted evidence
          (IDS signatures, protocol parsing, identity resolution), <strong>not</strong> by the LLM.
          They are the ground truth the narrative is built on.
        </p>
        <p className="mb-0">
          Each answer is labelled with how directly it is known:{' '}
          <strong>Measured</strong> (the traffic exhibited it), <strong>Reported</strong> (a party
          asserted it on the wire), or <strong>Inferred</strong> (a tool judged it) — so it is never
          presented as certain.
        </p>
      </InfoPopover>
  );
  return (
    <EscapableOverlayTrigger trigger="click" placement="right" overlay={popover}>
      <Button
        type="button"
        variant="link"
        className="p-0 text-muted ms-2"
        style={{ lineHeight: 1 }}
        aria-label="About Investigation Summary"
      >
        <i className="bi bi-info-circle" style={{ fontSize: '0.9rem' }} aria-hidden="true"></i>
      </Button>
    </EscapableOverlayTrigger>
  );
}

/**
 * How a C2 answer was concluded when no malware rule named the server itself (#1263): the chip
 * shown beside the grade, and the help behind its info button.
 */
const CONCLUSION_META: Record<string, { label: string; bg: string; title: string; note: string }> = {
  'suspected-c2': {
    label: 'Suspected',
    bg: '#b35900',
    title: 'Suspected C2',
    note:
      'No rule named this server. It is on a reputation list, a host already talking to a confirmed C2 ' +
      'reached it by bare IP address, and it did so in repeated rounds (or seconds after another such ' +
      'server). Reputation alone never makes a C2. Check its conversations before acting on it.',
  },
  'install-chain': {
    label: 'Install chain',
    bg: '#6f42c1',
    title: 'Remote-access install chain',
    note:
      'A remote-access tool checked in to a bare IP address, and shortly before, the same host ran a ' +
      'script engine or download tool against another outside server that then sent it a large ' +
      'payload. That sequence is how the tool was planted, so its server is treated as a C2. Confirm ' +
      'IT did not deploy the tool this way.',
  },
};

/** The chip saying how a C2 was concluded, with its reason behind a click-toggled info button. */
function ConclusionChip({ kind, reason, id }: { kind: string; reason?: string; id: string }) {
  const meta = CONCLUSION_META[kind];
  if (!meta) return null;
  const popover = (
    <InfoPopover id={`info-conclusion-${id}`} kind="How it was concluded" title={meta.title} source="corroboration checks" docs="architecture/knowledge-layer">
      <p className={reason ? 'mb-2' : 'mb-0'}>{meta.note}</p>
      {reason && (
        <p className="mb-0">
          <strong>Here:</strong> {reason}
        </p>
      )}
    </InfoPopover>
  );
  return (
    <span className="d-inline-flex align-items-center gap-1" data-testid="conclusion-chip">
      <span
        style={{ fontSize: 9, fontWeight: 600, color: '#fff', background: meta.bg, borderRadius: 3, padding: '1px 5px' }}
      >
        {meta.label}
      </span>
      {/* "auto": on the Overview this panel sits in the right-hand column, where a popover
          placed to the right runs off the screen. */}
      <EscapableOverlayTrigger trigger="click" placement="auto" overlay={popover}>
        <Button type="button" variant="link" className="p-0 text-muted" style={{ lineHeight: 1 }} aria-label={`About ${meta.title}`}>
          <i className="bi bi-info-circle" style={{ fontSize: '0.75rem' }} aria-hidden="true"></i>
        </Button>
      </EscapableOverlayTrigger>
    </span>
  );
}

/**
 * The address an answer is about, for its "conversations" link: for lateral movement the host acted
 * on, for a Kerberos attack the host that made the requests.
 */
function answerAddress(a: Answer): string | null {
  const v =
    a.question === 'c2'
      ? a.attributes.address
      : a.question === 'lateral-movement'
        ? a.attributes.server
        : a.question === 'kerberos-attack'
          ? a.attributes.client
          : a.attributes.external;
  return typeof v === 'string' && v ? v : null;
}

/** Friendly label + icon per standard-question key; unknown keys fall back to the raw key. */
const QUESTION_META: Record<string, { label: string; icon: string }> = {
  victim: { label: 'Victim host', icon: 'bi-pc-display' },
  c2: { label: 'Command & control', icon: 'bi-broadcast-pin' },
  malware: { label: 'Malware', icon: 'bi-bug' },
  'signed-in-user': { label: 'Signed-in user', icon: 'bi-person-badge' },
  'data-transfer': { label: 'Bulk transfer', icon: 'bi-arrow-up-right-circle' },
  'remote-access': { label: 'Remote-access tool', icon: 'bi-display' },
  'lateral-movement': { label: 'Lateral movement', icon: 'bi-diagram-2' },
  'kerberos-attack': { label: 'Kerberos attack', icon: 'bi-key' },
  downloads: { label: 'Downloaded file', icon: 'bi-file-earmark-arrow-down' },
};

/** The answer's "How we got here" button and the walkthrough it opens (#1293). */
function HowWeGotHere({ answer, label, fileId }: { answer: Answer; label: string; fileId?: string }) {
  const [show, setShow] = useState(false);
  if (!answer.derivation || answer.derivation.length === 0) return null;
  return (
    <>
      <Button
        type="button"
        variant="link"
        className="p-0 small text-decoration-none"
        style={{ fontSize: '0.72rem' }}
        onClick={() => setShow(true)}
      >
        <i className="bi bi-signpost-split me-1" aria-hidden="true" />
        How we got here
      </Button>
      <DerivationModal answer={answer} label={label} show={show} onHide={() => setShow(false)} fileId={fileId} />
    </>
  );
}

/**
 * The candidates the checks tested and ruled out (#1294), folded away: the reputation-listed server
 * that wasn't a C2, the beacon that matched no family. Answers "did it even look at X?".
 */
function ConsideredList({ items, fileId }: { items: Considered[]; fileId?: string }) {
  const [open, setOpen] = useState(false);
  if (items.length === 0) return null;
  return (
    <div className="mt-2">
      <Button
        type="button"
        variant="link"
        className="p-0 small text-decoration-none"
        style={{ fontSize: '0.75rem' }}
        aria-expanded={open}
        onClick={() => setOpen(o => !o)}
      >
        <i className={`bi ${open ? 'bi-chevron-down' : 'bi-chevron-right'} me-1`} aria-hidden="true" />
        Considered and ruled out ({items.length})
      </Button>
      {open && (
        <ul className="list-unstyled mb-0 mt-1 d-flex flex-column gap-2" data-testid="considered-list">
          {items.map((c, i) => (
            <li key={i} className="border rounded p-2" style={{ fontSize: '0.78rem', overflowWrap: 'anywhere' }}>
              <div>
                <span className="text-muted me-1">{QUESTION_META[c.question]?.label ?? c.question}:</span>
                <strong>{c.candidate}</strong> — {c.reason}
              </div>
              {c.rule && (
                <div className="text-muted mt-1" style={{ fontSize: '0.72rem' }}>
                  <strong>Rule:</strong> {c.rule}
                </div>
              )}
              {fileId && c.conversations.length > 0 && (
                <Link
                  to={`/analysis/${fileId}/conversations?highlight=${encodeURIComponent(c.conversations[0])}`}
                  className="small text-decoration-none"
                  style={{ fontSize: '0.72rem' }}
                >
                  Conversation <i className="bi bi-arrow-right-short" aria-hidden="true" />
                </Link>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** How many lines of evidence show before the rest fold away. */
const BASIS_SHOWN = 4;

/** An answer's evidence: the first few lines, the rest behind "and N more". */
function Basis({ lines }: { lines: string[] }) {
  const [open, setOpen] = useState(false);
  const shown = open ? lines : lines.slice(0, BASIS_SHOWN);
  const hidden = lines.length - BASIS_SHOWN;
  return (
    <ul className="mb-0 mt-1 ps-3 text-muted" style={{ fontSize: '0.72rem', overflowWrap: 'anywhere' }}>
      {shown.map((b, j) => (
        <li key={j}>{b}</li>
      ))}
      {hidden > 0 && (
        <li className="list-unstyled">
          <button
            type="button"
            className="btn btn-link btn-sm p-0 text-decoration-none"
            style={{ fontSize: '0.72rem' }}
            aria-expanded={open}
            onClick={() => setOpen(o => !o)}
          >
            {open ? 'Show fewer' : `and ${hidden} more`}
          </button>
        </li>
      )}
    </ul>
  );
}

/** Grade → chip colour: MEASURED strongest, INFERRED weakest. */
const GRADE_STYLE: Record<string, { bg: string; label: string; tip: string }> = {
  MEASURED: { bg: '#198754', label: 'Measured', tip: 'The traffic itself exhibited it — strongest.' },
  REPORTED: { bg: '#b35900', label: 'Reported', tip: 'A party asserted it on the wire — testimony.' },
  INFERRED: { bg: '#6c757d', label: 'Inferred', tip: 'A tool judged it (IDS, classifier) — a guess with error modes.' },
};

/**
 * Surfaces the deterministic standard-question answers (#813) — victim, C2, malware, signed-in
 * user — as a first-class panel, so an analyst sees the confirmed conclusions directly rather than
 * only through the LLM narrative. This is the same data that feeds the narrative's ground-truth
 * block. Renders nothing when there are no answers (a capture with no such findings).
 */
export const ConfirmedFindingsPanel = ({
  answers,
  loading = false,
  unknowns = [],
  fileId,
  considered = [],
}: ConfirmedFindingsPanelProps) => {
  return (
    <Card>
      <Card.Body>
        <h5 className="mb-1 d-flex align-items-center">
          <i className="bi bi-clipboard2-check me-2" aria-hidden="true" />
          Investigation Summary
          <InvestigationSummaryInfoPopover />
        </h5>
        <p className="text-muted small mb-3">
          Deterministic answers to the standard questions, drawn from the evidence — each labelled
          with how directly it is known (measured, reported, or inferred), not asserted as certain.
        </p>

        {loading ? (
          <div className="text-muted small d-flex align-items-center gap-2 py-2">
            <span className="spinner-border spinner-border-sm" role="status" aria-hidden="true" />
            Deriving answers…
          </div>
        ) : answers.length === 0 ? (
          <div className="text-center text-muted py-4">
            <i className="bi bi-clipboard-x d-block mb-2" style={{ fontSize: '1.6rem' }} aria-hidden="true" />
            <div className="small">
              No deterministic answers for this capture — nothing matched the standard questions
              (victim, C2, malware, signed-in user). The narrative below still summarises the traffic.
            </div>
          </div>
        ) : (
        <div className="d-flex flex-column gap-2">
          {answers.map((a, i) => {
            const meta = QUESTION_META[a.question] ?? { label: a.question, icon: 'bi-dot' };
            const grade = GRADE_STYLE[a.grade] ?? { bg: '#6c757d', label: a.grade, tip: '' };
            return (
              <div key={`${a.question}-${i}`} className="border rounded p-2 d-flex align-items-start gap-2">
                <i className={`bi ${meta.icon} text-muted mt-1`} aria-hidden="true" />
                <div className="flex-grow-1 min-w-0">
                  <div className="d-flex align-items-center gap-2 flex-wrap">
                    <span className="fw-semibold" style={{ fontSize: '0.8rem' }}>{meta.label}</span>
                    {/* Grade meaning is explained once in the header info popover — no native
                        title= tooltip here (CLAUDE.md: title= is unreliable/inaccessible). */}
                    <span
                      style={{
                        fontSize: 9,
                        fontWeight: 600,
                        color: '#fff',
                        background: grade.bg,
                        borderRadius: 3,
                        padding: '1px 5px',
                      }}
                    >
                      {grade.label}
                    </span>
                    {typeof a.attributes.conclusion === 'string' && (
                      <ConclusionChip
                        kind={a.attributes.conclusion}
                        reason={typeof a.attributes.conclusionReason === 'string' ? a.attributes.conclusionReason : undefined}
                        id={String(i)}
                      />
                    )}
                    <span className="ms-auto d-inline-flex align-items-center gap-2">
                    <HowWeGotHere answer={a} label={meta.label} fileId={fileId} />
                    {fileId && answerAddress(a) && (
                      <Link
                        to={`/analysis/${fileId}/conversations?ip=${encodeURIComponent(answerAddress(a)!)}`}
                        className="small text-decoration-none"
                        style={{ fontSize: '0.72rem' }}
                      >
                        Conversations <i className="bi bi-arrow-right-short" aria-hidden="true" />
                      </Link>
                    )}
                    </span>
                  </div>
                  {/* URLs and hashes have no spaces: let them wrap rather than run out of the card. */}
                  <div style={{ fontSize: '0.82rem', overflowWrap: 'anywhere' }}>{a.headline}</div>
                  {a.basis.length > 0 && <Basis lines={a.basis} />}
                </div>
              </div>
            );
          })}
          {unknowns.length > 0 && (
            <div className="text-muted small d-flex align-items-start gap-2 px-1 pt-1">
              <i className="bi bi-question-circle mt-1" aria-hidden="true" />
              <span>
                Not established for this capture:{' '}
                {unknowns.map((u) => GOAL_LABEL[u] ?? u.toLowerCase()).join(', ')}.
              </span>
            </div>
          )}
        </div>
        )}
        {!loading && <ConsideredList items={considered} fileId={fileId} />}
      </Card.Body>
    </Card>
  );
};
