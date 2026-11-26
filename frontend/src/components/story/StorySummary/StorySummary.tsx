import { SideDrawer } from '@components/common/SideDrawer';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@govtechsg/sgds-react';
import type { Answer, CaptureContext, CategoryStatus, GoalOutcome, Honeypots } from '@/types';
import { plural, summarySentence, worthALookNext } from '@/features/insights/categoryStatus';
import { GOAL_QUESTION } from '@/features/story/services/storyService';
import { QUESTION_META } from '@/features/story/questionMeta';
import { HowWeGotHere } from '@components/story/ConfirmedFindingsPanel/ConfirmedFindingsPanel';
import { CaptureContextLine } from './CaptureContextLine';
import { HoneypotLine } from './HoneypotLine';
import './StorySummary.css';

type Status = CategoryStatus['status'];

const STATUS_LABEL: Record<Status, string> = {
  ANSWERED: 'Answered',
  RULED_OUT: 'Ruled out',
  OPEN: 'Open',
  NOT_OBSERVABLE: 'Not observable',
};

/** Bar and grid order: settled first, then what needs a person, then what the capture can't show. */
const ORDER: Status[] = ['ANSWERED', 'RULED_OUT', 'OPEN', 'NOT_OBSERVABLE'];

const AXIS_LABEL: Record<CategoryStatus['axis'], string> = {
  CONTEXT: 'Capture context',
  ENTITY: 'Hosts',
  ACTIVITY: 'Activities (ATT&CK)',
};

const GRADE_LABEL: Record<string, string> = {
  MEASURED: 'measured',
  REPORTED: 'reported',
  INFERRED: 'inferred',
};

/** Open categories listed before "and N more open". */
const NEXT_SHOWN = 3;

interface StorySummaryProps {
  fileId: string;
  goals: GoalOutcome[];
  /** Answers that aren't a standing goal, e.g. a bulk transfer worth reviewing. */
  additional: Answer[];
  /** Every category's status on this capture; null from a backend that doesn't report them. */
  categories: CategoryStatus[] | null;
  /** Where the capture was taken, how complete it is, the time it spans; null from older backends. */
  context?: CaptureContext | null;
  /** Called after an analyst overrides or adds evidence to the context or a host's role, to re-read it. */
  onContextChanged?: () => void;
  /** Hosts read against the honeypot signatures; null from older backends. */
  honeypots?: Honeypots | null;
  loading: boolean;
}

/**
 * The top of Story, summary first (docs/architecture/investigation-framework.rst, "Story layout"):
 * one sentence and one bar for where the investigation stands, what it answered, the open
 * categories worth a look next, and the ruled-out and not-observable ones folded away with why.
 */
export function StorySummary({
  fileId, goals, additional, categories, context = null, onContextChanged = () => {}, honeypots = null,
  loading,
}: StorySummaryProps) {
  const [showMoreOpen, setShowMoreOpen] = useState(false);
  const [showRuledOut, setShowRuledOut] = useState(false);
  const [showUnseen, setShowUnseen] = useState(false);
  const [showAll, setShowAll] = useState(false);

  // Goals in the same shape as other answers, so each can open its "How we got here".
  const answers: { key: string; answer: Answer; meta: string }[] = [
    ...goals
      .filter(g => g.answered && g.headline)
      .map(g => ({
        key: `goal-${g.goal}`,
        answer: {
          question: GOAL_QUESTION[g.goal] ?? g.goal.toLowerCase(),
          headline: g.headline as string,
          grade: g.grade ?? '',
          subjects: g.subjects,
          basis: g.basis,
          attributes: g.attributes ?? {},
          derivation: g.derivation,
        },
        meta: [
          GRADE_LABEL[g.grade ?? ''] ?? (g.grade ?? '').toLowerCase(),
          g.confidence > 0 ? `${Math.round(g.confidence)}% confidence` : '',
        ].filter(Boolean).join(' · '),
      })),
    ...additional.map((a, i) => ({ key: `also-${i}`, answer: a, meta: GRADE_LABEL[a.grade ?? ''] ?? '' })),
  ];

  if (loading) {
    return (
      <section className="story-summary" aria-label="Where the investigation stands" aria-busy="true">
        <p className="story-summary-sentence text-muted mb-0">Checking every category…</p>
      </section>
    );
  }

  // Nothing to say: no categories reported (the investigation failed, or an older backend) and no
  // answers. Render nothing rather than an empty box.
  if (!categories?.length && answers.length === 0) return null;

  const cats = categories ?? [];
  const counted = cats.filter(c => c.axis !== 'CONTEXT');
  const counts = Object.fromEntries(ORDER.map(s => [s, counted.filter(c => c.status === s).length])) as Record<Status, number>;
  const next = worthALookNext(cats);
  const nextShown = showMoreOpen ? next : next.slice(0, NEXT_SHOWN);
  const ruledOut = counted.filter(c => c.status === 'RULED_OUT');
  const unseen = counted.filter(c => c.status === 'NOT_OBSERVABLE');

  return (
    <section className="story-summary" aria-label="Where the investigation stands" data-testid="story-summary">
      {context && <CaptureContextLine fileId={fileId} context={context} onChanged={onContextChanged} />}
      {honeypots && <HoneypotLine fileId={fileId} honeypots={honeypots} onChanged={onContextChanged} />}
      {categories && counted.length > 0 && (
        <>
          <div className="story-summary-scope">{plural(counted.length, 'category', 'categories')} checked</div>
          <p className="story-summary-sentence" data-testid="story-summary-sentence">{summarySentence(counts)}</p>
          <div
            className="story-summary-bar"
            role="img"
            aria-label={ORDER.map(s => `${counts[s]} ${STATUS_LABEL[s].toLowerCase()}`).join(', ')}
          >
            {ORDER.filter(s => counts[s] > 0).map(s => (
              <div key={s} className={`story-summary-seg seg-${s}`} style={{ flexGrow: counts[s] }} />
            ))}
          </div>
          <div className="story-summary-legend">
            {ORDER.map(s => (
              <span key={s}>
                <i className={`story-summary-dot seg-${s}`} aria-hidden="true" />
                <b>{counts[s]}</b> {STATUS_LABEL[s].toLowerCase()}
              </span>
            ))}
            <Button variant="link" size="sm" className="ms-auto p-0" onClick={() => setShowAll(true)}>
              Show all {counted.length} →
            </Button>
          </div>
        </>
      )}

      {answers.length > 0 && (
        <div className="story-summary-block">
          <h2 className="story-summary-h">Answered</h2>
          <ul className="story-summary-answers">
            {answers.map(a => {
              const label = QUESTION_META[a.answer.question]?.label ?? a.answer.question;
              return (
                <li key={a.key}>
                  <span className="story-summary-meta">{label}: </span>
                  <span className="story-summary-headline">{a.answer.headline}</span>
                  {a.meta && <span className="story-summary-meta"> · {a.meta}</span>}{' '}
                  <HowWeGotHere answer={a.answer} label={label} fileId={fileId} />
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {next.length > 0 && (
        <div className="story-summary-block">
          <h2 className="story-summary-h">Worth a look next</h2>
          <ul className="story-summary-leads">
            {nextShown.map(c => (
              <li key={c.key} data-testid={`story-next-${c.key}`}>
                <span className="story-summary-tag tag-OPEN">Open</span>
                <b className="story-summary-cat">{c.label}</b>
                <span className="story-summary-why">
                  {c.leads.length > 0
                    ? (
                      <>
                        Look in{' '}
                        {c.leads.map((l, i) => (
                          <span key={l.label}>
                            {i > 0 && ', '}
                            <Link to={`/analysis/${fileId}/conversations?${l.query}`}>{l.label}</Link>
                          </span>
                        ))}
                      </>
                    )
                    : c.reason ?? 'nothing concluded'}
                </span>
              </li>
            ))}
          </ul>
          {next.length > NEXT_SHOWN && (
            <Button variant="link" size="sm" className="p-0" onClick={() => setShowMoreOpen(v => !v)}>
              {showMoreOpen ? 'Show fewer' : `and ${next.length - NEXT_SHOWN} more open`}
            </Button>
          )}
        </div>
      )}

      {ruledOut.length > 0 && (
        <Fold
          id="story-ruled-out"
          count={ruledOut.length}
          label="Ruled out"
          tag="RULED_OUT"
          summary={ruledOut.map(c => c.label).join(', ')}
          open={showRuledOut}
          onToggle={() => setShowRuledOut(v => !v)}
        >
          {ruledOut.map(c => (
            <div key={c.key}>
              <b>{c.label}</b> · {c.reason ?? 'its candidates were tested and ruled out'}
            </div>
          ))}
        </Fold>
      )}

      {unseen.length > 0 && (
        <Fold
          id="story-unseen"
          count={unseen.length}
          label="Not observable"
          tag="NOT_OBSERVABLE"
          summary={unseen.map(c => c.label).join(', ')}
          open={showUnseen}
          onToggle={() => setShowUnseen(v => !v)}
        >
          {unseen.map(c => (
            <div key={c.key}>
              <b>{c.label}</b> · {c.reason}
            </div>
          ))}
        </Fold>
      )}

      <SideDrawer
        show={showAll}
        onHide={() => setShowAll(false)}
        title="Every category on this capture"
        titleId="every-category-title"
        wide
      >
        {(['CONTEXT', 'ENTITY', 'ACTIVITY'] as const).map(axis => {
          const rows = cats.filter(c => c.axis === axis);
          if (rows.length === 0) return null;
          return (
            <table key={axis} className="table table-sm story-summary-grid">
              <caption>{AXIS_LABEL[axis]}</caption>
              <colgroup>
                <col style={{ width: '38%' }} />
                <col style={{ width: '18%' }} />
                <col />
              </colgroup>
              <tbody>
                {rows.map(c => (
                  <tr key={c.key}>
                    <th scope="row">
                      {c.label}
                      {c.attackId && <span className="story-summary-meta"> {c.attackId}</span>}
                    </th>
                    <td><span className={`story-summary-tag tag-${c.status}`}>{STATUS_LABEL[c.status]}</span></td>
                    <td className="story-summary-meta">
                      {c.reason ?? (c.leads.length > 0 ? c.leads.map(l => l.label).join(', ') : '')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          );
        })}
      </SideDrawer>
    </section>
  );
}

function Fold({
  id, count, label, tag, summary, open, onToggle, children,
}: {
  id: string;
  count: number;
  label: string;
  tag: Status;
  summary: string;
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="story-summary-fold">
      <button type="button" className="story-summary-disc" aria-expanded={open} aria-controls={id} onClick={onToggle}>
        <span className={`story-summary-tag tag-${tag}`}>{count}</span>
        <b>{label}</b>
        <span className="story-summary-why text-truncate">{summary}</span>
        <i className={`bi bi-chevron-${open ? 'up' : 'down'}`} aria-hidden="true" />
      </button>
      {open && (
        <div id={id} className="story-summary-fold-body">
          {children}
        </div>
      )}
    </div>
  );
}
