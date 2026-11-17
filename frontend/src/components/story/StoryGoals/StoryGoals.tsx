import type { Answer, GoalOutcome } from '@/types';
import './StoryGoals.css';

/** The standing questions every investigation asks, in the order an analyst reads them. */
const GOALS: { goal: string; label: string; question: string }[] = [
  { goal: 'VICTIM', label: 'Victim', question: 'Which host was attacked?' },
  { goal: 'USER', label: 'User', question: 'Who was signed in?' },
  { goal: 'MALWARE', label: 'Malware', question: 'What ran on it?' },
  { goal: 'C2', label: 'C2', question: 'Where did it call home?' },
];

const INCIDENT_GOALS = new Set(['VICTIM', 'MALWARE', 'C2']);

const GRADE_LABEL: Record<string, string> = {
  MEASURED: 'measured',
  REPORTED: 'reported',
  INFERRED: 'inferred',
};

interface StoryGoalsProps {
  goals: GoalOutcome[];
  /** Answers that aren't a standing goal, e.g. a bulk transfer worth reviewing. */
  additional: Answer[];
  loading: boolean;
}

/**
 * The investigation's four questions as cards: answered (with what answered it), not established
 * (an incident was found but this part of it wasn't), or no lead (nothing in the capture pointed
 * here, which on a benign capture is the expected outcome, not a failure).
 */
export function StoryGoals({ goals, additional, loading }: StoryGoalsProps) {
  const byGoal = new Map(goals.map(g => [g.goal, g]));
  const incidentLead = goals.some(g => g.answered && INCIDENT_GOALS.has(g.goal));

  return (
    <section aria-label="Investigation questions">
      <div className="story-goals">
        {GOALS.map(({ goal, label, question }) => {
          const g = byGoal.get(goal);
          const answered = !!g?.answered && !!g.headline;
          const state = loading ? 'loading' : answered ? 'answered' : incidentLead ? 'open' : 'none';
          return (
            <article key={goal} className={`story-goal story-goal-${state}`} data-testid={`story-goal-${goal}`}>
              <div className="story-goal-head">
                <b>{label}</b>
                <span className="story-goal-tag">
                  {state === 'answered' && 'Answered'}
                  {state === 'open' && 'Not established'}
                  {state === 'none' && 'No lead'}
                  {state === 'loading' && '…'}
                </span>
              </div>
              <div className="story-goal-question">{question}</div>
              {state === 'answered' && g && (
                <>
                  <p className="story-goal-headline">{g.headline}</p>
                  <div className="story-goal-meta">
                    {GRADE_LABEL[g.grade ?? ''] ?? (g.grade ?? '').toLowerCase()}
                    {g.confidence > 0 && ` · ${Math.round(g.confidence)}% confidence`}
                    {g.basis.length > 0 && ` · ${g.basis.length} ${g.basis.length === 1 ? 'reason' : 'reasons'}`}
                  </div>
                </>
              )}
              {state === 'open' && (
                <p className="story-goal-note">An incident was found, but nothing settled this part of it.</p>
              )}
              {state === 'none' && <p className="story-goal-note">Nothing in this capture pointed here.</p>}
            </article>
          );
        })}
      </div>
      {additional.length > 0 && (
        <ul className="story-also" aria-label="Also found">
          {additional.map((a, i) => (
            <li key={i}>
              <span className="story-also-label">Also found</span> {a.headline}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
