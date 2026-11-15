import type { NarrativeSection, StoryTimelineEvent } from '@/types';
import { renderNarrative } from './renderNarrative';
import './StoryNarrative.css';

interface StoryNarrativeProps {
  sections: NarrativeSection[];
  events: StoryTimelineEvent[];
}

const time = (ms: number) =>
  new Date(ms).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

const EVENT_LABEL: Record<StoryTimelineEvent['type'], string> = {
  normal: '',
  suspicious: 'Suspicious',
  critical: 'Critical',
};

/**
 * The story told in order: the summary first, then what happened as a timeline of events, then the
 * rest of the narrative (details, anomalies, the conclusion) under its own headings.
 */
export function StoryNarrative({ sections, events }: StoryNarrativeProps) {
  const summary = sections.filter(s => s.type === 'summary');
  const rest = sections.filter(s => s.type !== 'summary');
  const ordered = [...events].sort((a, b) => a.timestamp - b.timestamp);

  return (
    <div className="story-narrative">
      {summary.map((s, i) => (
        <div key={`s${i}`} className="story-narrative-lead">
          {renderNarrative(s.content)}
        </div>
      ))}

      {ordered.length > 0 && (
        <>
          <h3 className="story-narrative-h">What happened</h3>
          <ol className="story-events">
            {ordered.map((e, i) => (
              <li key={i} className={`story-event story-event-${e.type}`}>
                <time className="story-event-time" dateTime={new Date(e.timestamp).toISOString()}>
                  {time(e.timestamp)}
                </time>
                <div className="story-event-body">
                  <div className="story-event-title">
                    {e.title}
                    {EVENT_LABEL[e.type] && <span className="story-event-tag">{EVENT_LABEL[e.type]}</span>}
                  </div>
                  {e.description && <div className="story-event-text">{renderNarrative(e.description)}</div>}
                </div>
              </li>
            ))}
          </ol>
        </>
      )}

      {rest.map((s, i) => (
        <section key={`r${i}`} className={`story-narrative-section story-narrative-${s.type}`}>
          <h3 className="story-narrative-h">{s.title}</h3>
          {renderNarrative(s.content)}
        </section>
      ))}
    </div>
  );
}
