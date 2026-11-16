import { useState } from 'react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { stepArgs, type ChatStep } from '@/features/chat/chatService';

/** "Used 3 tools · 6 s": what an answer looked up, collapsible; open while it is still working. */
export function ChatSteps({ steps, running, elapsedMs }: { steps: ChatStep[]; running: boolean; elapsedMs: number }) {
  const [open, setOpen] = useState(false);
  if (steps.length === 0) return null;
  const shown = running || open;
  const secs = Math.max(1, Math.round(elapsedMs / 1000));
  return (
    <div className="chat-steps">
      <button
        type="button"
        className="chat-steps-toggle"
        aria-expanded={shown}
        onClick={() => setOpen(o => !o)}
        disabled={running}
      >
        <i className={`bi ${shown ? 'bi-chevron-down' : 'bi-chevron-right'} me-1`} aria-hidden="true" />
        {running ? 'Looking things up…' : `Used ${steps.length} ${steps.length === 1 ? 'tool' : 'tools'} · ${secs} s`}
      </button>
      {shown && (
        <ol className="chat-steps-list">
          {steps.map((s, i) => (
            <li key={i} className={`chat-step is-${s.status.toLowerCase()}`}>
              <span className="chat-step-mark" aria-hidden="true">
                {s.status === 'RUNNING' ? (
                  <Spinner animation="border" size="sm" style={{ width: '0.7rem', height: '0.7rem' }} />
                ) : s.status === 'DONE' ? (
                  <i className="bi bi-check-lg" />
                ) : (
                  <i className="bi bi-x-lg" />
                )}
              </span>
              <span>
                <b>{s.label}</b> <span className="chat-step-args">{stepArgs(s)}</span>
                {s.summary && <span className="d-block text-muted">{s.summary}</span>}
              </span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
