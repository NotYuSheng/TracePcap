import { useEffect, useRef, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Overlay, Popover, Toast, ToastContainer } from '@govtechsg/sgds-react';
import { useEscapeLayer } from '@/utils/useEscapeLayer';
import { aiJobsService, AI_JOBS_CHANGED } from '@/features/aiJobs/aiJobsService';
import { isActive, type AiJob } from '@/features/aiJobs/aiJobs.types';
import { KIND_LABEL, jobPath, placeInLine, runningFor, shortDuration } from '@/features/aiJobs/aiJobText';
import { useNow } from '@/features/aiJobs/useNow';
import './AiWorkChip.css';

const BUSY_POLL_MS = 4000;
const IDLE_POLL_MS = 20000;

interface Note {
  job: AiJob;
}

/**
 * The header's "AI · 1 running · 1 waiting": shown only while the model has work, so a wait has
 * a visible reason. It lists the jobs with a link to where each answer lands, and when a job this
 * tab saw running finishes, a note says so, unless you're already on that page.
 */
export function AiWorkChip() {
  const [jobs, setJobs] = useState<AiJob[]>([]);
  // Open on the page it was opened on: moving to another page (an Open link) closes it.
  const [openAt, setOpenAt] = useState<string | null>(null);
  const [notes, setNotes] = useState<Note[]>([]);
  const seenActive = useRef(new Set<string>());
  const [chipEl, setChipEl] = useState<HTMLButtonElement | null>(null);
  const popRef = useRef<HTMLDivElement>(null);
  const location = useLocation();
  const pathRef = useRef(location.pathname);
  useEffect(() => {
    pathRef.current = location.pathname;
  }, [location.pathname]);

  const active = jobs.filter(j => isActive(j));
  const open = openAt === location.pathname && active.length > 0;
  const setOpen = (v: boolean) => setOpenAt(v ? location.pathname : null);
  const now = useNow(open ? 1000 : 30000);
  const running = active.filter(j => j.status === 'RUNNING').length;
  const waiting = active.length - running;

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const look = async () => {
      if (timer) clearTimeout(timer);
      let next: AiJob[] = [];
      try {
        next = await aiJobsService.list();
      } catch {
        // The chip is a convenience: an error just means nothing to show this time.
      }
      if (!alive) return;
      setJobs(next);
      const finished: Note[] = [];
      for (const j of next) {
        const live = j.status === 'WAITING' || j.status === 'RUNNING';
        if (live) seenActive.current.add(j.id);
        else if (seenActive.current.delete(j.id) && (j.status === 'DONE' || j.status === 'FAILED')) {
          if (jobPath(j) !== pathRef.current) finished.push({ job: j });
        }
      }
      if (finished.length) setNotes(n => [...n, ...finished]);
      timer = setTimeout(look, next.some(j => isActive(j)) ? BUSY_POLL_MS : IDLE_POLL_MS);
    };
    look();
    window.addEventListener(AI_JOBS_CHANGED, look);
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
      window.removeEventListener(AI_JOBS_CHANGED, look);
    };
  }, []);

  useEscapeLayer(() => setOpenAt(null), { enabled: open, ref: popRef });
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!popRef.current?.contains(t) && !chipEl?.contains(t)) setOpenAt(null);
    };
    document.addEventListener('mousedown', away);
    return () => document.removeEventListener('mousedown', away);
  }, [open, chipEl]);

  const summary = [running ? `${running} running` : '', waiting ? `${waiting} waiting` : '']
    .filter(Boolean)
    .join(' · ');

  return (
    <>
      {active.length > 0 && (
        <button
          ref={setChipEl}
          type="button"
          className="ai-work-chip"
          aria-expanded={open}
          aria-controls="ai-work-popover"
          aria-label={`AI work: ${summary}`}
          onClick={() => setOpen(!open)}
          data-testid="ai-work-chip"
        >
          <i className="bi bi-stars" aria-hidden="true" /> AI · {summary}
        </button>
      )}
      <Overlay target={chipEl} show={open} placement="bottom-end">
        <Popover id="ai-work-popover" className="ai-work-popover" ref={popRef}>
          <Popover.Body>
            <div className="ai-work-head">
              <strong>AI work</strong>
              <span className="text-muted">the model answers one thing at a time</span>
            </div>
            <ul className="ai-work-list">
              {active.map(j => {
                const path = jobPath(j);
                return (
                  <li key={j.id}>
                    <span className={`ai-work-dot${j.status === 'RUNNING' ? ' is-running' : ''}`} aria-hidden="true" />
                    <div className="ai-work-what">
                      <div>
                        <strong>{KIND_LABEL[j.kind] ?? j.kind}</strong> · {j.subjectName ?? 'unnamed'}
                      </div>
                      <div className="text-muted small">
                        {j.status === 'RUNNING'
                          ? `Running · ${shortDuration(runningFor(j, now))}${j.typicalMs ? ` · usually about ${shortDuration(j.typicalMs)}` : ''}`
                          : `Waiting · ${placeInLine(j.position)}`}
                        {j.trigger === 'UPLOAD' ? ' · asked at upload' : ''}
                      </div>
                    </div>
                    {path && (
                      <Link to={path} className="small">
                        Open
                      </Link>
                    )}
                  </li>
                );
              })}
            </ul>
            <div className="ai-work-foot text-muted small">Cancel a waiting one from the page you asked on.</div>
          </Popover.Body>
        </Popover>
      </Overlay>
      <ToastContainer position="bottom-end" className="ai-work-toasts">
        {notes.map(({ job }) => {
          const path = jobPath(job);
          const ok = job.status === 'DONE';
          const close = () => setNotes(n => n.filter(x => x.job.id !== job.id));
          return (
            <Toast key={job.id} show onClose={close} autohide delay={ok ? 12000 : 20000} status={ok ? 'success' : 'danger'}>
              <Toast.Header>
                <strong className="me-auto">
                  {KIND_LABEL[job.kind] ?? job.kind} {ok ? 'ready' : "couldn't be written"}
                </strong>
              </Toast.Header>
              <Toast.Body>
                {job.subjectName}
                {!ok && job.error?.message ? <div className="small text-muted">{job.error.message}</div> : null}
                {path && (
                  <div className="mt-1">
                    <Link to={path} onClick={close}>
                      Open
                    </Link>
                  </div>
                )}
              </Toast.Body>
            </Toast>
          );
        })}
      </ToastContainer>
    </>
  );
}
