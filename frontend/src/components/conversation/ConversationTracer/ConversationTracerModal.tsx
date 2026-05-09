import { useState, useEffect, useRef, useCallback } from 'react';
import { tracerService, type TracerStep, type TracerStepsResponse } from '@/features/tracer/tracerService';

interface ConversationTracerModalProps {
  conversationId: string;
  onClose: () => void;
}

// ── Animated arrow ────────────────────────────────────────────────────────────

interface ArrowProps {
  direction: 'CLIENT' | 'SERVER';
  label: string;
}

function AnimatedArrow({ direction, label }: ArrowProps) {
  const isLeft = direction === 'SERVER'; // SERVER sends back to client (right→left)
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        justifyContent: 'center',
        fontSize: 12,
        color: direction === 'CLIENT' ? '#0072c6' : '#107c10',
        animation: 'tracerPulse 0.4s ease-out',
      }}
    >
      {isLeft && <span style={{ fontSize: 18 }}>◄</span>}
      <span
        style={{
          background: direction === 'CLIENT' ? '#e8f0fe' : '#e6f4ea',
          padding: '2px 10px',
          borderRadius: 12,
          fontWeight: 500,
        }}
      >
        {label}
      </span>
      {!isLeft && <span style={{ fontSize: 18 }}>►</span>}
    </div>
  );
}

// ── Host node ─────────────────────────────────────────────────────────────────

function HostNode({ ip, port, label }: { ip: string; port: number | null; label: string }) {
  return (
    <div style={{ textAlign: 'center', minWidth: 110 }}>
      <div
        style={{
          width: 56,
          height: 56,
          borderRadius: '50%',
          background: '#f0f4ff',
          border: '2px solid #0072c6',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          margin: '0 auto 4px',
        }}
      >
        <i className="bi bi-pc-display" style={{ fontSize: 22, color: '#0072c6' }} />
      </div>
      <div style={{ fontSize: 11, fontWeight: 600, fontFamily: 'monospace' }}>{ip}</div>
      {port != null && port > 0 && (
        <div style={{ fontSize: 10, color: '#767676' }}>:{port}</div>
      )}
      <div style={{ fontSize: 10, color: '#767676' }}>{label}</div>
    </div>
  );
}

// ── Main modal ────────────────────────────────────────────────────────────────

export const ConversationTracerModal = ({ conversationId, onClose }: ConversationTracerModalProps) => {
  const [tracer, setTracer] = useState<TracerStepsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [currentStep, setCurrentStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [explanations, setExplanations] = useState<Map<number, string>>(new Map());
  const [explainLoading, setExplainLoading] = useState(false);

  const playInterval = useRef<ReturnType<typeof setInterval> | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Fetch steps
  useEffect(() => {
    setLoading(true);
    tracerService.getSteps(conversationId)
      .then(data => {
        setTracer(data);
        setCurrentStep(0);
      })
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load steps'))
      .finally(() => setLoading(false));
  }, [conversationId]);

  // Fetch explanations after steps load
  useEffect(() => {
    if (!tracer || tracer.steps.length === 0) return;
    setExplainLoading(true);
    tracerService.explain(conversationId)
      .then(data => {
        const map = new Map<number, string>();
        data.explanations.forEach(e => map.set(e.stepIndex, e.explanation));
        setExplanations(map);
      })
      .catch(console.error)
      .finally(() => setExplainLoading(false));
  }, [tracer, conversationId]);

  // Auto-play
  useEffect(() => {
    if (!isPlaying || !tracer) return;
    playInterval.current = setInterval(() => {
      setCurrentStep(prev => {
        if (prev >= tracer.steps.length - 1) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 1500);
    return () => { if (playInterval.current) clearInterval(playInterval.current); };
  }, [isPlaying, tracer]);

  // Scroll current step into view in the packet list
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-step="${currentStep}"]`);
    el?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [currentStep]);

  const goTo = useCallback((step: number) => {
    setCurrentStep(step);
    setIsPlaying(false);
  }, []);

  const prev = useCallback(() => goTo(Math.max(0, currentStep - 1)), [currentStep, goTo]);
  const next = useCallback(() => {
    if (tracer) goTo(Math.min(tracer.steps.length - 1, currentStep + 1));
  }, [currentStep, tracer, goTo]);

  const togglePlay = useCallback(() => setIsPlaying(p => !p), []);

  // Keyboard navigation
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'ArrowRight') next();
      if (e.key === 'ArrowLeft') prev();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose, next, prev]);

  const step: TracerStep | undefined = tracer?.steps[currentStep];

  const title = tracer
    ? `${tracer.srcIp}${tracer.srcPort ? `:${tracer.srcPort}` : ''} → ${tracer.dstIp}${tracer.dstPort ? `:${tracer.dstPort}` : ''}`
    : 'Loading…';

  return (
    <>
      {/* CSS animation */}
      <style>{`
        @keyframes tracerPulse {
          from { transform: scale(0.95); opacity: 0.6; }
          to   { transform: scale(1);    opacity: 1;   }
        }
      `}</style>

      {/* Backdrop */}
      <div
        style={{
          position: 'fixed', inset: 0, zIndex: 1060,
          background: 'rgba(0,0,0,0.5)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: 16,
        }}
        onClick={e => { if (e.target === e.currentTarget) onClose(); }}
      >
        <div
          style={{
            background: '#fff', borderRadius: 10,
            width: '100%', maxWidth: 700,
            boxShadow: '0 8px 40px rgba(0,0,0,0.25)',
            display: 'flex', flexDirection: 'column',
            maxHeight: '90vh',
          }}
        >
          {/* Header */}
          <div
            style={{
              padding: '12px 16px',
              borderBottom: '1px solid #dee2e6',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}
          >
            <div>
              <div className="fw-semibold" style={{ fontSize: 14 }}>Conversation Tracer</div>
              <div style={{ fontSize: 11, color: '#767676', fontFamily: 'monospace' }}>{title}</div>
              {tracer?.protocol && (
                <span className="badge bg-secondary ms-0 mt-1" style={{ fontSize: 10 }}>
                  {tracer.protocol}{tracer.appName ? ` / ${tracer.appName}` : ''}
                </span>
              )}
            </div>
            <button className="btn-close" onClick={onClose} />
          </div>

          {loading && (
            <div className="d-flex align-items-center justify-content-center p-5">
              <span className="spinner-border text-primary me-2" />
              <span>Loading packets…</span>
            </div>
          )}

          {error && (
            <div className="alert alert-danger m-3">{error}</div>
          )}

          {!loading && !error && tracer && (
            <>
              {/* Visualization panel */}
              <div style={{ padding: '20px 24px', borderBottom: '1px solid #dee2e6' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16, justifyContent: 'center' }}>
                  <HostNode ip={tracer.srcIp} port={tracer.srcPort} label="Client" />

                  <div style={{ flex: 1, textAlign: 'center' }}>
                    {step ? (
                      <AnimatedArrow
                        key={currentStep}
                        direction={step.direction}
                        label={`${step.protocol} · ${step.size}B`}
                      />
                    ) : (
                      <div style={{ color: '#ccc' }}>—</div>
                    )}
                    {step?.info && (
                      <div style={{ fontSize: 10, color: '#555', marginTop: 4, fontStyle: 'italic' }}>
                        {step.info.length > 80 ? step.info.slice(0, 80) + '…' : step.info}
                      </div>
                    )}
                  </div>

                  <HostNode ip={tracer.dstIp} port={tracer.dstPort} label="Server" />
                </div>

                {/* LLM explanation */}
                <div
                  style={{
                    marginTop: 14,
                    minHeight: 52,
                    background: '#f8f9fa',
                    borderRadius: 6,
                    padding: '8px 12px',
                    fontSize: 12,
                    color: '#333',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  <i className="bi bi-stars" style={{ color: '#6c757d', flexShrink: 0 }} />
                  {explainLoading && !explanations.has(currentStep) ? (
                    <span className="text-muted">Generating AI explanation…</span>
                  ) : explanations.has(currentStep) ? (
                    <span>{explanations.get(currentStep)}</span>
                  ) : (
                    <span className="text-muted">No explanation available for this packet.</span>
                  )}
                </div>
              </div>

              {/* Navigation */}
              <div
                style={{
                  padding: '10px 16px',
                  borderBottom: '1px solid #dee2e6',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12,
                }}
              >
                <button
                  className="btn btn-sm btn-outline-secondary"
                  onClick={prev}
                  disabled={currentStep === 0}
                >
                  ‹ Prev
                </button>
                <span style={{ fontSize: 12, color: '#555', minWidth: 90, textAlign: 'center' }}>
                  Step {currentStep + 1} / {tracer.steps.length}
                </span>
                <button
                  className="btn btn-sm btn-outline-secondary"
                  onClick={next}
                  disabled={currentStep >= tracer.steps.length - 1}
                >
                  Next ›
                </button>
                <button
                  className={`btn btn-sm ${isPlaying ? 'btn-warning' : 'btn-outline-primary'}`}
                  onClick={togglePlay}
                  disabled={currentStep >= tracer.steps.length - 1}
                  title={isPlaying ? 'Pause' : 'Auto-play'}
                >
                  <i className={`bi ${isPlaying ? 'bi-pause-fill' : 'bi-play-fill'}`} />
                </button>
              </div>

              {/* Packet list */}
              <div ref={listRef} style={{ overflowY: 'auto', flex: 1, maxHeight: 220 }}>
                <table className="table table-sm table-hover mb-0" style={{ fontSize: 11 }}>
                  <thead className="table-light sticky-top">
                    <tr>
                      <th>#</th>
                      <th>Dir</th>
                      <th>Protocol</th>
                      <th>Size</th>
                      <th>Timestamp</th>
                      <th>Info</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tracer.steps.map(s => (
                      <tr
                        key={s.stepIndex}
                        data-step={s.stepIndex}
                        onClick={() => goTo(s.stepIndex)}
                        style={{ cursor: 'pointer' }}
                        className={s.stepIndex === currentStep ? 'table-primary' : ''}
                      >
                        <td className="text-muted">{s.stepIndex + 1}</td>
                        <td>
                          <span style={{ color: s.direction === 'CLIENT' ? '#0072c6' : '#107c10', fontWeight: 600 }}>
                            {s.direction === 'CLIENT' ? '→' : '←'}
                          </span>
                        </td>
                        <td>{s.protocol}</td>
                        <td>{s.size}B</td>
                        <td style={{ fontFamily: 'monospace', fontSize: 10 }}>
                          {s.timestamp ? s.timestamp.split(' ')[1] : '—'}
                        </td>
                        <td
                          style={{
                            maxWidth: 200,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                          title={s.info ?? ''}
                        >
                          {s.info ?? '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
};
