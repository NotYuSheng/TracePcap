import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import { tracerService, type TracerStep, type TracerStepsResponse } from '@/features/tracer/tracerService';
import { conversationService } from '@/features/conversation/services/conversationService';

function AiExplanationInfoPopover() {
  const popover = (
    <Popover id="info-ai-explanation" style={{ maxWidth: '320px' }}>
      <Popover.Header>AI Explanation — How it works</Popover.Header>
      <Popover.Body className="small">
        <p className="mb-2">
          For each packet the LLM receives: direction, protocol, size, tshark's dissector info
          string, and up to 64 bytes of payload decoded as ASCII (where readable).
        </p>
        <p className="mb-2">
          <strong>Works well for:</strong> TCP handshakes, HTTP requests, DNS queries, TLS
          handshake phases — where the info field or payload is descriptive.
        </p>
        <p className="mb-0">
          <strong>Limited for:</strong> encrypted traffic (TLS data, RDP) where only size and
          direction are available — explanations will be generic.
        </p>
      </Popover.Body>
    </Popover>
  );
  return (
    <OverlayTrigger trigger="click" placement="right" overlay={popover} rootClose>
      <button
        type="button"
        className="btn btn-link p-0 text-muted"
        style={{ lineHeight: 1, flexShrink: 0 }}
        aria-label="About AI Explanation"
      >
        <i className="bi bi-info-circle" style={{ fontSize: '0.85rem' }}></i>
      </button>
    </OverlayTrigger>
  );
}

interface ConversationTracerModalProps {
  conversationId: string;
  fileId: string;
  onClose: () => void;
}

// ── SVG star-graph constants ───────────────────────────────────────────────

const SVG_W = 500;
const SVG_H = 380;
const CX = SVG_W / 2;
const CY = SVG_H / 2;
const PEER_R = 150; // radius of the peer ring
const NODE_R = 26;  // node circle radius

function peerPos(index: number, total: number): { x: number; y: number } {
  // Start from top (−π/2) so single peer appears directly above center
  const angle = (2 * Math.PI * index) / total - Math.PI / 2;
  return {
    x: CX + PEER_R * Math.cos(angle),
    y: CY + PEER_R * Math.sin(angle),
  };
}

/** Shorten an IP for display inside the small node circle. */
function shortIp(ip: string): string {
  if (ip.length <= 15) return ip;
  // IPv6: show last two groups
  const parts = ip.split(':');
  return '…:' + parts.slice(-2).join(':');
}

// ── Main modal ────────────────────────────────────────────────────────────────

export const ConversationTracerModal = ({ conversationId, fileId, onClose }: ConversationTracerModalProps) => {
  const [tracer, setTracer] = useState<TracerStepsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [peers, setPeers] = useState<string[]>([]);

  const [currentStep, setCurrentStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [explanations, setExplanations] = useState<Map<number, string>>(new Map());
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError] = useState<string | null>(null);

  const [dotT, setDotT] = useState(0);

  const playInterval = useRef<ReturnType<typeof setInterval> | null>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const rafRef = useRef<number | null>(null);
  const rafStart = useRef<number | null>(null);

  // Fetch tracer steps
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

  // Fetch all conversations for srcIp → build peer list
  useEffect(() => {
    if (!tracer || !fileId) return;
    const srcIp = tracer.srcIp;
    conversationService.getConversations(fileId, {
      ip: srcIp,
      port: '', payloadContains: '',
      protocols: [], l7Protocols: [], apps: [], categories: [],
      hasRisks: false, fileTypes: [], riskTypes: [], customSignatures: [],
      deviceTypes: [], countries: [],
      sortBy: '', sortDir: 'desc',
      page: 1, pageSize: 50,
    }).then(result => {
      const peerSet = new Set<string>();
      result.data.forEach(c => {
        const [src, dst] = c.endpoints;
        peerSet.add(src.ip === srcIp ? dst.ip : src.ip);
      });
      // Always include the traced conversation's peer
      peerSet.add(tracer.dstIp);
      setPeers([...peerSet].slice(0, 12));
    }).catch(() => {
      setPeers([tracer.dstIp]);
    });
  }, [tracer, fileId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch LLM explanations after steps load
  useEffect(() => {
    if (!tracer || tracer.steps.length === 0) return;
    setExplainLoading(true);
    setExplainError(null);
    tracerService.explain(conversationId)
      .then(data => {
        if (data.error) {
          setExplainError(data.error);
          return;
        }
        const map = new Map<number, string>();
        data.explanations.forEach(e => map.set(e.stepIndex, e.explanation));
        setExplanations(map);
      })
      .catch(() => {
        setExplainError('AI explanation unavailable — could not reach the language model. Check your LLM configuration.');
      })
      .finally(() => setExplainLoading(false));
  }, [tracer, conversationId]);

  // Auto-play
  useEffect(() => {
    if (!isPlaying || !tracer) return;
    playInterval.current = setInterval(() => {
      setCurrentStep(prev => {
        if (prev >= tracer.steps.length - 1) { setIsPlaying(false); return prev; }
        return prev + 1;
      });
    }, 1500);
    return () => { if (playInterval.current) clearInterval(playInterval.current); };
  }, [isPlaying, tracer]);

  // Animate dot along edge on step change
  useEffect(() => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    rafStart.current = null;
    setDotT(0);
    const DURATION = 500;
    const tick = (ts: number) => {
      if (rafStart.current === null) rafStart.current = ts;
      const t = Math.min((ts - rafStart.current) / DURATION, 1);
      setDotT(t);
      if (t < 1) rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, [currentStep]);

  // Scroll current step into view
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
      if (e.key === 'Escape') { e.stopPropagation(); onClose(); }
      if (e.key === 'ArrowRight') next();
      if (e.key === 'ArrowLeft') prev();
    };
    document.addEventListener('keydown', onKey, true);
    return () => document.removeEventListener('keydown', onKey, true);
  }, [onClose, next, prev]);

  const step: TracerStep | undefined = tracer?.steps[currentStep];

  const title = tracer
    ? `${tracer.srcIp}${tracer.srcPort ? `:${tracer.srcPort}` : ''} → ${tracer.dstIp}${tracer.dstPort ? `:${tracer.dstPort}` : ''}`
    : 'Loading…';

  // Compute dot position for the current step
  const activePeerIp = tracer?.dstIp ?? null;
  const activePeerIdx = peers.indexOf(activePeerIp ?? '');
  const dotPos = useMemo(() => {
    if (!step || activePeerIdx < 0) return null;
    const pos = peerPos(activePeerIdx, peers.length);
    const [fx, fy, tx, ty] = step.direction === 'CLIENT'
      ? [CX, CY, pos.x, pos.y]
      : [pos.x, pos.y, CX, CY];
    return {
      x: fx + (tx - fx) * dotT,
      y: fy + (ty - fy) * dotT,
      color: step.direction === 'CLIENT' ? '#0072c6' : '#107c10',
    };
  }, [step, activePeerIdx, peers.length, dotT]);

  return (
    <>
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
            background: 'var(--tp-surface)', borderRadius: 10,
            width: '100%', maxWidth: 720,
            boxShadow: '0 8px 40px rgba(0,0,0,0.25)',
            display: 'flex', flexDirection: 'column',
            maxHeight: '90vh',
          }}
        >
          {/* Header */}
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--tp-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div className="fw-semibold" style={{ fontSize: 14 }}>Conversation Tracer</div>
              <div style={{ fontSize: 11, color: 'var(--tp-text-muted)', fontFamily: 'monospace' }}>{title}</div>
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

          {error && <div className="alert alert-danger m-3">{error}</div>}

          {!loading && !error && tracer && (
            <>
              {/* Star-graph visualization */}
              <div style={{ padding: '8px 16px 10px', borderBottom: '1px solid var(--tp-border)' }}>
                <svg
                  viewBox={`0 0 ${SVG_W} ${SVG_H}`}
                  style={{ width: '100%', height: 'auto', maxHeight: 260, display: 'block' }}
                >
                  {/* Edges */}
                  {peers.map((ip, i) => {
                    const pos = peerPos(i, peers.length);
                    const isActive = ip === activePeerIp;
                    return (
                      <line
                        key={ip}
                        x1={CX} y1={CY}
                        x2={pos.x} y2={pos.y}
                        stroke={isActive ? '#0072c6' : 'var(--tp-border)'}
                        strokeWidth={isActive ? 2.5 : 1.5}
                        strokeDasharray={isActive ? undefined : '5 4'}
                      />
                    );
                  })}

                  {/* Animated dot */}
                  {dotPos && (
                    <circle
                      cx={dotPos.x}
                      cy={dotPos.y}
                      r={7}
                      fill={dotPos.color}
                      stroke="#fff"
                      strokeWidth={2}
                    />
                  )}

                  {/* Center node (srcIp / host) */}
                  <circle cx={CX} cy={CY} r={NODE_R} fill="var(--tp-bg-subtle)" stroke="#0072c6" strokeWidth={2} />
                  <text
                    x={CX} y={CY + 4}
                    textAnchor="middle" dominantBaseline="middle"
                    fontSize={8} fontFamily="monospace" fill="#0050a0"
                  >
                    {shortIp(tracer.srcIp)}
                  </text>
                  <text x={CX} y={CY + NODE_R + 13} textAnchor="middle" fontSize={10} fill="var(--tp-text-muted)">
                    Host
                  </text>

                  {/* Peer nodes */}
                  {peers.map((ip, i) => {
                    const pos = peerPos(i, peers.length);
                    const isActive = ip === activePeerIp;
                    // Place label above or below based on y position
                    const labelY = pos.y < CY
                      ? pos.y - NODE_R - 6
                      : pos.y + NODE_R + 13;
                    return (
                      <g key={ip}>
                        <circle
                          cx={pos.x} cy={pos.y} r={NODE_R}
                          fill={isActive ? 'var(--tp-surface-hover)' : 'var(--tp-bg-subtle)'}
                          stroke={isActive ? '#0072c6' : 'var(--tp-text-muted)'}
                          strokeWidth={isActive ? 2 : 1.5}
                        />
                        <text
                          x={pos.x} y={pos.y + 4}
                          textAnchor="middle" dominantBaseline="middle"
                          fontSize={8} fontFamily="monospace"
                          fill={isActive ? '#0050a0' : 'var(--tp-text-muted)'}
                        >
                          {shortIp(ip)}
                        </text>
                        <text
                          x={pos.x} y={labelY}
                          textAnchor="middle" fontSize={10}
                          fill={isActive ? '#0072c6' : 'var(--tp-text-muted)'}
                          fontWeight={isActive ? 600 : 400}
                        >
                          {isActive ? 'Traced' : 'Peer'}
                        </text>
                      </g>
                    );
                  })}
                </svg>

                {/* Step info */}
                {step?.info && (
                  <div style={{ fontSize: 10, color: 'var(--tp-text-muted)', textAlign: 'center', marginBottom: 6, fontStyle: 'italic' }}>
                    {step.direction === 'CLIENT' ? '→' : '←'} {step.protocol} · {step.size}B
                    {' — '}
                    {step.info.length > 100 ? step.info.slice(0, 100) + '…' : step.info}
                  </div>
                )}

                {/* LLM explanation */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <AiExplanationInfoPopover />
                  <div
                    style={{
                      flex: 1,
                      minHeight: 44,
                      background: 'var(--tp-bg-subtle)',
                      borderRadius: 6,
                      padding: '6px 12px',
                      fontSize: 12,
                      color: 'var(--tp-text)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                    }}
                  >
                    <i className="bi bi-stars" style={{ color: '#6c757d', flexShrink: 0 }} />
                    {explainLoading ? (
                      <span className="text-muted">Generating AI explanation…</span>
                    ) : explainError ? (
                      <span style={{ color: 'var(--bs-danger)' }}>{explainError}</span>
                    ) : explanations.has(currentStep) ? (
                      <span>{explanations.get(currentStep)}</span>
                    ) : (
                      <span className="text-muted">No explanation available for this packet.</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Navigation */}
              <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--tp-border)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
                <button className="btn btn-sm btn-outline-secondary" onClick={prev} disabled={currentStep === 0}>‹ Prev</button>
                <span style={{ fontSize: 12, color: 'var(--tp-text-muted)', minWidth: 90, textAlign: 'center' }}>
                  Step {currentStep + 1} / {tracer.steps.length}
                </span>
                <button className="btn btn-sm btn-outline-secondary" onClick={next} disabled={currentStep >= tracer.steps.length - 1}>Next ›</button>
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
              <div ref={listRef} style={{ overflowY: 'auto', flex: 1, maxHeight: 200 }}>
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
                          style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
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
