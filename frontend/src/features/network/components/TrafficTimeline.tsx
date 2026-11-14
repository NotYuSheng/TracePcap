import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import type { GraphEdge } from '../types';
import { bytesHistogram, clampWindow, type TimeWindow } from '../services/timeWindow';

const BUCKETS = 120;
const TICK_MS = 100;
/** At 1×, playback crosses the whole capture in about this long. */
const PLAY_SECONDS_AT_1X = 30;

/** Window widths offered, as a share of the capture. */
const WIDTHS: { value: number; label: string }[] = [
  { value: 0.05, label: '5% of capture' },
  { value: 0.1, label: '10% of capture' },
  { value: 0.25, label: '25% of capture' },
  { value: 0.5, label: '50% of capture' },
];

const SPEEDS = [1, 2, 4, 8];

interface Props {
  edges: GraphEdge[];
  bounds: TimeWindow;
  window: TimeWindow | null;
  onWindowChange: (w: TimeWindow | null) => void;
  /** How many of the conversations are active in the window, for the readout. */
  activeCount: number;
  /** Dots moving along the edges, on or off. */
  animate: boolean;
  onAnimateChange: (on: boolean) => void;
}

function clock(ms: number, withDate: boolean): string {
  const d = new Date(ms);
  return withDate
    ? d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function duration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m} min`;
  const h = Math.round((m / 60) * 10) / 10;
  return `${h} h`;
}

/**
 * The capture's traffic over time, with a window that picks which part the graph shows: drag the
 * sliders, click the chart to centre the window there, or play it through the capture. The graph
 * keeps its layout and only dims what's outside the window, so what changes over time stays where
 * it was on screen.
 */
export function TrafficTimeline({
  edges,
  bounds,
  window: win,
  onWindowChange,
  activeCount,
  animate,
  onAnimateChange,
}: Props) {
  const [playing, setPlaying] = useState(false);
  const [widthShare, setWidthShare] = useState(0.1);
  const [speed, setSpeed] = useState(1);
  const span = Math.max(1, bounds.to - bounds.from);
  const multiDay = new Date(bounds.from).toDateString() !== new Date(bounds.to).toDateString();
  const histogram = useMemo(() => bytesHistogram(edges, bounds, BUCKETS), [edges, bounds]);
  const peak = Math.max(1, ...histogram);

  const winRef = useRef(win);
  winRef.current = win;
  const onChangeRef = useRef(onWindowChange);
  onChangeRef.current = onWindowChange;

  // Playback: slide the window along; stop at the end. Each tick moves from the window the last
  // tick set, not from the last render, so a slow render can't stall it.
  useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => {
      const step = (span / ((PLAY_SECONDS_AT_1X * 1000) / TICK_MS)) * speed;
      const cur = winRef.current ?? clampWindow(bounds.from, span * widthShare, bounds);
      if (cur.to >= bounds.to) {
        setPlaying(false);
        return;
      }
      const next = clampWindow(cur.from + step, cur.to - cur.from, bounds);
      winRef.current = next;
      onChangeRef.current(next);
    }, TICK_MS);
    return () => clearInterval(id);
  }, [playing, speed, span, widthShare, bounds]);

  const play = () => {
    // From the start when there's no window yet, or the last one reached the end.
    if (!win || win.to >= bounds.to) {
      const first = clampWindow(bounds.from, span * widthShare, bounds);
      winRef.current = first;
      onWindowChange(first);
    }
    setPlaying(true);
  };

  const setWidth = (share: number) => {
    setWidthShare(share);
    const centre = win ? (win.from + win.to) / 2 : bounds.from + (span * share) / 2;
    onWindowChange(clampWindow(centre - (span * share) / 2, span * share, bounds));
  };

  const centreAt = (t: number) => {
    const width = win ? win.to - win.from : span * widthShare;
    onWindowChange(clampWindow(t - width / 2, width, bounds));
  };

  const pct = (t: number) => ((t - bounds.from) / span) * 100;
  const sliderStep = Math.max(1, Math.round(span / 1000));

  return (
    <div className="border rounded p-2 mb-2" data-testid="traffic-timeline">
      <div className="d-flex flex-wrap align-items-center gap-2 mb-2 small">
        <Button
          type="button"
          size="sm"
          variant="primary"
          onClick={() => (playing ? setPlaying(false) : play())}
          aria-label={playing ? 'Pause' : 'Play through the capture'}
        >
          <i className={`bi ${playing ? 'bi-pause-fill' : 'bi-play-fill'}`} aria-hidden="true" />
          <span className="ms-1">{playing ? 'Pause' : 'Play'}</span>
        </Button>
        <Form.Label htmlFor="timeline-width" className="mb-0 text-muted">Window</Form.Label>
        <Form.Select
          id="timeline-width"
          size="sm"
          style={{ width: 'auto' }}
          value={widthShare}
          onChange={e => setWidth(Number(e.target.value))}
        >
          {WIDTHS.map(w => (
            <option key={w.value} value={w.value}>
              {w.label} ({duration(span * w.value)})
            </option>
          ))}
        </Form.Select>
        <Form.Label htmlFor="timeline-speed" className="mb-0 text-muted">Speed</Form.Label>
        <Form.Select
          id="timeline-speed"
          size="sm"
          style={{ width: 'auto' }}
          value={speed}
          onChange={e => setSpeed(Number(e.target.value))}
        >
          {SPEEDS.map(s => (
            <option key={s} value={s}>{s}×</option>
          ))}
        </Form.Select>
        <Form.Check
          type="switch"
          id="timeline-animate"
          label="Animate traffic"
          className="mb-0 ms-1"
          checked={animate}
          onChange={e => onAnimateChange(e.target.checked)}
        />
        <Button
          type="button"
          size="sm"
          variant="outline-secondary"
          disabled={!win}
          onClick={() => {
            setPlaying(false);
            onWindowChange(null);
          }}
        >
          Show all
        </Button>
        <span className="ms-auto text-muted" aria-live="polite" data-testid="timeline-readout">
          {win ? (
            <>
              <strong className="text-body">{clock(win.from, multiDay)} – {clock(win.to, multiDay)}</strong>
              {' · '}
              {activeCount} of {edges.length} conversations
            </>
          ) : (
            <>
              Whole capture: {clock(bounds.from, multiDay)} – {clock(bounds.to, multiDay)} ({duration(span)})
            </>
          )}
        </span>
      </div>

      {/* Traffic over time; click to centre the window there. */}
      <svg
        role="img"
        aria-label="Traffic over the capture, bytes per interval"
        viewBox={`0 0 ${BUCKETS} 40`}
        preserveAspectRatio="none"
        style={{ width: '100%', height: 56, display: 'block', cursor: 'pointer' }}
        onClick={e => {
          const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          centreAt(bounds.from + ((e.clientX - r.left) / r.width) * span);
        }}
        data-testid="timeline-chart"
      >
        {win && (
          <rect
            x={(pct(win.from) / 100) * BUCKETS}
            y={0}
            width={Math.max(0.4, ((win.to - win.from) / span) * BUCKETS)}
            height={40}
            fill="var(--sgds-primary, #5925dc)"
            opacity={0.15}
          />
        )}
        {histogram.map((v, i) => {
          const h = v > 0 ? Math.max(1, (v / peak) * 38) : 0;
          const t = bounds.from + ((i + 0.5) / BUCKETS) * span;
          const inside = !win || (t >= win.from && t <= win.to);
          return (
            <rect
              key={i}
              x={i + 0.1}
              y={40 - h}
              width={0.8}
              height={h}
              fill={inside ? 'var(--sgds-primary, #5925dc)' : 'var(--tp-text-muted, #8892a4)'}
              opacity={inside ? 0.85 : 0.45}
            />
          );
        })}
      </svg>
      <div className="d-flex justify-content-between text-muted" style={{ fontSize: '0.7rem' }}>
        <span>{clock(bounds.from, multiDay)}</span>
        <span>{clock(bounds.to, multiDay)}</span>
      </div>

      <div className="row g-2 mt-1">
        <div className="col-sm-6">
          <Form.Label htmlFor="timeline-from" className="small text-muted mb-0">
            From
          </Form.Label>
          <input
            type="range"
            className="form-range"
            id="timeline-from"
            min={bounds.from}
            max={bounds.to}
            step={sliderStep}
            value={win?.from ?? bounds.from}
            onChange={e => {
              setPlaying(false);
              const from = Number(e.target.value);
              const to = win?.to ?? bounds.to;
              onWindowChange({ from: Math.min(from, to), to });
            }}
          />
        </div>
        <div className="col-sm-6">
          <Form.Label htmlFor="timeline-to" className="small text-muted mb-0">
            To
          </Form.Label>
          <input
            type="range"
            className="form-range"
            id="timeline-to"
            min={bounds.from}
            max={bounds.to}
            step={sliderStep}
            value={win?.to ?? bounds.to}
            onChange={e => {
              setPlaying(false);
              const to = Number(e.target.value);
              const from = win?.from ?? bounds.from;
              onWindowChange({ from, to: Math.max(to, from) });
            }}
          />
        </div>
      </div>
    </div>
  );
}
