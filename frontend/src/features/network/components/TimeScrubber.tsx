import { useEffect, useMemo, useRef, useState } from 'react';
import { Popover } from '@govtechsg/sgds-react';
import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';
import type { GraphEdge } from '../types';
import { bytesHistogram, clampWindow, type TimeWindow } from '../services/timeWindow';
import { PlayByControl, type AxisMode } from './PlayByControl';
import './TimeScrubber.css';

const BUCKETS = 120;
const TICK_MS = 100;
/** At 1×, playback crosses the whole capture in about this long. */
const PLAY_SECONDS_AT_1X = 30;
/** A drag this close (px) to a window edge resizes instead of moving. */
const EDGE_PX = 8;

const WIDTHS = [0.05, 0.1, 0.25, 0.5];
const SPEEDS = [1, 2, 4, 8];

interface Props {
  edges: GraphEdge[];
  bounds: TimeWindow;
  window: TimeWindow | null;
  onWindowChange: (w: TimeWindow | null) => void;
  /** How many of the conversations are active in the window, for the readout. */
  activeCount: number;
  animate: boolean;
  onAnimateChange: (on: boolean) => void;
  /** Hide nodes until their first conversation has started, so playing grows the network. */
  appearWhenSeen: boolean;
  onAppearWhenSeenChange: (on: boolean) => void;
  unseenStyle: 'hide' | 'faint';
  onUnseenStyleChange: (style: 'hide' | 'faint') => void;
  /** Switch to packet-by-packet replay (shown only where replay is available). */
  onModeChange?: (mode: AxisMode) => void;
}

function clock(ms: number, withDate: boolean, seconds = false): string {
  const d = new Date(ms);
  const opts: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit', ...(seconds ? { second: '2-digit' } : {}) };
  return withDate ? d.toLocaleString(undefined, { month: 'short', day: 'numeric', ...opts }) : d.toLocaleTimeString(undefined, opts);
}

function duration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m} min`;
  return `${Math.round((m / 60) * 10) / 10} h`;
}

type Drag = { mode: 'move' | 'from' | 'to'; startX: number; start: TimeWindow };

/**
 * The time axis, as one bar along the bottom of the network graph (inside it, so it stays in
 * fullscreen): play, a small traffic chart with the window on it, the window's times and how many
 * conversations it holds, and a settings popover (window width, speed, traffic animation, whole
 * capture).
 *
 * The chart is the control: drag the window to move it, drag its edges to resize it, click elsewhere
 * to centre it there. From the keyboard it's a slider: arrows move the window (Shift: further), Home
 * and End jump to the ends, Escape shows the whole capture.
 */
export function TimeScrubber({
  edges,
  bounds,
  window: win,
  onWindowChange,
  activeCount,
  animate,
  onAnimateChange,
  appearWhenSeen,
  onAppearWhenSeenChange,
  unseenStyle,
  onUnseenStyleChange,
  onModeChange,
}: Props) {
  const [playing, setPlaying] = useState(false);
  const [widthShare, setWidthShare] = useState(0.1);
  const [speed, setSpeed] = useState(1);
  const span = Math.max(1, bounds.to - bounds.from);
  const multiDay = new Date(bounds.from).toDateString() !== new Date(bounds.to).toDateString();
  const histogram = useMemo(() => bytesHistogram(edges, bounds, BUCKETS), [edges, bounds]);
  const peak = Math.max(1, ...histogram);
  const chartRef = useRef<HTMLDivElement>(null);
  const drag = useRef<Drag | null>(null);

  const winRef = useRef(win);
  winRef.current = win;
  const onChangeRef = useRef(onWindowChange);
  onChangeRef.current = onWindowChange;

  // Playback: slide the window along from the last tick's window; stop at the end.
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

  const set = (w: TimeWindow | null) => {
    winRef.current = w;
    onWindowChange(w);
  };

  const play = () => {
    if (!win || win.to >= bounds.to) set(clampWindow(bounds.from, span * widthShare, bounds));
    setPlaying(true);
  };

  // The window before "Show the whole capture", so switching it back off returns to it.
  const lastWindow = useRef<TimeWindow | null>(null);
  const showAll = () => {
    setPlaying(false);
    if (win) lastWindow.current = win;
    set(null);
  };
  const showWindow = () => {
    set(lastWindow.current ?? clampWindow(bounds.from, span * widthShare, bounds));
  };

  const chooseWidth = (share: number) => {
    setWidthShare(share);
    const centre = win ? (win.from + win.to) / 2 : bounds.from + (span * share) / 2;
    set(clampWindow(centre - (span * share) / 2, span * share, bounds));
  };

  // ── Pointer: move, resize, or centre ───────────────────────────────────────

  const timeAt = (clientX: number) => {
    const r = chartRef.current!.getBoundingClientRect();
    return bounds.from + Math.min(1, Math.max(0, (clientX - r.left) / r.width)) * span;
  };

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    setPlaying(false);
    const r = chartRef.current!.getBoundingClientRect();
    const pxPerMs = r.width / span;
    let cur = win;
    let mode: Drag['mode'] = 'move';
    if (cur) {
      const left = r.left + (cur.from - bounds.from) * pxPerMs;
      const right = r.left + (cur.to - bounds.from) * pxPerMs;
      if (Math.abs(e.clientX - left) <= EDGE_PX) mode = 'from';
      else if (Math.abs(e.clientX - right) <= EDGE_PX) mode = 'to';
      else if (e.clientX < left || e.clientX > right) cur = null;
    }
    if (!cur) {
      const width = win ? win.to - win.from : span * widthShare;
      cur = clampWindow(timeAt(e.clientX) - width / 2, width, bounds);
      set(cur);
    }
    drag.current = { mode, startX: e.clientX, start: cur };
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d) return;
    const r = chartRef.current!.getBoundingClientRect();
    const dt = ((e.clientX - d.startX) / r.width) * span;
    const minWidth = span / 200;
    if (d.mode === 'move') set(clampWindow(d.start.from + dt, d.start.to - d.start.from, bounds));
    else if (d.mode === 'from') {
      set({ from: Math.min(Math.max(bounds.from, d.start.from + dt), d.start.to - minWidth), to: d.start.to });
    } else {
      set({ from: d.start.from, to: Math.max(Math.min(bounds.to, d.start.to + dt), d.start.from + minWidth) });
    }
  };

  const onPointerUp = () => {
    drag.current = null;
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const cur = win ?? clampWindow(bounds.from, span * widthShare, bounds);
    const width = cur.to - cur.from;
    const step = span * (e.shiftKey ? 0.1 : 0.01);
    let next: TimeWindow | null | undefined;
    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') next = clampWindow(cur.from + step, width, bounds);
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') next = clampWindow(cur.from - step, width, bounds);
    else if (e.key === 'Home') next = clampWindow(bounds.from, width, bounds);
    else if (e.key === 'End') next = clampWindow(bounds.to - width, width, bounds);
    else if (e.key === 'Escape' && win) next = null;
    if (next === undefined) return;
    e.preventDefault();
    e.stopPropagation();
    setPlaying(false);
    set(next);
  };

  const pct = (t: number) => ((t - bounds.from) / span) * 100;

  const settings = (
    <Popover id="time-scrubber-settings" className="ts-popover">
      <Popover.Body>
        {onModeChange && <PlayByControl mode="window" onChange={onModeChange} />}
        <div className="ts-setting">
          <span className="ts-setting-label" id="ts-width-label">Window</span>
          <div className="ts-segmented" role="group" aria-labelledby="ts-width-label">
            {WIDTHS.map(w => (
              <button key={w} type="button" aria-pressed={widthShare === w} onClick={() => chooseWidth(w)}>
                {Math.round(w * 100)}%
              </button>
            ))}
          </div>
          <span className="ts-hint">{Math.round(widthShare * 100)}% of the capture = {duration(span * widthShare)}</span>
        </div>
        <div className="ts-setting">
          <span className="ts-setting-label" id="ts-speed-label">Speed</span>
          <div className="ts-segmented" role="group" aria-labelledby="ts-speed-label">
            {SPEEDS.map(s => (
              <button key={s} type="button" aria-pressed={speed === s} onClick={() => setSpeed(s)}>
                {s}×
              </button>
            ))}
          </div>
        </div>
        <div className="form-check form-switch ts-setting-row">
          <input
            className="form-check-input"
            type="checkbox"
            role="switch"
            id="ts-animate"
            checked={animate}
            onChange={e => onAnimateChange(e.target.checked)}
          />
          <label className="form-check-label" htmlFor="ts-animate">Animate traffic</label>
        </div>
        <div className="form-check form-switch ts-setting-row">
          <input
            className="form-check-input"
            type="checkbox"
            role="switch"
            id="ts-appear"
            checked={appearWhenSeen}
            onChange={e => onAppearWhenSeenChange(e.target.checked)}
          />
          <label className="form-check-label" htmlFor="ts-appear">Nodes appear when first seen</label>
          <div className="ts-hint">Until its first conversation a node is hidden or faint, so playing grows the network.</div>
        </div>
        {appearWhenSeen && (
          <div className="ts-setting" role="group" aria-label="Nodes not seen yet">
            <span className="ts-setting-label">Nodes not seen yet</span>
            <div className="ts-segmented ts-segmented-2">
              {(['hide', 'faint'] as const).map(s => (
                <button key={s} type="button" aria-pressed={unseenStyle === s} onClick={() => onUnseenStyleChange(s)}>
                  {s === 'hide' ? 'Hide them' : 'Show them faint'}
                </button>
              ))}
            </div>
          </div>
        )}
        <div className="form-check form-switch ts-setting-row">
          <input
            className="form-check-input"
            type="checkbox"
            role="switch"
            id="ts-whole"
            checked={!win}
            onChange={e => (e.target.checked ? showAll() : showWindow())}
          />
          <label className="form-check-label" htmlFor="ts-whole">Show the whole capture</label>
          <div className="ts-hint">Off goes back to the window you had.</div>
        </div>
      </Popover.Body>
    </Popover>
  );

  return (
    <div className="time-scrubber" data-testid="traffic-timeline">
      <button
        type="button"
        className="ts-play"
        onClick={() => (playing ? setPlaying(false) : play())}
        aria-label={playing ? 'Pause' : 'Play through the capture'}
      >
        <i className={`bi ${playing ? 'bi-pause-fill' : 'bi-play-fill'}`} aria-hidden="true" />
      </button>
      <span className="ts-edge-time">{clock(bounds.from, multiDay)}</span>
      <div
        ref={chartRef}
        className="ts-chart"
        role="slider"
        tabIndex={0}
        aria-label="Time window"
        aria-valuemin={bounds.from}
        aria-valuemax={bounds.to}
        aria-valuenow={win?.from ?? bounds.from}
        aria-valuetext={win ? `${clock(win.from, multiDay, true)} to ${clock(win.to, multiDay, true)}` : 'The whole capture'}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onKeyDown={onKeyDown}
        data-testid="timeline-chart"
      >
        <div className="ts-bars" aria-hidden="true">
          {histogram.map((v, i) => {
            const t = bounds.from + ((i + 0.5) / BUCKETS) * span;
            const inside = !win || (t >= win.from && t <= win.to);
            return (
              <span
                key={i}
                className={inside ? 'ts-bar ts-bar-in' : 'ts-bar'}
                style={{ height: v > 0 ? `${Math.max(6, (v / peak) * 100)}%` : 0 }}
              />
            );
          })}
        </div>
        {win && (
          <div className="ts-window" style={{ left: `${pct(win.from)}%`, width: `${Math.max(0.5, pct(win.to) - pct(win.from))}%` }}>
            <span className="ts-handle ts-handle-from" />
            <span className="ts-handle ts-handle-to" />
          </div>
        )}
      </div>
      <span className="ts-edge-time">{clock(bounds.to, multiDay)}</span>
      <span className="ts-divider" aria-hidden="true" />
      <div className="ts-readout" aria-live="polite" data-testid="timeline-readout">
        {win ? (
          <>
            <span className="ts-readout-time">{clock(win.from, multiDay, true)} – {clock(win.to, multiDay, true)}</span>
            <span className="ts-readout-count">{activeCount} of {edges.length} conversations</span>
          </>
        ) : (
          <>
            <span className="ts-readout-time">Whole capture</span>
            <span className="ts-readout-count">{duration(span)} · {edges.length} conversations</span>
          </>
        )}
      </div>
      {win && (
        <button type="button" className="ts-icon-btn" onClick={showAll} aria-label="Show the whole capture">
          <i className="bi bi-x-lg" aria-hidden="true" />
        </button>
      )}
      <EscapableOverlayTrigger trigger="click" placement="top-end" overlay={settings}>
        <button type="button" className="ts-icon-btn" aria-label="Time axis settings">
          <i className="bi bi-sliders" aria-hidden="true" />
        </button>
      </EscapableOverlayTrigger>
    </div>
  );
}
