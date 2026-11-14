import { useMemo, useRef } from 'react';
import { Popover } from '@govtechsg/sgds-react';
import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';
import type { GraphEdge } from '../types';
import { bytesHistogram, type TimeWindow } from '../services/timeWindow';
import { describeMoment } from '../services/packetReplay';
import type { PacketReplay } from '../hooks/usePacketReplay';
import { PlayByControl, type AxisMode } from './PlayByControl';
import './TimeScrubber.css';

const BUCKETS = 120;
const SPEEDS = [1, 2, 5, 10, 25];

interface Props {
  edges: GraphEdge[];
  bounds: TimeWindow;
  replay: PacketReplay;
  onModeChange: (mode: AxisMode) => void;
  /** How many of the moment's packets have no edge on the graph (their conversation is filtered out). */
  offGraph: number;
}

function clockMs(ms: number): string {
  const d = new Date(ms);
  const t = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  return `${t}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}

/**
 * The time axis in packet-by-packet mode: the capture plays one moment at a time, every packet of a
 * moment together. Play, step back and forward, a playhead on the traffic chart (click or drag to
 * seek), and what the current packet is.
 *
 * From the keyboard the chart is a slider: arrows step a moment (Shift: ten), Home and End jump to
 * the ends.
 */
export function PacketReplayBar({ edges, bounds, replay, onModeChange, offGraph }: Props) {
  const span = Math.max(1, bounds.to - bounds.from);
  const histogram = useMemo(() => bytesHistogram(edges, bounds, BUCKETS), [edges, bounds]);
  const peak = Math.max(1, ...histogram);
  const chartRef = useRef<HTMLDivElement>(null);
  const dragging = useRef(false);
  const { moment, status } = replay;
  const pct = moment ? ((moment.t - bounds.from) / span) * 100 : 0;

  const timeAt = (clientX: number) => {
    const r = chartRef.current!.getBoundingClientRect();
    return bounds.from + Math.min(1, Math.max(0, (clientX - r.left) / r.width)) * span;
  };

  const onPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    dragging.current = true;
    e.currentTarget.setPointerCapture(e.pointerId);
    replay.seek(timeAt(e.clientX));
  };
  const onPointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    if (dragging.current) replay.seek(timeAt(e.clientX));
    dragging.current = false;
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const by = e.shiftKey ? 10 : 1;
    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') replay.step(by);
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') replay.step(-by);
    else if (e.key === 'Home') replay.seek(bounds.from);
    else if (e.key === 'End') replay.seek(bounds.to);
    else return;
    e.preventDefault();
    e.stopPropagation();
  };

  const settings = (
    <Popover id="packet-replay-settings" className="ts-popover">
      <Popover.Body>
        <PlayByControl mode="packets" onChange={onModeChange} />
        <div className="ts-setting">
          <span className="ts-setting-label" id="pr-speed-label">Speed</span>
          <div className="ts-segmented ts-segmented-5" role="group" aria-labelledby="pr-speed-label">
            {SPEEDS.map(s => (
              <button key={s} type="button" aria-pressed={replay.speed === s} onClick={() => replay.setSpeed(s)}>
                {s}
              </button>
            ))}
          </div>
          <span className="ts-hint">Moments a second. Packets captured at the same instant play together.</span>
        </div>
      </Popover.Body>
    </Popover>
  );

  let line1: string;
  let line2: string;
  if (status === 'pruned') {
    line1 = 'Packets not kept';
    line2 = "This capture's packets were pruned, so it can't be replayed.";
  } else if (status === 'error') {
    line1 = 'Replay unavailable';
    line2 = "The packets couldn't be loaded.";
  } else if (!moment) {
    line1 = 'Loading packets…';
    line2 = '';
  } else {
    const n = moment.packets.length;
    const first = moment.packets[0].number;
    line1 = `${n > 1 ? `Packets ${first.toLocaleString()}–${(first + n - 1).toLocaleString()}` : `Packet ${first.toLocaleString()}`} of ${replay.total.toLocaleString()} · ${clockMs(moment.t)}`;
    line2 = describeMoment(moment) + (offGraph > 0 ? ` · ${offGraph} not on the graph` : '');
  }

  const ready = status === 'ready' && moment != null;
  return (
    <div className="time-scrubber packet-replay" data-testid="packet-replay">
      <button
        type="button"
        className="ts-play"
        onClick={() => (replay.playing ? replay.pause() : replay.play())}
        disabled={!ready}
        aria-label={replay.playing ? 'Pause' : 'Play packet by packet'}
      >
        <i className={`bi ${replay.playing ? 'bi-pause-fill' : 'bi-play-fill'}`} aria-hidden="true" />
      </button>
      <button type="button" className="ts-icon-btn" onClick={() => replay.step(-1)} disabled={!ready} aria-label="Previous moment">
        <i className="bi bi-skip-start-fill" aria-hidden="true" />
      </button>
      <button type="button" className="ts-icon-btn" onClick={() => replay.step(1)} disabled={!ready} aria-label="Next moment">
        <i className="bi bi-skip-end-fill" aria-hidden="true" />
      </button>
      <div
        ref={chartRef}
        className="ts-chart"
        role="slider"
        tabIndex={0}
        aria-label="Replay position"
        aria-valuemin={1}
        aria-valuemax={Math.max(1, replay.total)}
        aria-valuenow={replay.position || 1}
        aria-valuetext={moment ? `Packet ${replay.position} of ${replay.total}, ${clockMs(moment.t)}` : 'Loading'}
        onPointerDown={onPointerDown}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onKeyDown={onKeyDown}
        data-testid="replay-chart"
      >
        <div className="ts-bars" aria-hidden="true">
          {histogram.map((v, i) => {
            const t = bounds.from + ((i + 0.5) / BUCKETS) * span;
            const played = moment != null && t <= moment.t;
            return (
              <span
                key={i}
                className={played ? 'ts-bar ts-bar-in' : 'ts-bar'}
                style={{ height: v > 0 ? `${Math.max(6, (v / peak) * 100)}%` : 0 }}
              />
            );
          })}
        </div>
        {moment && <div className="pr-playhead" style={{ left: `${pct}%` }} aria-hidden="true" />}
      </div>
      <span className="ts-divider" aria-hidden="true" />
      <div className="ts-readout pr-readout" aria-live="polite" data-testid="replay-readout">
        <span className="ts-readout-time">{line1}</span>
        <span className="ts-readout-count pr-detail">{line2}</span>
      </div>
      <EscapableOverlayTrigger trigger="click" placement="top-end" overlay={settings}>
        <button type="button" className="ts-icon-btn" aria-label="Replay settings">
          <i className="bi bi-sliders" aria-hidden="true" />
        </button>
      </EscapableOverlayTrigger>
    </div>
  );
}
