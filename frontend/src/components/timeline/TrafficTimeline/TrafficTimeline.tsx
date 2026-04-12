import { useState, useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import type { TimelineDataPoint } from '@/types';
import { formatTimestamp, formatBytes, formatNumber } from '@/utils/formatters';

const GRANULARITY_OPTIONS: { label: string; seconds: number }[] = [
  { label: '1s', seconds: 1 },
  { label: '5s', seconds: 5 },
  { label: '30s', seconds: 30 },
  { label: '1m', seconds: 60 },
  { label: '5m', seconds: 300 },
  { label: '10m', seconds: 600 },
  { label: '30m', seconds: 1800 },
  { label: '1h', seconds: 3600 },
  { label: '1d', seconds: 86400 },
];

// Distinct colours for protocols — cycles if more than 12
const PROTOCOL_COLORS = [
  '#0d6efd',
  '#198754',
  '#dc3545',
  '#ffc107',
  '#0dcaf0',
  '#6f42c1',
  '#fd7e14',
  '#20c997',
  '#d63384',
  '#6c757d',
  '#0dcaf0',
  '#adb5bd',
];

function protocolColor(index: number): string {
  return PROTOCOL_COLORS[index % PROTOCOL_COLORS.length];
}

/** Derive the effective bin interval (seconds) from the returned data. */
function effectiveInterval(data: TimelineDataPoint[]): number | null {
  if (data.length < 2) return null;
  return Math.round(
    (data[data.length - 1].timestamp - data[0].timestamp) / (data.length - 1) / 1000
  );
}

/** Format seconds as a human-readable label, e.g. 90 → "1m 30s". */
function formatInterval(secs: number): string {
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  if (secs < 3600) return s === 0 ? `${m}m` : `${m}m ${s}s`;
  const h = Math.floor(secs / 3600);
  const rem = Math.floor((secs % 3600) / 60);
  if (secs < 86400) return rem === 0 ? `${h}h` : `${h}h ${rem}m`;
  return `${Math.floor(secs / 86400)}d`;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; color?: string }>;
  label?: number;
  viewMode: 'packets' | 'bytes';
}

function CustomTooltip({ active, payload, label, viewMode }: CustomTooltipProps) {
  if (!active || !payload || payload.length === 0 || typeof label !== 'number') return null;
  const total = payload.reduce((s, e) => s + (e.value ?? 0), 0);
  return (
    <div className="card shadow-sm" style={{ minWidth: '220px' }}>
      <div className="card-body p-2">
        <p className="mb-2 fw-semibold small">{formatTimestamp(label)}</p>
        <div className="mb-1 small">
          <strong>Total {viewMode === 'packets' ? 'Packets' : 'Bytes'}:</strong>{' '}
          {viewMode === 'packets' ? formatNumber(total) : formatBytes(total)}
        </div>
        {viewMode === 'packets' && payload.length > 1 && (
          <ul className="list-unstyled mb-0 mt-1 small">
            {[...payload].reverse().map(entry => (
              <li key={entry.name} className="d-flex justify-content-between gap-3">
                <span style={{ color: entry.color }}>{entry.name}</span>
                <span>{formatNumber(entry.value ?? 0)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

interface TrafficTimelineProps {
  data: TimelineDataPoint[];
  granularity: number | 'auto';
  onGranularityChange: (g: number | 'auto') => void;
}

export const TrafficTimeline = ({
  data,
  granularity,
  onGranularityChange,
}: TrafficTimelineProps) => {
  const [viewMode, setViewMode] = useState<'packets' | 'bytes'>('packets');

  const autoLabel = useMemo(() => {
    const secs = effectiveInterval(data);
    return secs !== null ? `Auto (${formatInterval(secs)})` : 'Auto';
  }, [data]);

  // Collect all protocols across all bins, ordered by total packets descending
  const allProtocols = useMemo(() => {
    const totals: Record<string, number> = {};
    data.forEach(point => {
      Object.entries(point.protocols ?? {}).forEach(([proto, count]) => {
        totals[proto] = (totals[proto] ?? 0) + count;
      });
    });
    return Object.entries(totals)
      .sort((a, b) => b[1] - a[1])
      .map(([proto]) => proto);
  }, [data]);

  // Build chart data: each bin gets a key per protocol (packets mode) or total bytes
  const chartData = useMemo(
    () =>
      data.map(point => {
        const entry: Record<string, number | string> = { timestamp: point.timestamp };
        if (viewMode === 'packets') {
          allProtocols.forEach(proto => {
            entry[proto] = point.protocols?.[proto] ?? 0;
          });
        } else {
          entry['bytes'] = point.bytes;
        }
        return entry;
      }),
    [data, viewMode, allProtocols]
  );

  const xAxisTickFormatter = useMemo(() => {
    const secs = effectiveInterval(data);
    return (ts: number) => {
      const date = new Date(ts);
      if (secs !== null && secs >= 86400) {
        return date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
      }
      if (secs !== null && secs >= 3600) {
        return `${date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })} ${date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}`;
      }
      return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    };
  }, [data]);

  return (
    <div className="traffic-timeline">
      <div className="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
        <h5 className="mb-0">Traffic Over Time</h5>
        <div className="d-flex align-items-center gap-2 flex-wrap">
          <div className="d-flex align-items-center gap-1">
            <label htmlFor="granularity-select" className="text-muted small mb-0">
              Granularity:
            </label>
            <select
              id="granularity-select"
              className="form-select form-select-sm"
              style={{ width: 'auto' }}
              value={granularity === 'auto' ? 'auto' : String(granularity)}
              onChange={e => {
                const val = e.target.value;
                onGranularityChange(val === 'auto' ? 'auto' : Number(val));
              }}
            >
              <option value="auto">{autoLabel}</option>
              {GRANULARITY_OPTIONS.map(({ label, seconds }) => (
                <option key={seconds} value={String(seconds)}>
                  {label}
                </option>
              ))}
            </select>
          </div>
          <div className="btn-group btn-group-sm" role="group" aria-label="View mode">
            <button
              type="button"
              className={`btn ${viewMode === 'packets' ? 'btn-primary' : 'btn-outline-primary'}`}
              onClick={() => setViewMode('packets')}
            >
              Packets
            </button>
            <button
              type="button"
              className={`btn ${viewMode === 'bytes' ? 'btn-primary' : 'btn-outline-primary'}`}
              onClick={() => setViewMode('bytes')}
            >
              Bytes
            </button>
          </div>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={400}>
        <BarChart
          data={chartData}
          margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
          barCategoryGap="20%"
        >
          <CartesianGrid strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="timestamp" tickFormatter={xAxisTickFormatter} />
          <YAxis
            tickFormatter={value =>
              viewMode === 'packets' ? formatNumber(value) : formatBytes(value)
            }
          />
          <Tooltip content={<CustomTooltip viewMode={viewMode} />} />
          {viewMode === 'packets' ? (
            <>
              <Legend />
              {allProtocols.map((proto, i) => (
                <Bar
                  key={proto}
                  dataKey={proto}
                  stackId="a"
                  fill={protocolColor(i)}
                  isAnimationActive={false}
                />
              ))}
            </>
          ) : (
            <Bar dataKey="bytes" fill="#0d6efd" isAnimationActive={false}>
              {chartData.map((_, i) => (
                <Cell key={i} fill="#0d6efd" fillOpacity={0.8} />
              ))}
            </Bar>
          )}
        </BarChart>
      </ResponsiveContainer>

      <div className="mt-3">
        <small className="text-muted">
          <strong>Tip:</strong> Hover over a bar to see the protocol breakdown for that time window.
          Each colour represents a distinct protocol. Use granularity to zoom in or out.
        </small>
      </div>
    </div>
  );
};
