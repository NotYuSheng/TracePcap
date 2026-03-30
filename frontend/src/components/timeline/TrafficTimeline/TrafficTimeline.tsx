import { useState } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
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

/** Derive the effective bin interval (seconds) from the returned data. */
function effectiveInterval(data: TimelineDataPoint[]): number | null {
  if (data.length < 2) return null;
  return Math.round((data[data.length - 1].timestamp - data[0].timestamp) / (data.length - 1) / 1000);
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

interface ChartDataPoint {
  timestamp: number;
  value: number;
  protocols: Record<string, number>;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ value?: number; payload?: ChartDataPoint }>;
  label?: number;
  viewMode: 'packets' | 'bytes';
}

function CustomTooltip({ active, payload, label, viewMode }: CustomTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const entry = payload[0];
  return (
    <div className="card shadow-sm" style={{ minWidth: '250px' }}>
      <div className="card-body p-2">
        <p className="mb-2 fw-semibold">{formatTimestamp(label as number)}</p>
        <div className="small">
          {viewMode === 'packets' ? (
            <>
              <div className="mb-1">
                <strong>Total Packets:</strong> {formatNumber(entry.value ?? 0)}
              </div>
              {entry.payload?.protocols && (
                <div className="mt-2">
                  <strong>By Protocol:</strong>
                  <ul className="list-unstyled mb-0 mt-1">
                    {Object.entries(entry.payload.protocols).map(([proto, count]) => (
                      <li key={proto}>
                        {proto}: {formatNumber(count)}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          ) : (
            <div className="mb-1">
              <strong>Total Bytes:</strong> {formatBytes(entry.value ?? 0)}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface TrafficTimelineProps {
  data: TimelineDataPoint[];
  granularity: number | 'auto';
  onGranularityChange: (g: number | 'auto') => void;
}

export const TrafficTimeline = ({ data, granularity, onGranularityChange }: TrafficTimelineProps) => {
  const [viewMode, setViewMode] = useState<'packets' | 'bytes'>('packets');

  const autoLabel = (() => {
    const secs = effectiveInterval(data);
    return secs !== null ? `Auto (${formatInterval(secs)})` : 'Auto';
  })();

  const chartData = data.map(point => ({
    timestamp: point.timestamp,
    value: viewMode === 'packets' ? point.packetCount : point.bytes,
    protocols: point.protocols,
  }));

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
        <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#0d6efd" stopOpacity={0.8} />
              <stop offset="95%" stopColor="#0d6efd" stopOpacity={0.1} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis
            dataKey="timestamp"
            tickFormatter={ts => {
              const date = new Date(ts);
              return date.toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit',
              });
            }}
          />
          <YAxis
            tickFormatter={value =>
              viewMode === 'packets' ? formatNumber(value) : formatBytes(value)
            }
          />
          <Tooltip content={<CustomTooltip viewMode={viewMode} />} />
          <Legend formatter={() => (viewMode === 'packets' ? 'Packet Count' : 'Bytes')} />
          <Area
            type="monotone"
            dataKey="value"
            stroke="#0d6efd"
            fillOpacity={1}
            fill="url(#colorValue)"
          />
        </AreaChart>
      </ResponsiveContainer>

      <div className="row mt-4">
        <div className="col-md-12">
          <div className="alert alert-info">
            <small>
              <strong>Tip:</strong> Hover over the chart to see detailed information about each time
              period. Use the granularity selector to adjust the bin size, or leave it on Auto for
              an optimal view of the capture duration.
            </small>
          </div>
        </div>
      </div>
    </div>
  );
};
