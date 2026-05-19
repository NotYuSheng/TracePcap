import { useEffect, useState, useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import type { TimelineDataPoint } from '@/types';
import { timelineService } from '@/features/timeline/services/timelineService';
import { parseDateTime } from '@/utils/dateUtils';
import { formatBytes, formatNumber } from '@/utils/formatters';

// Same palette as TrafficTimeline
const PROTOCOL_COLORS = [
  '#0d6efd', '#198754', '#dc3545', '#ffc107', '#0dcaf0',
  '#6f42c1', '#fd7e14', '#20c997', '#d63384', '#6c757d', '#adb5bd',
];
function protocolColor(i: number): string {
  return PROTOCOL_COLORS[i % PROTOCOL_COLORS.length];
}

const GRANULARITY_OPTIONS: { label: string; seconds: number }[] = [
  { label: '1s',  seconds: 1 },
  { label: '5s',  seconds: 5 },
  { label: '30s', seconds: 30 },
  { label: '1m',  seconds: 60 },
  { label: '5m',  seconds: 300 },
  { label: '10m', seconds: 600 },
  { label: '30m', seconds: 1800 },
  { label: '1h',  seconds: 3600 },
  { label: '1d',  seconds: 86400 },
];

function formatSnapLabel(snap: NetworkSnapshot): string {
  if (snap.startTime) {
    const ms = parseDateTime(snap.startTime as unknown as string | number[]);
    return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }
  return snap.fileName;
}

function effectiveInterval(points: TimelineDataPoint[]): number | null {
  if (points.length < 2) return null;
  return Math.round((points[points.length - 1].timestamp - points[0].timestamp) / (points.length - 1) / 1000);
}

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

interface ChartBin {
  label: string;        // x-axis tick label
  snapLabel: string;    // snapshot label for tooltip
  timestamp: number;
  packets: number;
  bytes: number;
  protocols: Record<string, number>;
  isBoundary?: boolean; // true on first bin of each snapshot
}

interface TooltipProps {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; color?: string; payload?: ChartBin }>;
  label?: string;
  viewMode: 'packets' | 'bytes';
}

function CustomTooltip({ active, payload, label, viewMode }: TooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const total = payload.reduce((s, e) => s + (e.value ?? 0), 0);
  const snapLabel = payload[0]?.payload?.snapLabel;
  return (
    <div className="card shadow-sm" style={{ minWidth: 200 }}>
      <div className="card-body p-2 small">
        {snapLabel && <p className="mb-0 text-muted" style={{ fontSize: '0.7rem' }}>{snapLabel}</p>}
        <p className="mb-1 fw-semibold">{label}</p>
        <div className="mb-1">
          <strong>Total {viewMode === 'packets' ? 'Packets' : 'Bytes'}:</strong>{' '}
          {viewMode === 'packets' ? formatNumber(total) : formatBytes(total)}
        </div>
        {payload.length > 1 && (
          <ul className="list-unstyled mb-0 mt-1">
            {[...payload].reverse().map(e => (
              <li key={e.name} className="d-flex justify-content-between gap-3">
                <span style={{ color: e.color }}>{e.name}</span>
                <span>{viewMode === 'packets' ? formatNumber(e.value ?? 0) : formatBytes(e.value ?? 0)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

interface Props {
  snapshots: NetworkSnapshot[];
}

export const SnapshotTrafficChart = ({ snapshots }: Props) => {
  const [allPoints, setAllPoints] = useState<Map<string, TimelineDataPoint[]>>(new Map());
  const [loading, setLoading] = useState(false);
  const [viewMode, setViewMode] = useState<'packets' | 'bytes'>('packets');
  const [granularity, setGranularity] = useState<number | 'auto'>('auto');

  const sorted = useMemo(
    () => [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder),
    [snapshots],
  );

  useEffect(() => {
    if (sorted.length === 0) return;
    setLoading(true);
    const interval = granularity === 'auto' ? undefined : granularity;
    Promise.all(
      sorted.map(snap =>
        timelineService.getTimelineData(snap.fileId, interval).then(points => ({ snapId: snap.id, points }))
      )
    ).then(results => {
      const map = new Map<string, TimelineDataPoint[]>();
      for (const r of results) map.set(r.snapId, r.points);
      setAllPoints(map);
    }).finally(() => setLoading(false));
  }, [sorted, granularity]);

  // Compute auto label from first snapshot's data
  const autoLabel = useMemo(() => {
    const firstPoints = allPoints.get(sorted[0]?.id ?? '');
    if (!firstPoints) return 'Auto';
    const secs = effectiveInterval(firstPoints);
    return secs !== null ? `Auto (${formatInterval(secs)})` : 'Auto';
  }, [allPoints, sorted]);

  // Flatten all snapshot bins into one chart array, with boundary markers
  const { chartData, boundaryIndices } = useMemo(() => {
    const bins: ChartBin[] = [];
    const boundaries: number[] = [];

    for (const snap of sorted) {
      const points = allPoints.get(snap.id) ?? [];
      const snapLabel = formatSnapLabel(snap);
      let first = true;
      for (const pt of points) {
        if (first) boundaries.push(bins.length);
        bins.push({
          label: new Date(pt.timestamp).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }),
          snapLabel,
          timestamp: pt.timestamp,
          packets: pt.packetCount,
          bytes: pt.bytes,
          protocols: pt.protocols ?? {},
          isBoundary: first,
        });
        first = false;
      }
    }
    return { chartData: bins, boundaryIndices: boundaries };
  }, [allPoints, sorted]);

  const allProtocols = useMemo(() => {
    const totals: Record<string, number> = {};
    for (const bin of chartData) {
      for (const [proto, count] of Object.entries(bin.protocols)) {
        totals[proto] = (totals[proto] ?? 0) + count;
      }
    }
    return Object.entries(totals).sort((a, b) => b[1] - a[1]).map(([p]) => p);
  }, [chartData]);

  const rechartsData = useMemo(() =>
    chartData.map(bin => {
      if (viewMode === 'bytes') return { ...bin };
      const entry: Record<string, unknown> = { ...bin };
      for (const proto of allProtocols) entry[proto] = bin.protocols[proto] ?? 0;
      return entry;
    }),
    [chartData, viewMode, allProtocols],
  );

  if (snapshots.length < 2) return null;

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
        <span className="text-muted small">
          Traffic bins across {sorted.length} snapshots — vertical lines mark snapshot boundaries
        </span>
        <div className="d-flex align-items-center gap-2 flex-wrap">
          <div className="d-flex align-items-center gap-1">
            <label className="text-muted small mb-0">Granularity:</label>
            <select
              className="form-select form-select-sm"
              style={{ width: 'auto' }}
              value={granularity === 'auto' ? 'auto' : String(granularity)}
              onChange={e => {
                const val = e.target.value;
                setGranularity(val === 'auto' ? 'auto' : Number(val));
              }}
            >
              <option value="auto">{autoLabel}</option>
              {GRANULARITY_OPTIONS.map(({ label, seconds }) => (
                <option key={seconds} value={String(seconds)}>{label}</option>
              ))}
            </select>
          </div>
          <div className="btn-group btn-group-sm">
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

      {loading ? (
        <div className="d-flex align-items-center justify-content-center py-5 text-muted">
          <span className="spinner-border spinner-border-sm me-2" />
          Loading traffic data…
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={rechartsData} margin={{ top: 4, right: 16, left: 0, bottom: 0 }} barCategoryGap="10%">
            <CartesianGrid strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="snapLabel" tick={{ fontSize: 11 }} interval="preserveStartEnd" />
            <YAxis tickFormatter={v => viewMode === 'packets' ? formatNumber(v) : formatBytes(v)} tick={{ fontSize: 11 }} width={60} />
            <Tooltip content={<CustomTooltip viewMode={viewMode} />} wrapperStyle={{ zIndex: 9999 }} />
            {/* Snapshot boundary lines */}
            {boundaryIndices.slice(1).map(idx => (
              <ReferenceLine key={idx} x={rechartsData[idx]?.snapLabel as string} stroke="#6c757d" strokeDasharray="4 2" strokeWidth={1.5} />
            ))}
            {viewMode === 'packets' ? (
              <>
                <Legend wrapperStyle={{ fontSize: 12 }} />
                {allProtocols.map((proto, i) => (
                  <Bar key={proto} dataKey={proto} stackId="a" fill={protocolColor(i)} isAnimationActive={false} />
                ))}
              </>
            ) : (
              <Bar dataKey="bytes" fill="#0d6efd" isAnimationActive={false} />
            )}
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
};
