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

interface TrafficTimelineProps {
  data: TimelineDataPoint[];
}

export const TrafficTimeline = ({ data }: TrafficTimelineProps) => {
  const [viewMode, setViewMode] = useState<'packets' | 'bytes'>('packets');

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="card shadow-sm" style={{ minWidth: '250px' }}>
          <div className="card-body p-2">
            <p className="mb-2 fw-semibold">{formatTimestamp(label)}</p>
            <div className="small">
              {viewMode === 'packets' ? (
                <>
                  <div className="mb-1">
                    <strong>Total Packets:</strong> {formatNumber(payload[0]?.value || 0)}
                  </div>
                  {payload[0]?.payload?.protocols && (
                    <div className="mt-2">
                      <strong>By Protocol:</strong>
                      <ul className="list-unstyled mb-0 mt-1">
                        {Object.entries(payload[0].payload.protocols).map(([proto, count]) => (
                          <li key={proto}>
                            {proto}: {formatNumber(count as number)}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              ) : (
                <>
                  <div className="mb-1">
                    <strong>Total Bytes:</strong> {formatBytes(payload[0]?.value || 0)}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      );
    }
    return null;
  };

  const chartData = data.map(point => ({
    timestamp: point.timestamp,
    value: viewMode === 'packets' ? point.packetCount : point.bytes,
    protocols: point.protocols,
  }));

  return (
    <div className="traffic-timeline">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h5 className="mb-0">Traffic Over Time</h5>
        <div className="btn-group btn-group-sm" role="group">
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
          <Tooltip content={<CustomTooltip />} />
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
              period. Switch between packet count and byte size views using the buttons above.
            </small>
          </div>
        </div>
      </div>
    </div>
  );
};
