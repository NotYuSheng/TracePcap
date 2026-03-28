import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import type { ProtocolStats } from '@/types';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import './ProtocolBreakdownChart.css';

interface ProtocolBreakdownChartProps {
  protocolStats: ProtocolStats[];
}

const protocolInfoPopover = (
  <Popover id="protocol-info" style={{ maxWidth: '300px' }}>
    <Popover.Header>Protocol distribution</Popover.Header>
    <Popover.Body>
      <p className="mb-0">
        Shows the breakdown of <strong>transport-layer protocols</strong> (TCP, UDP, ICMP, ARP,
        etc.) read directly from IP packet headers — no heuristics involved. The counts
        accurately reflect what is declared in each packet's header. Note that tunnelled traffic
        (e.g. GRE, VXLAN, IP-in-IP) will appear as its outer transport protocol, not the
        encapsulated inner protocol.
      </p>
    </Popover.Body>
  </Popover>
);

const COLORS = [
  '#0076d1', // Primary blue
  '#5925dc', // Secondary purple
  '#2ecc71', // Green
  '#f39c12', // Orange
  '#e74c3c', // Red
  '#3498db', // Light blue
  '#9b59b6', // Purple
  '#1abc9c', // Teal
  '#e67e22', // Dark orange
  '#95a5a6', // Gray
];

export const ProtocolBreakdownChart = ({ protocolStats }: ProtocolBreakdownChartProps) => {
  // Format data for the pie chart
  const chartData = protocolStats.map(stat => ({
    name: stat.protocol,
    value: stat.count,
    percentage: stat.percentage,
  }));

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  // Legend rows depend on number of items; each row ≈ 24 px, ~3 items per row at typical widths.
  const chartHeight = Math.max(300, 240 + Math.ceil(chartData.length / 3) * 24);

  return (
    <div className="protocol-breakdown">
      <h3 className="breakdown-title d-flex align-items-center gap-2">
        Protocol Distribution
        <OverlayTrigger trigger="click" placement="right" overlay={protocolInfoPopover} rootClose>
          <button
            type="button"
            className="btn btn-link p-0 text-muted"
            style={{ lineHeight: 1 }}
            aria-label="About protocol detection accuracy"
          >
            <i className="bi bi-info-circle fs-6"></i>
          </button>
        </OverlayTrigger>
      </h3>

      <div className="breakdown-content">
        <div className="breakdown-chart">
          <ResponsiveContainer width="100%" height={chartHeight}>
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={props => `${((props.percent || 0) * 100).toFixed(1)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {chartData.map((_item, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip formatter={value => [`${value?.toLocaleString() || 0} packets`]} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="breakdown-table">
          <table className="table">
            <thead>
              <tr>
                <th>Protocol</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Percentage</th>
              </tr>
            </thead>
            <tbody>
              {protocolStats.map((stat, index) => (
                <tr key={stat.protocol}>
                  <td>
                    <span
                      className="protocol-indicator"
                      style={{ backgroundColor: COLORS[index % COLORS.length] }}
                    ></span>
                    {stat.protocol}
                  </td>
                  <td>{stat.count.toLocaleString()}</td>
                  <td>{formatBytes(stat.bytes)}</td>
                  <td>
                    <div className="percentage-bar">
                      <div
                        className="percentage-fill"
                        style={{
                          width: `${stat.percentage}%`,
                          backgroundColor: COLORS[index % COLORS.length],
                        }}
                      ></div>
                      <span className="percentage-text">{stat.percentage.toFixed(1)}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
