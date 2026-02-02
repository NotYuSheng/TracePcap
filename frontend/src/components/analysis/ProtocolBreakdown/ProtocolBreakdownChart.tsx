import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import type { ProtocolStats } from '@/types';
import './ProtocolBreakdownChart.css';

interface ProtocolBreakdownChartProps {
  protocolStats: ProtocolStats[];
}

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

  return (
    <div className="protocol-breakdown">
      <h3 className="breakdown-title">Protocol Distribution</h3>

      <div className="breakdown-content">
        <div className="breakdown-chart">
          <ResponsiveContainer width="100%" height={300}>
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
