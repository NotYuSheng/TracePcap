import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import type { CategoryStat } from '@/types';
import { getCategoryColor } from '@/utils/appColors';
import { formatBytes } from '@/utils/formatters';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';

const categoryInfoPopover = (
  <Popover id="category-info" style={{ maxWidth: '300px' }}>
    <Popover.Header>About category detection</Popover.Header>
    <Popover.Body>
      <p className="mb-0">
        Categories are assigned by <strong>nDPI</strong> based on its application detection
        (e.g. YouTube → Media, Google → Web). They inherit the same probabilistic limitations —
        a misidentified application will produce an incorrect category. Treat as indicative,
        not definitive.
      </p>
    </Popover.Body>
  </Popover>
);

interface CategoryBreakdownChartProps {
  categoryStats: CategoryStat[];
}

export const CategoryBreakdownChart = ({ categoryStats }: CategoryBreakdownChartProps) => {
  const chartData = categoryStats.map(stat => ({
    name: stat.category,
    value: stat.count,
    percentage: stat.percentage,
    color: getCategoryColor(stat.category),
  }));

  return (
    <div className="protocol-breakdown">
      <h3 className="breakdown-title d-flex align-items-center gap-2">
        Category Distribution
        <OverlayTrigger trigger="click" placement="right" overlay={categoryInfoPopover} rootClose>
          <button
            type="button"
            className="btn btn-link p-0 text-muted"
            style={{ lineHeight: 1 }}
            aria-label="About category detection accuracy"
          >
            <i className="bi bi-info-circle fs-6"></i>
          </button>
        </OverlayTrigger>
      </h3>

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
                {chartData.map((item, index) => (
                  <Cell key={`cell-${index}`} fill={item.color} />
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
                <th>Category</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Percentage</th>
              </tr>
            </thead>
            <tbody>
              {categoryStats.map(stat => (
                <tr key={stat.category}>
                  <td>
                    <span
                      className="protocol-indicator"
                      style={{ backgroundColor: getCategoryColor(stat.category) }}
                    ></span>
                    {stat.category}
                  </td>
                  <td>{stat.count.toLocaleString()}</td>
                  <td>{formatBytes(stat.bytes)}</td>
                  <td>
                    <div className="percentage-bar">
                      <div
                        className="percentage-fill"
                        style={{
                          width: `${stat.percentage}%`,
                          backgroundColor: getCategoryColor(stat.category),
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
