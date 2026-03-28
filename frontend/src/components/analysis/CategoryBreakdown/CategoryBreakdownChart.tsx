import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import type { CategoryStat } from '@/types';
import { getCategoryColor } from '@/utils/appColors';
import { formatBytes } from '@/utils/formatters';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';

const categoryInfoPopover = (
  <Popover id="category-info" style={{ maxWidth: '310px' }}>
    <Popover.Header>About category detection</Popover.Header>
    <Popover.Body>
      <p className="mb-2">
        Categories are assigned by <a href="https://www.ntop.org/products/deep-packet-inspection/ndpi/" target="_blank" rel="noreferrer">nDPI</a> by
        first identifying the application (e.g. YouTube → <em>Media</em>, Google → <em>Web</em>),
        then mapping it to a category.
      </p>
      <p className="mb-0">
        Because application detection uses deep packet inspection heuristics, it is
        <strong> probabilistic</strong> — binary payloads can occasionally match the wrong
        signature. A misidentified application will produce an incorrect category.
        Treat category labels as strong indicators, not definitive classifications.
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
