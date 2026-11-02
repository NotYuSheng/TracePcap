import { useMemo, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import type { ProtocolStats } from '@/types';
import { Button, OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import { Pagination } from '@components/common/Pagination/Pagination';
import './ProtocolBreakdownChart.css';
import { formatBytes } from '@/utils/formatters';
import { MAX_PIE_PROTOCOLS, OTHER_SLICE, toPieSlices } from './protocolPie';

const TABLE_PAGE_SIZE = 10;

interface ProtocolBreakdownChartProps {
  protocolStats: ProtocolStats[];
}

const protocolInfoPopover = (
  <Popover id="protocol-info" style={{ maxWidth: '300px' }}>
    <Popover.Header>Protocol distribution</Popover.Header>
    <Popover.Body>
      <p className="mb-0">
        Shows the breakdown of protocols read directly from the IP header's Protocol field — no
        heuristics involved. The counts accurately reflect what is declared in each packet's header.
        Note that tunnelled traffic (e.g. GRE, VXLAN, IP-in-IP) will appear as its outer protocol,
        not the encapsulated inner protocol.
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
  const [page, setPage] = useState(1);

  const sortedStats = useMemo(
    () => [...protocolStats].sort((a, b) => b.count - a.count),
    [protocolStats]
  );
  const chartData = useMemo(() => toPieSlices(sortedStats), [sortedStats]);
  const sliceColors = useMemo(
    () => new Map(chartData.map((slice, index) => [slice.name, COLORS[index % COLORS.length]])),
    [chartData]
  );
  const colorOf = (protocol: string) =>
    sliceColors.get(protocol) ?? sliceColors.get(OTHER_SLICE) ?? COLORS[MAX_PIE_PROTOCOLS];

  const totalPages = Math.ceil(sortedStats.length / TABLE_PAGE_SIZE);
  const currentPage = Math.min(page, Math.max(1, totalPages));
  const pageStats = sortedStats.slice(
    (currentPage - 1) * TABLE_PAGE_SIZE,
    currentPage * TABLE_PAGE_SIZE
  );

  // Legend rows depend on number of items; each row ≈ 24 px, ~3 items per row at typical widths.
  const chartHeight = Math.max(300, 280 + Math.ceil(chartData.length / 3) * 24);

  return (
    <div className="protocol-breakdown">
      <h3 className="breakdown-title d-flex align-items-center gap-2">
        Protocol Distribution
        <OverlayTrigger trigger="click" placement="right" overlay={protocolInfoPopover} rootClose>
          <Button
            type="button"
            variant="link"
            className="p-0 text-muted"
            style={{ lineHeight: 1 }}
            aria-label="About protocol detection accuracy"
          >
            <i className="bi bi-info-circle fs-6"></i>
          </Button>
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
                {chartData.map(slice => (
                  <Cell key={slice.name} fill={colorOf(slice.name)} />
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
              {pageStats.map(stat => (
                <tr key={stat.protocol}>
                  <td>
                    <span
                      className="protocol-indicator"
                      style={{ backgroundColor: colorOf(stat.protocol) }}
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
                          backgroundColor: colorOf(stat.protocol),
                        }}
                      ></div>
                      <span className="percentage-text">{stat.percentage.toFixed(1)}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {totalPages > 1 && (
            <Pagination
              currentPage={currentPage}
              totalPages={totalPages}
              totalItems={sortedStats.length}
              pageSize={TABLE_PAGE_SIZE}
              onPageChange={setPage}
              showPageSizeSelector={false}
              compact
            />
          )}
        </div>
      </div>
    </div>
  );
};
