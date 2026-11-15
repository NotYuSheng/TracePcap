import { formatBytes } from '@/utils/formatters';

export interface MixRow {
  name: string;
  packets: number;
  bytes: number;
  percentage: number;
  color: string;
}

/** A stacked bar over its table: what a capture's traffic is made of, by share of packets. */
export function MixBar({
  title,
  column,
  rows,
  onPick,
}: {
  title: string;
  column: string;
  rows: MixRow[];
  onPick?: (name: string) => void;
}) {
  return (
    <div className="ov-mix">
      <h3 className="ov-mix-title">{title}</h3>
      <div
        className="ov-mix-bar"
        role="img"
        aria-label={rows.map(r => `${r.name} ${r.percentage.toFixed(1)}%`).join(', ')}
      >
        {rows.map(r => (
          <span key={r.name} style={{ width: `${r.percentage}%`, background: r.color }} />
        ))}
      </div>
      <table className="ov-mix-table">
        <thead>
          <tr>
            <th scope="col">{column}</th>
            <th scope="col">Packets</th>
            <th scope="col">Bytes</th>
            <th scope="col">Share</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(r => (
            <tr key={r.name}>
              <td>
                <span className="ov-swatch" style={{ background: r.color }} aria-hidden="true" />
                {onPick ? (
                  <button
                    type="button"
                    className="btn btn-link p-0 align-baseline ov-mix-name"
                    onClick={() => onPick(r.name)}
                  >
                    {r.name}
                  </button>
                ) : (
                  r.name
                )}
              </td>
              <td>{r.packets.toLocaleString()}</td>
              <td>{formatBytes(r.bytes)}</td>
              <td className="fw-semibold">{r.percentage.toFixed(1)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
