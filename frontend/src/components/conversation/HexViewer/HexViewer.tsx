import './HexViewer.css';

const BYTES_PER_ROW = 16;

interface HexViewerProps {
  hex: string;
  truncated: boolean;
}

export const HexViewer = ({ hex, truncated }: HexViewerProps) => {
  if (!hex) {
    return <p className="text-muted small mb-0">No payload data available.</p>;
  }

  const bytes: string[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(hex.slice(i, i + 2));
  }

  const rows: string[][] = [];
  for (let i = 0; i < bytes.length; i += BYTES_PER_ROW) {
    rows.push(bytes.slice(i, i + BYTES_PER_ROW));
  }

  return (
    <div className="hex-viewer p-2">
      <pre>
        {rows.map((row, rowIdx) => {
          const offset = (rowIdx * BYTES_PER_ROW).toString(16).padStart(4, '0');
          const left  = row.slice(0, 8).join(' ');
          const right = row.slice(8).join(' ');
          const hex16 = right ? `${left}  ${right}` : left;
          const padded = hex16.padEnd(BYTES_PER_ROW * 3, ' ');

          const ascii = row
            .map(b => {
              const code = parseInt(b, 16);
              return code >= 0x20 && code <= 0x7e ? String.fromCharCode(code) : '.';
            })
            .join('');

          return (
            <span key={rowIdx}>
              <span className="hex-offset">{offset}</span>
              {'  '}
              <span className="hex-bytes">{padded}</span>
              {'  '}
              <span className="hex-ascii">{ascii}</span>
              {'\n'}
            </span>
          );
        })}
      </pre>
      {truncated && (
        <p className="mb-0 mt-1 small hex-truncated">— truncated to first 1024 bytes —</p>
      )}
    </div>
  );
};
