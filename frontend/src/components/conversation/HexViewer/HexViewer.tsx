import { useRef, useEffect, useState, useCallback } from 'react';
import './HexViewer.css';

const MIN_BYTES_PER_ROW = 8;
const ALIGN_TO = 8; // snap to multiples of 8 so the mid-group split is always even

interface HexViewerProps {
  hex: string;
  truncated: boolean;
}

export const HexViewer = ({ hex, truncated }: HexViewerProps) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const rulerRef = useRef<HTMLSpanElement>(null);
  const [bytesPerRow, setBytesPerRow] = useState(16);

  const compute = useCallback(() => {
    const container = containerRef.current;
    const ruler = rulerRef.current;
    if (!container || !ruler) return;

    const rulerWidth = ruler.getBoundingClientRect().width;
    if (rulerWidth === 0) return;

    // Ruler renders "XX " — exactly 3 monospace chars at the pre's font size
    const charWidth = rulerWidth / 3;
    const containerWidth = container.clientWidth;

    // Line layout: 4 (offset) + 2 (gap) + N*3 (hex) + 2 (gap) + N (ascii) = 8 + N*4
    const available = Math.floor(containerWidth / charWidth);
    let n = Math.floor((available - 8) / 4);
    n = Math.max(MIN_BYTES_PER_ROW, Math.floor(n / ALIGN_TO) * ALIGN_TO);
    setBytesPerRow(n);
  }, []);

  useEffect(() => {
    compute();
    const ro = new ResizeObserver(compute);
    if (containerRef.current) ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, [compute]);

  if (!hex) {
    return <p className="text-muted small mb-0">No payload data available.</p>;
  }

  const bytes: string[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(hex.slice(i, i + 2));
  }

  const rows: string[][] = [];
  for (let i = 0; i < bytes.length; i += bytesPerRow) {
    rows.push(bytes.slice(i, i + bytesPerRow));
  }

  const half = bytesPerRow / 2;

  return (
    <div className="hex-viewer p-2" ref={containerRef}>
      {/* Invisible ruler — measures the exact monospace char width at this font size */}
      <span ref={rulerRef} className="hex-ruler" aria-hidden>
        XX{' '}
      </span>
      <pre>
        {rows.map((row, rowIdx) => {
          const offset = (rowIdx * bytesPerRow).toString(16).padStart(4, '0');
          const left = row.slice(0, half).join(' ');
          const right = row.slice(half).join(' ');
          const hexStr = right ? `${left}  ${right}` : left;
          const padded = hexStr.padEnd(bytesPerRow * 3, ' ');

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
