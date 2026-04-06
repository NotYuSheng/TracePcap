import { useRef, useCallback, useEffect } from 'react';
import './ScrollableTable.css';

interface ScrollableTableProps {
  children: React.ReactNode;
  maxHeight?: string;
}

/**
 * Shared scroll container for data tables.
 *
 * Features:
 * - Vertically scrollable with a configurable max-height
 * - Horizontally scrollable with a synced phantom scrollbar above the table
 * - Sticky column headers
 * - Middle-click pan gesture
 */
export const ScrollableTable = ({ children, maxHeight = '62vh' }: ScrollableTableProps) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const topBarRef = useRef<HTMLDivElement>(null);
  const topInnerRef = useRef<HTMLDivElement>(null);
  const syncingRef = useRef(false);

  // Keep phantom scrollbar width in sync with actual table content width
  useEffect(() => {
    const scroll = scrollRef.current;
    if (!scroll) return;
    const updateWidth = () => {
      const table = scroll.querySelector('table');
      if (topInnerRef.current && table) {
        topInnerRef.current.style.width = `${table.scrollWidth}px`;
      }
    };
    updateWidth();
    const ro = new ResizeObserver(updateWidth);
    const table = scroll.querySelector('table');
    if (table) ro.observe(table);
    return () => ro.disconnect();
  }, []);

  const handleScroll = useCallback(() => {
    if (!syncingRef.current && topBarRef.current && scrollRef.current) {
      syncingRef.current = true;
      topBarRef.current.scrollLeft = scrollRef.current.scrollLeft;
      syncingRef.current = false;
    }
  }, []);

  const handleTopScroll = useCallback(() => {
    if (!syncingRef.current && scrollRef.current && topBarRef.current) {
      syncingRef.current = true;
      scrollRef.current.scrollLeft = topBarRef.current.scrollLeft;
      syncingRef.current = false;
    }
  }, []);

  // Middle-click pan
  const panActive = useRef(false);
  const panOrigin = useRef({ x: 0, y: 0 });
  const panMouse = useRef({ x: 0, y: 0 });
  const panRaf = useRef(0);
  const panDot = useRef<HTMLDivElement | null>(null);
  const panTick = useRef<() => void>(() => {});

  const stopPan = useCallback(() => {
    panActive.current = false;
    if (scrollRef.current) scrollRef.current.style.cursor = '';
    cancelAnimationFrame(panRaf.current);
    panDot.current?.remove();
    panDot.current = null;
  }, []);

  useEffect(() => {
    const DEAD = 8,
      SPD = 0.1;
    panTick.current = () => {
      if (!panActive.current) return;
      const dx = panMouse.current.x - panOrigin.current.x;
      const dy = panMouse.current.y - panOrigin.current.y;
      if (scrollRef.current && Math.abs(dx) > DEAD) scrollRef.current.scrollLeft += dx * SPD;
      if (scrollRef.current && Math.abs(dy) > DEAD) scrollRef.current.scrollTop += dy * SPD;
      panRaf.current = requestAnimationFrame(panTick.current);
    };
    const onMove = (e: MouseEvent) => {
      panMouse.current = { x: e.clientX, y: e.clientY };
    };
    const onClick = (e: MouseEvent) => {
      if (panActive.current && e.button !== 1) stopPan();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') stopPan();
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mousedown', onClick);
    window.addEventListener('keydown', onKey);
    return () => {
      stopPan();
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mousedown', onClick);
      window.removeEventListener('keydown', onKey);
    };
  }, [stopPan]);

  const handleMiddleDown = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.button !== 1) return;
      e.preventDefault();
      if (panActive.current) {
        stopPan();
        return;
      }
      panActive.current = true;
      panOrigin.current = { x: e.clientX, y: e.clientY };
      panMouse.current = { x: e.clientX, y: e.clientY };
      if (scrollRef.current) scrollRef.current.style.cursor = 'all-scroll';
      const dot = document.createElement('div');
      dot.className = 'sct-pan-dot';
      dot.style.left = `${e.clientX}px`;
      dot.style.top = `${e.clientY}px`;
      document.body.appendChild(dot);
      panDot.current = dot;
      panRaf.current = requestAnimationFrame(panTick.current);
    },
    [stopPan]
  );

  return (
    <div>
      <div ref={topBarRef} className="sct-top-scrollbar" onScroll={handleTopScroll}>
        <div ref={topInnerRef} className="sct-top-scrollbar-inner" />
      </div>
      <div
        ref={scrollRef}
        className="sct-scroll"
        style={{ maxHeight }}
        onScroll={handleScroll}
        onMouseDown={handleMiddleDown}
      >
        {children}
      </div>
    </div>
  );
};
