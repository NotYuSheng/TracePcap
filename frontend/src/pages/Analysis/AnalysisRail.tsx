import { useState } from 'react';
import { Spinner } from '@components/common/Spinner/Spinner';
import './AnalysisRail.css';

export interface RailItem {
  key: string;
  /** The full name, shown when the rail is expanded and to screen readers. */
  label: string;
  /** A short name, shown under the icon when the rail is narrow. */
  short: string;
  icon: string;
  busy?: boolean;
}

const EXPANDED_KEY = 'tracepcap.analysisRail.expanded';

function readExpanded(): boolean {
  try {
    return localStorage.getItem(EXPANDED_KEY) === '1';
  } catch {
    return false;
  }
}

/**
 * The analysis page's sections, down the left: an icon over a short name (nothing hides behind a
 * tooltip), or icon and full name when expanded. Replaces the horizontal tabs, which ran out of room.
 */
export function AnalysisRail({
  items,
  active,
  onSelect,
}: {
  items: RailItem[];
  active: string;
  onSelect: (key: string) => void;
}) {
  const [expanded, setExpanded] = useState(readExpanded);
  const toggle = () => {
    setExpanded(e => {
      try {
        localStorage.setItem(EXPANDED_KEY, e ? '0' : '1');
      } catch {
        // Not remembered: the rail still works.
      }
      return !e;
    });
  };
  return (
    <nav className={`analysis-rail${expanded ? ' analysis-rail-expanded' : ''}`} aria-label="Analysis sections">
      <ul className="analysis-rail-list">
        {items.map(i => (
          <li key={i.key}>
            <button
              type="button"
              className={`analysis-rail-item${active === i.key ? ' active' : ''}`}
              aria-current={active === i.key ? 'page' : undefined}
              aria-label={expanded ? undefined : i.label}
              onClick={() => onSelect(i.key)}
            >
              <span className="analysis-rail-icon" aria-hidden="true">
                <i className={`bi ${i.icon}`} />
                {i.busy && <Spinner animation="border" size="sm" className="analysis-rail-busy" />}
              </span>
              <span className="analysis-rail-label" aria-hidden={expanded ? undefined : true}>
                {expanded ? i.label : i.short}
              </span>
            </button>
          </li>
        ))}
      </ul>
      <button
        type="button"
        className="analysis-rail-toggle"
        onClick={toggle}
        aria-expanded={expanded}
        aria-label={expanded ? 'Narrow the menu' : 'Widen the menu'}
      >
        <i className={`bi ${expanded ? 'bi-chevron-double-left' : 'bi-chevron-double-right'}`} aria-hidden="true" />
      </button>
    </nav>
  );
}
