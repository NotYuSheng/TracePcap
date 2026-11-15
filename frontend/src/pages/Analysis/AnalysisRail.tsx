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
  /** A count to flag on the icon, e.g. changes to review. */
  badge?: number;
  /** Starts a group: a divider and this label go above the item. */
  group?: string;
}

const DEFAULT_EXPANDED_KEY = 'tracepcap.analysisRail.expanded';

function readExpanded(key: string): boolean {
  try {
    return localStorage.getItem(key) === '1';
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
  label = 'Analysis sections',
  storageKey = DEFAULT_EXPANDED_KEY,
}: {
  items: RailItem[];
  active: string;
  onSelect: (key: string) => void;
  /** The nav's accessible name. */
  label?: string;
  /** Where the widened/narrowed choice is remembered, per page. */
  storageKey?: string;
}) {
  const [expanded, setExpanded] = useState(() => readExpanded(storageKey));
  const toggle = () => {
    setExpanded(e => {
      try {
        localStorage.setItem(storageKey, e ? '0' : '1');
      } catch {
        // Not remembered: the rail still works.
      }
      return !e;
    });
  };
  return (
    <nav className={`analysis-rail${expanded ? ' analysis-rail-expanded' : ''}`} aria-label={label}>
      <ul className="analysis-rail-list">
        {items.map(i => (
          <li key={i.key}>
            {i.group && (
              <div className="analysis-rail-group">
                <span>{i.group}</span>
              </div>
            )}
            <button
              type="button"
              className={`analysis-rail-item${active === i.key ? ' active' : ''}`}
              aria-current={active === i.key ? 'page' : undefined}
              aria-label={i.badge ? `${i.label}, ${i.badge}` : expanded ? undefined : i.label}
              onClick={() => onSelect(i.key)}
            >
              <span className="analysis-rail-icon" aria-hidden="true">
                <i className={`bi ${i.icon}`} />
                {i.busy && <Spinner animation="border" size="sm" className="analysis-rail-busy" />}
                {!!i.badge && <span className="analysis-rail-badge">{i.badge}</span>}
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
