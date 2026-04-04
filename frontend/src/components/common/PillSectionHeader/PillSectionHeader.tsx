import React from 'react';

export function PillSectionHeader({
  label,
  info,
  onSelectAll,
  onDeselectAll,
}: {
  label: React.ReactNode;
  info?: React.ReactNode;
  onSelectAll: () => void;
  onDeselectAll: () => void;
}) {
  return (
    <div className="filter-section-row">
      <span className="filter-section-label d-inline-flex align-items-center">
        {label}
        {info}
      </span>
      <div className="filter-section-actions">
        <button type="button" className="filter-section-action" onClick={onSelectAll}>
          Select All
        </button>
        <span className="filter-section-action" aria-hidden>
          ·
        </span>
        <button type="button" className="filter-section-action" onClick={onDeselectAll}>
          Clear
        </button>
      </div>
    </div>
  );
}
