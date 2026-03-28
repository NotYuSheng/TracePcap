import { useState, useEffect, useRef } from 'react';
import type { ConversationFilters } from '@/features/conversation/types';
import { getAppColor } from '@/utils/appColors';
import './ConversationFilterPanel.css';

interface ProtocolStat  { protocol: string; count: number }
interface AppStat        { name: string }
interface CategoryStat   { category: string }

interface ConversationFilterPanelProps {
  filters:           ConversationFilters;
  onFiltersChange:   (update: Partial<ConversationFilters>) => void;
  onClearAll:        () => void;
  protocols:         ProtocolStat[];
  apps:              AppStat[];
  categories:        CategoryStat[];
  fileTypes:         string[];
  activeFilterCount: number;
}

function Chip({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="badge bg-primary d-flex align-items-center gap-1 filter-chip">
      {label}
      <button
        type="button"
        className="btn-close btn-close-white filter-chip-close"
        onClick={onRemove}
        aria-label={`Remove ${label} filter`}
      />
    </span>
  );
}

export function ConversationFilterPanel({
  filters,
  onFiltersChange,
  onClearAll,
  protocols,
  apps,
  categories,
  fileTypes,
  activeFilterCount,
}: ConversationFilterPanelProps) {
  const [isOpen, setIsOpen] = useState(activeFilterCount > 0);
  const [ipInput, setIpInput] = useState(filters.ip);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Sync ip input when filters change externally (e.g. URL navigation)
  useEffect(() => { setIpInput(filters.ip); }, [filters.ip]);

  // Auto-open if filters are active on mount
  useEffect(() => {
    if (activeFilterCount > 0) setIsOpen(true);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleIpChange = (value: string) => {
    setIpInput(value);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      onFiltersChange({ ip: value });
    }, 300);
  };

  const toggleProtocol = (proto: string) => {
    const next = filters.protocols.includes(proto)
      ? filters.protocols.filter(p => p !== proto)
      : [...filters.protocols, proto];
    onFiltersChange({ protocols: next });
  };

  const toggleApp = (app: string) => {
    const next = filters.apps.includes(app)
      ? filters.apps.filter(a => a !== app)
      : [...filters.apps, app];
    onFiltersChange({ apps: next });
  };

  const toggleCategory = (cat: string) => {
    const next = filters.categories.includes(cat)
      ? filters.categories.filter(c => c !== cat)
      : [...filters.categories, cat];
    onFiltersChange({ categories: next });
  };

  const toggleFileType = (ft: string) => {
    const next = filters.fileTypes.includes(ft)
      ? filters.fileTypes.filter(f => f !== ft)
      : [...filters.fileTypes, ft];
    onFiltersChange({ fileTypes: next });
  };

  return (
    <div className="conversation-filter-panel mb-3">
      {/* Toggle button */}
      <div className="d-flex align-items-center gap-2">
        <button
          type="button"
          className="btn btn-outline-secondary btn-sm"
          onClick={() => setIsOpen(o => !o)}
        >
          <i className="bi bi-funnel me-1"></i>
          Filters
          {activeFilterCount > 0 && (
            <span className="badge bg-primary ms-2">{activeFilterCount}</span>
          )}
          <i className={`bi ms-2 ${isOpen ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
        </button>
        {activeFilterCount > 0 && (
          <button type="button" className="btn btn-link btn-sm text-muted p-0" onClick={onClearAll}>
            Clear all
          </button>
        )}
      </div>

      {/* Collapsible panel */}
      {isOpen && (
        <div className="card mt-2 filter-panel-body">
          <div className="card-body p-3">
            <div className="row g-3">

              {/* IP / Hostname */}
              <div className="col-md-4">
                <label className="form-label filter-section-label">IP / Hostname</label>
                <div className="input-group input-group-sm">
                  <span className="input-group-text"><i className="bi bi-search"></i></span>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="e.g. 192.168.1.1"
                    value={ipInput}
                    onChange={e => handleIpChange(e.target.value)}
                  />
                  {ipInput && (
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      onClick={() => handleIpChange('')}
                    >×</button>
                  )}
                </div>
              </div>

              {/* Protocol pills */}
              {protocols.length > 0 && (
                <div className="col-md-8">
                  <label className="form-label filter-section-label">Protocol</label>
                  <div className="d-flex flex-wrap gap-1">
                    {protocols.map(({ protocol }) => (
                      <button
                        key={protocol}
                        type="button"
                        className={`badge rounded-pill border-0 filter-pill ${filters.protocols.includes(protocol) ? 'active' : ''}`}
                        onClick={() => toggleProtocol(protocol)}
                      >
                        {protocol}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Application pills */}
              {apps.length > 0 && (
                <div className="col-12">
                  <label className="form-label filter-section-label">Application</label>
                  <div className="d-flex flex-wrap gap-1 filter-pill-scroll">
                    {apps.map(({ name }) => (
                      <button
                        key={name}
                        type="button"
                        className={`badge rounded-pill border-0 filter-pill ${filters.apps.includes(name) ? 'active' : ''}`}
                        style={{
                          backgroundColor: filters.apps.includes(name)
                            ? getAppColor(name)
                            : undefined,
                        }}
                        onClick={() => toggleApp(name)}
                      >
                        {name}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Category pills */}
              {categories.length > 0 && (
                <div className="col-md-8">
                  <label className="form-label filter-section-label">Category</label>
                  <div className="d-flex flex-wrap gap-1">
                    {categories.map(({ category }) => (
                      <button
                        key={category}
                        type="button"
                        className={`badge rounded-pill border-0 filter-pill ${filters.categories.includes(category) ? 'active' : ''}`}
                        onClick={() => toggleCategory(category)}
                      >
                        {category}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* File type pills */}
              {fileTypes.length > 0 && (
                <div className="col-12">
                  <label className="form-label filter-section-label">
                    <i className="bi bi-file-earmark me-1"></i>File Types
                  </label>
                  <div className="d-flex flex-wrap gap-1">
                    {fileTypes.map(ft => (
                      <button
                        key={ft}
                        type="button"
                        className={`badge rounded-pill border-0 filter-pill ${filters.fileTypes.includes(ft) ? 'active' : ''}`}
                        onClick={() => toggleFileType(ft)}
                      >
                        {ft}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Security risks toggle */}
              <div className="col-md-4 d-flex align-items-end">
                <div className="form-check mb-0">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="hasRisksCheck"
                    checked={filters.hasRisks}
                    onChange={e => onFiltersChange({ hasRisks: e.target.checked })}
                  />
                  <label className="form-check-label small" htmlFor="hasRisksCheck">
                    <i className="bi bi-shield-exclamation text-warning me-1"></i>
                    Security risks only
                  </label>
                </div>
              </div>
            </div>

            {/* Active filter chips */}
            {activeFilterCount > 0 && (
              <div className="d-flex flex-wrap gap-1 mt-3 pt-2 border-top">
                <small className="text-muted me-1 align-self-center">Active:</small>
                {filters.ip && (
                  <Chip label={`IP: ${filters.ip}`} onRemove={() => onFiltersChange({ ip: '' })} />
                )}
                {filters.protocols.map(p => (
                  <Chip key={p} label={p} onRemove={() => toggleProtocol(p)} />
                ))}
                {filters.apps.map(a => (
                  <Chip key={a} label={a} onRemove={() => toggleApp(a)} />
                ))}
                {filters.categories.map(c => (
                  <Chip key={c} label={c} onRemove={() => toggleCategory(c)} />
                ))}
                {filters.hasRisks && (
                  <Chip label="Risks only" onRemove={() => onFiltersChange({ hasRisks: false })} />
                )}
                {filters.fileTypes.map(ft => (
                  <Chip key={ft} label={ft} onRemove={() => toggleFileType(ft)} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
