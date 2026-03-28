import { useState, useEffect, useRef } from 'react';
import type { ConversationFilters } from '@/features/conversation/types';
import '../../conversation/ConversationFilterPanel/ConversationFilterPanel.css';

interface ProtocolStat {
  protocol: string;
  count: number;
}

interface SecurityFilterPanelProps {
  filters: ConversationFilters;
  onFiltersChange: (update: Partial<ConversationFilters>) => void;
  onClearAll: () => void;
  protocols: ProtocolStat[];
  riskTypes: string[];
  activeFilterCount: number;
}

function formatRiskLabel(risk: string): string {
  return risk.replace(/_/g, ' ');
}

export function SecurityFilterPanel({
  filters,
  onFiltersChange,
  onClearAll,
  protocols,
  riskTypes,
  activeFilterCount,
}: SecurityFilterPanelProps) {
  const [isOpen, setIsOpen] = useState(activeFilterCount > 0);
  const [ipInput, setIpInput] = useState(filters.ip);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setIpInput(filters.ip);
  }, [filters.ip]);

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

  const toggleRiskType = (rt: string) => {
    const next = filters.riskTypes.includes(rt)
      ? filters.riskTypes.filter(r => r !== rt)
      : [...filters.riskTypes, rt];
    onFiltersChange({ riskTypes: next });
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
                  <span className="input-group-text">
                    <i className="bi bi-search"></i>
                  </span>
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
                    >
                      ×
                    </button>
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

              {/* Risk type pills */}
              {riskTypes.length > 0 && (
                <div className="col-12">
                  <label className="form-label filter-section-label">
                    <i className="bi bi-shield-exclamation me-1"></i>Risk Type
                  </label>
                  <div className="d-flex flex-wrap gap-1">
                    {riskTypes.map(rt => (
                      <button
                        key={rt}
                        type="button"
                        className={`badge rounded-pill border-0 filter-pill ${filters.riskTypes.includes(rt) ? 'active' : ''}`}
                        onClick={() => toggleRiskType(rt)}
                      >
                        {formatRiskLabel(rt)}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {activeFilterCount > 0 && (
              <div className="mt-3 pt-2 border-top">
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary"
                  onClick={onClearAll}
                >
                  <i className="bi bi-x-circle me-1"></i>Clear filters
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
