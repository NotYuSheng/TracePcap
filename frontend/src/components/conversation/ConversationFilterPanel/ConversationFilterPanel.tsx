import React, { useState, useEffect, useRef } from 'react';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import type { ConversationFilters } from '@/features/conversation/types';
import { COLUMN_DEFS } from '@/features/conversation/constants';
import type { ColumnKey } from '@/features/conversation/constants';
import {
  getAppColor,
  getCategoryColor,
  getL7ProtocolColor,
  getTextColor,
  getSeverityColor,
  RISK_BADGE,
} from '@/utils/appColors';
import { getProtocolColor } from '@/features/network/constants';
import './ConversationFilterPanel.css';

interface ProtocolStat {
  protocol: string;
  count: number;
}
interface AppStat {
  name: string;
}
interface CategoryStat {
  category: string;
}

interface ConversationFilterPanelProps {
  filters: ConversationFilters;
  onFiltersChange: (update: Partial<ConversationFilters>) => void;
  onClearAll: () => void;
  protocols: ProtocolStat[];
  l7Protocols: string[];
  apps: AppStat[];
  categories: CategoryStat[];
  fileTypes: string[];
  riskTypes: string[];
  customSignatureOptions: string[];
  signatureSeverities?: Record<string, string>;
  activeFilterCount: number;
  visibleColumns: Set<ColumnKey>;
  onToggleColumn: (key: ColumnKey) => void;
}

function InfoPopover({ id, title, body }: { id: string; title: string; body: React.ReactNode }) {
  const popover = (
    <Popover id={id} style={{ maxWidth: '280px' }}>
      <Popover.Header>{title}</Popover.Header>
      <Popover.Body className="small">{body}</Popover.Body>
    </Popover>
  );
  return (
    <OverlayTrigger trigger="click" placement="right" overlay={popover} rootClose>
      <button
        type="button"
        className="btn btn-link p-0 text-muted ms-1"
        style={{ lineHeight: 1 }}
        aria-label={`About ${title}`}
      >
        <i className="bi bi-info-circle" style={{ fontSize: '0.8rem' }}></i>
      </button>
    </OverlayTrigger>
  );
}

function PillSectionHeader({
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

export function ConversationFilterPanel({
  filters,
  onFiltersChange,
  onClearAll,
  protocols,
  l7Protocols,
  apps,
  categories,
  fileTypes,
  riskTypes,
  customSignatureOptions,
  signatureSeverities = {},
  activeFilterCount,
  visibleColumns,
  onToggleColumn,
}: ConversationFilterPanelProps) {
  const [isOpen, setIsOpen] = useState(activeFilterCount > 0);
  const [ipInput, setIpInput] = useState(filters.ip);
  const [portInput, setPortInput] = useState(filters.port);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const portDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setIpInput(filters.ip);
  }, [filters.ip]);
  useEffect(() => {
    setPortInput(filters.port);
  }, [filters.port]);

  const handleIpChange = (value: string) => {
    setIpInput(value);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => onFiltersChange({ ip: value }), 300);
  };

  const handlePortChange = (value: string) => {
    if (value && !/^\d+$/.test(value)) return; // digits only
    setPortInput(value);
    if (portDebounceRef.current) clearTimeout(portDebounceRef.current);
    portDebounceRef.current = setTimeout(() => onFiltersChange({ port: value }), 300);
  };

  const toggle = <K extends keyof ConversationFilters>(
    key: K,
    value: string,
    current: string[]
  ) => {
    const next = current.includes(value) ? current.filter(v => v !== value) : [...current, value];
    onFiltersChange({ [key]: next } as Partial<ConversationFilters>);
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
                <label className="filter-section-label d-inline-flex align-items-center mb-2">
                  IP / Hostname
                  <InfoPopover
                    id="info-ip"
                    title="IP / Hostname filter"
                    body="Matches conversations where the source IP, destination IP, or hostname contains this text (case-insensitive)."
                  />
                </label>
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

              {/* Port */}
              <div className="col-md-2">
                <label className="filter-section-label d-inline-flex align-items-center mb-2">
                  Port
                  <InfoPopover
                    id="info-port"
                    title="Port filter"
                    body="Filters to conversations where either the source or destination port exactly matches the entered number."
                  />
                </label>
                <div className="input-group input-group-sm">
                  <input
                    type="text"
                    inputMode="numeric"
                    className="form-control"
                    placeholder="e.g. 443"
                    value={portInput}
                    onChange={e => handlePortChange(e.target.value)}
                  />
                  {portInput && (
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      onClick={() => handlePortChange('')}
                    >
                      ×
                    </button>
                  )}
                </div>
              </div>

              {/* Security risks toggle */}
              <div className="col-md-2 d-flex align-items-end">
                <div className="form-check mb-0">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="hasRisksCheck"
                    checked={filters.hasRisks}
                    onChange={e => onFiltersChange({ hasRisks: e.target.checked })}
                  />
                  <label
                    className="form-check-label small d-inline-flex align-items-center"
                    htmlFor="hasRisksCheck"
                  >
                    Security risks only
                    <InfoPopover
                      id="info-risks"
                      title="Security risks"
                      body="Shows only conversations flagged with at least one nDPI risk indicator, such as unsafe protocols, clear-text credentials, or suspicious traffic patterns."
                    />
                  </label>
                </div>
              </div>

              {/* Protocol pills */}
              {protocols.length > 0 && (
                <div className="col-12">
                  <PillSectionHeader
                    label="L4 Protocol"
                    info={
                      <InfoPopover
                        id="info-protocol"
                        title="L4 Protocol"
                        body="Filter by Layer 4 transport protocol (e.g. TCP, UDP, ICMP). Select multiple to show any of them."
                      />
                    }
                    onSelectAll={() =>
                      onFiltersChange({ protocols: protocols.map(p => p.protocol) })
                    }
                    onDeselectAll={() => onFiltersChange({ protocols: [] })}
                  />
                  <div className="d-flex flex-wrap gap-1">
                    {protocols.map(({ protocol }) => {
                      const isActive = filters.protocols.includes(protocol);
                      const bg = getProtocolColor(protocol);
                      return (
                        <button
                          key={protocol}
                          type="button"
                          className={`badge rounded-pill border-0 filter-pill ${isActive ? 'active' : ''}`}
                          style={
                            isActive ? { backgroundColor: bg, color: getTextColor(bg) } : undefined
                          }
                          onClick={() => toggle('protocols', protocol, filters.protocols)}
                        >
                          {protocol}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* L7 Protocol pills */}
              {l7Protocols.length > 0 && (
                <div className="col-12">
                  <PillSectionHeader
                    label="L7 Protocol"
                    info={
                      <InfoPopover
                        id="info-l7protocol"
                        title="L7 Protocol"
                        body="Layer 7 application-layer protocol identified by Wireshark's deterministic dissectors (e.g. TLS, HTTP, DNS, QUIC). Select multiple to show any of them."
                      />
                    }
                    onSelectAll={() => onFiltersChange({ l7Protocols })}
                    onDeselectAll={() => onFiltersChange({ l7Protocols: [] })}
                  />
                  <div className="d-flex flex-wrap gap-1">
                    {l7Protocols.map(proto => {
                      const isActive = filters.l7Protocols.includes(proto);
                      const bg = getL7ProtocolColor(proto);
                      return (
                        <button
                          key={proto}
                          type="button"
                          className={`badge rounded-pill border-0 filter-pill ${isActive ? 'active' : ''}`}
                          style={
                            isActive ? { backgroundColor: bg, color: getTextColor(bg) } : undefined
                          }
                          onClick={() => toggle('l7Protocols', proto, filters.l7Protocols)}
                        >
                          {proto}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Application pills */}
              {apps.length > 0 && (
                <div className="col-12">
                  <PillSectionHeader
                    label="Application"
                    info={
                      <InfoPopover
                        id="info-app"
                        title="Application"
                        body={
                          <>
                            Application or service identified by <strong>nDPI</strong> deep packet
                            inspection (e.g. YouTube, WhatsApp).{' '}
                            <strong>Detection accuracy may vary</strong> — treat results as
                            indicative, not definitive.
                          </>
                        }
                      />
                    }
                    onSelectAll={() => onFiltersChange({ apps: apps.map(a => a.name) })}
                    onDeselectAll={() => onFiltersChange({ apps: [] })}
                  />
                  <div className="d-flex flex-wrap gap-1 filter-pill-scroll">
                    {apps.map(({ name }) => {
                      const isActive = filters.apps.includes(name);
                      const bg = getAppColor(name);
                      return (
                        <button
                          key={name}
                          type="button"
                          className={`badge rounded-pill border-0 filter-pill ${isActive ? 'active' : ''}`}
                          style={
                            isActive ? { backgroundColor: bg, color: getTextColor(bg) } : undefined
                          }
                          onClick={() => toggle('apps', name, filters.apps)}
                        >
                          {name}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Category pills */}
              {categories.length > 0 && (
                <div className="col-12">
                  <PillSectionHeader
                    label="Category"
                    info={
                      <InfoPopover
                        id="info-category"
                        title="Category"
                        body="Broad traffic category assigned by nDPI (e.g. Web, Media, VPN). Select multiple to show any of them."
                      />
                    }
                    onSelectAll={() =>
                      onFiltersChange({ categories: categories.map(c => c.category) })
                    }
                    onDeselectAll={() => onFiltersChange({ categories: [] })}
                  />
                  <div className="d-flex flex-wrap gap-1">
                    {categories.map(({ category }) => {
                      const isActive = filters.categories.includes(category);
                      const bg = getCategoryColor(category);
                      return (
                        <button
                          key={category}
                          type="button"
                          className={`badge rounded-pill border-0 filter-pill ${isActive ? 'active' : ''}`}
                          style={
                            isActive ? { backgroundColor: bg, color: getTextColor(bg) } : undefined
                          }
                          onClick={() => toggle('categories', category, filters.categories)}
                        >
                          {category}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* File type pills */}
              {fileTypes.length > 0 && (
                <div className="col-12">
                  <PillSectionHeader
                    label="File Types"
                    info={
                      <InfoPopover
                        id="info-filetypes"
                        title="File Types"
                        body="Shows only conversations containing at least one packet where a file signature (magic bytes) was detected in the payload — e.g. PDF, ZIP, PNG."
                      />
                    }
                    onSelectAll={() => onFiltersChange({ fileTypes })}
                    onDeselectAll={() => onFiltersChange({ fileTypes: [] })}
                  />
                  <div className="d-flex flex-wrap gap-1">
                    {fileTypes.map(ft => {
                      const isActive = filters.fileTypes.includes(ft);
                      const bg = getAppColor(ft);
                      return (
                        <button
                          key={ft}
                          type="button"
                          className={`badge rounded-pill border-0 filter-pill ${isActive ? 'active' : ''}`}
                          style={
                            isActive ? { backgroundColor: bg, color: getTextColor(bg) } : undefined
                          }
                          onClick={() => toggle('fileTypes', ft, filters.fileTypes)}
                        >
                          {ft}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Risk type pills */}
              {riskTypes.length > 0 && (
                <div className="col-12">
                  <PillSectionHeader
                    label="Risk Type"
                    info={
                      <InfoPopover
                        id="info-risktype"
                        title="Risk Type"
                        body="Filter by nDPI risk flags assigned to a conversation. Examples: clear-text credentials, unsafe protocols, known malicious signatures."
                      />
                    }
                    onSelectAll={() => onFiltersChange({ riskTypes })}
                    onDeselectAll={() => onFiltersChange({ riskTypes: [] })}
                  />
                  <div className="d-flex flex-wrap gap-1">
                    {riskTypes.map(rt => {
                      const isActive = filters.riskTypes.includes(rt);
                      return (
                        <button
                          key={rt}
                          type="button"
                          className={`badge rounded-pill border-0 filter-pill ${isActive ? 'active' : ''}`}
                          style={
                            isActive
                              ? { backgroundColor: RISK_BADGE.bg, color: RISK_BADGE.text }
                              : undefined
                          }
                          onClick={() => toggle('riskTypes', rt, filters.riskTypes)}
                        >
                          {rt.replace(/_/g, ' ')}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Custom signature rule pills */}
              {customSignatureOptions.length > 0 && (
                <div className="col-12">
                  <PillSectionHeader
                    label="Custom Rules"
                    info={
                      <InfoPopover
                        id="info-customrules"
                        title="Custom Rules"
                        body="Filter by your own custom detection rules defined in signatures.yml. Only rules that matched at least one conversation in this file are shown."
                      />
                    }
                    onSelectAll={() =>
                      onFiltersChange({ customSignatures: customSignatureOptions })
                    }
                    onDeselectAll={() => onFiltersChange({ customSignatures: [] })}
                  />
                  <div className="d-flex flex-wrap gap-1 mb-2">
                    {customSignatureOptions.map(rule => {
                      const isActive = filters.customSignatures.includes(rule);
                      const { bg, text } = getSeverityColor(signatureSeverities[rule]);
                      return (
                        <button
                          key={rule}
                          type="button"
                          className={`badge rounded-pill border-0 filter-pill ${isActive ? 'active' : ''}`}
                          style={isActive ? { backgroundColor: bg, color: text } : undefined}
                          onClick={() => toggle('customSignatures', rule, filters.customSignatures)}
                        >
                          {rule.replace(/_/g, ' ')}
                        </button>
                      );
                    })}
                  </div>
                  <div
                    className="d-flex flex-wrap gap-2 align-items-center"
                    style={{ fontSize: '0.75rem', color: '#6c757d' }}
                  >
                    <span>Severity:</span>
                    {(
                      [
                        ['critical', '#dc3545', '#fff'],
                        ['high', '#fd7e14', '#fff'],
                        ['medium', '#e67e22', '#fff'],
                        ['low', '#6f42c1', '#fff'],
                      ] as const
                    ).map(([label, bg, text]) => {
                      const rulesOfSeverity = customSignatureOptions.filter(
                        r => (signatureSeverities[r] ?? 'low').toLowerCase() === label
                      );
                      if (rulesOfSeverity.length === 0) return null;
                      const allSelected = rulesOfSeverity.every(r =>
                        filters.customSignatures.includes(r)
                      );
                      const handleClick = () => {
                        if (allSelected) {
                          onFiltersChange({
                            customSignatures: filters.customSignatures.filter(
                              r => !rulesOfSeverity.includes(r)
                            ),
                          });
                        } else {
                          const next = [
                            ...new Set([...filters.customSignatures, ...rulesOfSeverity]),
                          ];
                          onFiltersChange({ customSignatures: next });
                        }
                      };
                      return (
                        <button
                          key={label}
                          type="button"
                          className="badge border-0"
                          style={{
                            backgroundColor: allSelected ? bg : undefined,
                            color: allSelected ? text : undefined,
                            fontWeight: 400,
                            cursor: 'pointer',
                            opacity: allSelected ? 1 : 0.6,
                          }}
                          onClick={handleClick}
                          title={
                            allSelected
                              ? `Deselect all ${label} rules`
                              : `Select all ${label} rules`
                          }
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Column visibility */}
              <div className="col-12 pt-1 border-top mt-3">
                <label className="filter-section-label d-block mb-2">
                  <i className="bi bi-layout-three-columns me-1"></i>Columns
                </label>
                <div className="d-flex flex-wrap gap-2">
                  {COLUMN_DEFS.map(({ key, label }) => (
                    <div key={key} className="form-check form-check-inline mb-0">
                      <input
                        type="checkbox"
                        className="form-check-input"
                        id={`col-${key}`}
                        checked={visibleColumns.has(key)}
                        onChange={() => onToggleColumn(key)}
                      />
                      <label className="form-check-label small" htmlFor={`col-${key}`}>
                        {label}
                      </label>
                    </div>
                  ))}
                </div>
              </div>
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
