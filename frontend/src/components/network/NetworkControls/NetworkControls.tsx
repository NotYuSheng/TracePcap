import { useState, useEffect, useRef, type ReactNode } from 'react';
import {
  PROTOCOL_COLORS,
  PROTOCOL_LABELS,
  NODE_TYPE_COLORS,
  NODE_TYPE_LABELS,
  DEFAULT_EDGE_COLOR,
} from '@/features/network/constants';
import { DEVICE_TYPES, deviceTypeLabel, deviceTypeColor } from '@/utils/deviceType';
import {
  getAppColor,
  getL7ProtocolColor,
  getCategoryColor,
  getTextColor,
  RISK_BADGE,
} from '@/utils/appColors';
import { PillSectionHeader } from '@components/common/PillSectionHeader/PillSectionHeader';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import './NetworkControls.css';

function InfoPopover({ id, title, body }: { id: string; title: string; body: ReactNode }) {
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

interface NetworkControlsProps {
  activeLegendProtocols: string[];
  onLegendProtocolClick: (key: string) => void;
  onLegendProtocolClear: () => void;
  presentEdgeLegendKeys: Set<string>;
  activeNodeFilters: string[];
  onNodeFilterClick: (key: string) => void;
  onNodeFilterClear: () => void;
  presentNodeTypes: Set<string>;
  presentDeviceTypes: Set<string>;
  ipFilter: string;
  onIpFilterChange: (value: string) => void;
  portFilter: string;
  onPortFilterChange: (value: string) => void;
  activeAppFilters: string[];
  onAppFilterClick: (app: string) => void;
  onAppFilterClear: () => void;
  presentAppNames: string[];
  activeL7Protocols: string[];
  onL7ProtocolClick: (proto: string) => void;
  onL7ProtocolClear: () => void;
  presentL7Protocols: string[];
  activeCategories: string[];
  onCategoryClick: (cat: string) => void;
  onCategoryClear: () => void;
  presentCategories: string[];
  activeRiskTypes: string[];
  onRiskTypeClick: (risk: string) => void;
  onRiskTypeClear: () => void;
  presentRiskTypes: string[];
  activeCustomSigs: string[];
  onCustomSigClick: (sig: string) => void;
  onCustomSigClear: () => void;
  presentCustomSigs: string[];
  activeFileTypes: string[];
  onFileTypeClick: (ft: string) => void;
  onFileTypeClear: () => void;
  presentFileTypes: string[];
  activeCountries: string[];
  onCountryClick: (code: string) => void;
  onCountryClear: () => void;
  presentCountries: string[];
  hasRisksOnly: boolean;
  onHasRisksOnlyChange: (val: boolean) => void;
  activeFilterCount: number;
  onClearAllFilters: () => void;
}

function edgeLegendLabel(key: string): string {
  return PROTOCOL_LABELS[key] ?? key;
}
function edgeLegendColor(key: string): string {
  return PROTOCOL_COLORS[key] ?? DEFAULT_EDGE_COLOR;
}
function nodeLegendLabel(key: string): string {
  return NODE_TYPE_LABELS[key] ?? key.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
function nodeLegendColor(key: string): string {
  return NODE_TYPE_COLORS[key] ?? '#95a5a6';
}
function countryFlag(code: string): string {
  return code
    .toUpperCase()
    .split('')
    .map(c => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join('');
}

export function NetworkControls({
  activeLegendProtocols,
  onLegendProtocolClick,
  onLegendProtocolClear,
  presentEdgeLegendKeys,
  activeNodeFilters,
  onNodeFilterClick,
  onNodeFilterClear,
  presentNodeTypes,
  presentDeviceTypes,
  ipFilter,
  onIpFilterChange,
  portFilter,
  onPortFilterChange,
  activeAppFilters,
  onAppFilterClick,
  onAppFilterClear,
  presentAppNames,
  activeL7Protocols,
  onL7ProtocolClick,
  onL7ProtocolClear,
  presentL7Protocols,
  activeCategories,
  onCategoryClick,
  onCategoryClear,
  presentCategories,
  activeRiskTypes,
  onRiskTypeClick,
  onRiskTypeClear,
  presentRiskTypes,
  activeCustomSigs,
  onCustomSigClick,
  onCustomSigClear,
  presentCustomSigs,
  activeFileTypes,
  onFileTypeClick,
  onFileTypeClear,
  presentFileTypes,
  activeCountries,
  onCountryClick,
  onCountryClear,
  presentCountries,
  hasRisksOnly,
  onHasRisksOnlyChange,
  activeFilterCount,
  onClearAllFilters,
}: NetworkControlsProps) {
  const [isOpen, setIsOpen] = useState(true);
  const [showColorInfo, setShowColorInfo] = useState(false);
  const [ipInput, setIpInput] = useState(ipFilter);
  const [portInput, setPortInput] = useState(portFilter);
  const ipDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const portDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setIpInput(ipFilter);
  }, [ipFilter]);
  useEffect(() => {
    setPortInput(portFilter);
  }, [portFilter]);

  useEffect(() => {
    return () => {
      if (ipDebounceRef.current) clearTimeout(ipDebounceRef.current);
      if (portDebounceRef.current) clearTimeout(portDebounceRef.current);
    };
  }, []);

  const handleIpChange = (value: string) => {
    setIpInput(value);
    if (ipDebounceRef.current) clearTimeout(ipDebounceRef.current);
    ipDebounceRef.current = setTimeout(() => onIpFilterChange(value), 300);
  };

  const handlePortChange = (value: string) => {
    if (value && !/^\d+$/.test(value)) return;
    setPortInput(value);
    if (portDebounceRef.current) clearTimeout(portDebounceRef.current);
    portDebounceRef.current = setTimeout(() => onPortFilterChange(value), 300);
  };

  const allNodeKeys = [
    ...Array.from(presentNodeTypes).map(k => `nt:${k}`),
    ...DEVICE_TYPES.filter(dt => presentDeviceTypes.has(dt)).map(dt => `dt:${dt}`),
  ];

  const legendPillClass = (isActive: boolean) =>
    `badge rounded-pill border-0 nc-legend-pill filter-pill${isActive ? ' active' : ''}`;

  const filterPillClass = (isActive: boolean) =>
    `badge rounded-pill border-0 filter-pill${isActive ? ' active' : ''}`;

  return (
    <>
      <div className="nc-filter-panel">
        <div className="card">
          {/* Card header — click anywhere to toggle */}
          <div
            className="card-header d-flex justify-content-between align-items-center"
            style={{ cursor: 'pointer' }}
            onClick={() => setIsOpen(o => !o)}
          >
            <div className="d-flex align-items-center gap-2">
              <strong>Filters</strong>
              {activeFilterCount > 0 && (
                <span className="badge bg-primary">{activeFilterCount}</span>
              )}
            </div>
            <div className="d-flex align-items-center gap-2">
              <button
                className="btn btn-link btn-sm p-0 text-muted"
                onClick={e => {
                  e.stopPropagation();
                  setShowColorInfo(true);
                }}
                title="How are node colours determined?"
              >
                <i className="bi bi-info-circle me-1"></i>Node colours
              </button>
              <i className={`bi ${isOpen ? 'bi-chevron-up' : 'bi-chevron-down'} text-muted`} />
            </div>
          </div>

          {/* Collapsible body */}
          {isOpen && (
            <div className="card-body p-3">
              <div className="row g-3">
                {/* IP / Hostname */}
                <div className="col-md-3">
                  <label className="filter-section-label d-block mb-2">IP / Hostname</label>
                  <div className="input-group input-group-sm">
                    <span className="input-group-text">
                      <i className="bi bi-search" />
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
                  <label className="filter-section-label d-block mb-2">Port</label>
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

                {/* Has risks */}
                <div className="col-md-2 d-flex align-items-end">
                  <div className="form-check mb-0">
                    <input
                      type="checkbox"
                      className="form-check-input"
                      id="ncHasRisks"
                      checked={hasRisksOnly}
                      onChange={e => onHasRisksOnlyChange(e.target.checked)}
                    />
                    <label className="form-check-label small" htmlFor="ncHasRisks">
                      Security risks only
                    </label>
                  </div>
                </div>

                {/* Node Types */}
                <div className="col-12">
                  <PillSectionHeader
                    label="Node Types"
                    info={
                      <InfoPopover
                        id="nc-info-nodetypes"
                        title="Node Types"
                        body="Filter by the role of each node in the network graph — e.g. Client, Server, Gateway. Roles are inferred from port usage and traffic direction."
                      />
                    }
                    onSelectAll={() =>
                      allNodeKeys.forEach(k => {
                        if (!activeNodeFilters.includes(k)) onNodeFilterClick(k);
                      })
                    }
                    onDeselectAll={onNodeFilterClear}
                  />
                  <div className="d-flex flex-wrap gap-1 mt-1">
                    {Array.from(presentNodeTypes).map(key => {
                      const fkey = `nt:${key}`;
                      const isActive = activeNodeFilters.includes(fkey);
                      const color = nodeLegendColor(key);
                      return (
                        <button
                          key={fkey}
                          type="button"
                          className={legendPillClass(isActive)}
                          style={
                            isActive
                              ? { backgroundColor: color, color: getTextColor(color) }
                              : undefined
                          }
                          onClick={() => onNodeFilterClick(fkey)}
                        >
                          <span className="nc-dot" style={{ background: color }} />
                          {nodeLegendLabel(key)}
                        </button>
                      );
                    })}
                    {DEVICE_TYPES.filter(dt => presentDeviceTypes.has(dt)).map(dt => {
                      const fkey = `dt:${dt}`;
                      const isActive = activeNodeFilters.includes(fkey);
                      const color = deviceTypeColor(dt);
                      return (
                        <button
                          key={fkey}
                          type="button"
                          className={legendPillClass(isActive)}
                          style={
                            isActive
                              ? { backgroundColor: color, color: getTextColor(color) }
                              : undefined
                          }
                          onClick={() => onNodeFilterClick(fkey)}
                        >
                          <span className="nc-dot" style={{ background: color }} />
                          {deviceTypeLabel(dt)}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Edge Protocols */}
                {presentEdgeLegendKeys.size > 0 && (
                  <div className="col-12">
                    <PillSectionHeader
                      label="Edge Protocols"
                      info={
                        <InfoPopover
                          id="nc-info-edgeprotocols"
                          title="Edge Protocols"
                          body="Filter edges (connections) by their transport protocol — TCP, UDP, or ICMP. Hiding a protocol removes all edges using it from the graph."
                        />
                      }
                      onSelectAll={() =>
                        presentEdgeLegendKeys.forEach(k => {
                          if (!activeLegendProtocols.includes(k)) onLegendProtocolClick(k);
                        })
                      }
                      onDeselectAll={onLegendProtocolClear}
                    />
                    <div className="d-flex flex-wrap gap-1 mt-1">
                      {Array.from(presentEdgeLegendKeys).map(key => {
                        const isActive = activeLegendProtocols.includes(key);
                        const color = edgeLegendColor(key);
                        return (
                          <button
                            key={key}
                            type="button"
                            className={legendPillClass(isActive)}
                            style={
                              isActive
                                ? { backgroundColor: color, color: getTextColor(color) }
                                : undefined
                            }
                            onClick={() => onLegendProtocolClick(key)}
                          >
                            <span className="nc-dot" style={{ background: color }} />
                            {edgeLegendLabel(key)}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* L7 Protocols */}
                {presentL7Protocols.length > 0 && (
                  <div className="col-12">
                    <PillSectionHeader
                      label="L7 Protocol"
                      info={
                        <InfoPopover
                          id="nc-info-l7protocol"
                          title="L7 Protocol"
                          body="Layer 7 application-layer protocol identified by Wireshark's deterministic dissectors (e.g. TLS, HTTP, DNS, QUIC). Select multiple to show any of them."
                        />
                      }
                      onSelectAll={() =>
                        presentL7Protocols.forEach(p => {
                          if (!activeL7Protocols.includes(p)) onL7ProtocolClick(p);
                        })
                      }
                      onDeselectAll={onL7ProtocolClear}
                    />
                    <div className="d-flex flex-wrap gap-1 mt-1">
                      {presentL7Protocols.map(proto => {
                        const isActive = activeL7Protocols.includes(proto);
                        const bg = getL7ProtocolColor(proto);
                        return (
                          <button
                            key={proto}
                            type="button"
                            className={filterPillClass(isActive)}
                            style={
                              isActive
                                ? { backgroundColor: bg, color: getTextColor(bg) }
                                : undefined
                            }
                            onClick={() => onL7ProtocolClick(proto)}
                          >
                            {proto}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Applications */}
                {presentAppNames.length > 0 && (
                  <div className="col-12">
                    <PillSectionHeader
                      label="Applications"
                      info={
                        <InfoPopover
                          id="nc-info-app"
                          title="Application"
                          body={
                            <>
                              Application or service identified by <strong>nDPI</strong> deep packet
                              inspection (e.g. YouTube, WhatsApp).{' '}
                              <strong>Detection accuracy may vary</strong> — treat results as
                              indicative, not definitive.
                              <br />
                              <a
                                href="/ndpi-reference.html"
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                View protocol reference →
                              </a>
                            </>
                          }
                        />
                      }
                      onSelectAll={() =>
                        presentAppNames.forEach(a => {
                          if (!activeAppFilters.includes(a)) onAppFilterClick(a);
                        })
                      }
                      onDeselectAll={onAppFilterClear}
                    />
                    <div className="d-flex flex-wrap gap-1 mt-1 filter-pill-scroll">
                      {presentAppNames.map(app => {
                        const isActive = activeAppFilters.includes(app);
                        const bg = getAppColor(app);
                        return (
                          <button
                            key={app}
                            type="button"
                            className={filterPillClass(isActive)}
                            style={
                              isActive
                                ? { backgroundColor: bg, color: getTextColor(bg) }
                                : undefined
                            }
                            onClick={() => onAppFilterClick(app)}
                          >
                            {app}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Categories */}
                {presentCategories.length > 0 && (
                  <div className="col-12">
                    <PillSectionHeader
                      label="Category"
                      info={
                        <InfoPopover
                          id="nc-info-cat"
                          title="Category"
                          body={
                            <>
                              Broad traffic category assigned by <strong>nDPI</strong> (e.g. Web,
                              Media, VPN). Select multiple to show any of them.
                              <br />
                              <a
                                href="/ndpi-reference.html"
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                View protocol reference →
                              </a>
                            </>
                          }
                        />
                      }
                      onSelectAll={() =>
                        presentCategories.forEach(c => {
                          if (!activeCategories.includes(c)) onCategoryClick(c);
                        })
                      }
                      onDeselectAll={onCategoryClear}
                    />
                    <div className="d-flex flex-wrap gap-1 mt-1">
                      {presentCategories.map(cat => {
                        const isActive = activeCategories.includes(cat);
                        const bg = getCategoryColor(cat);
                        return (
                          <button
                            key={cat}
                            type="button"
                            className={filterPillClass(isActive)}
                            style={
                              isActive
                                ? { backgroundColor: bg, color: getTextColor(bg) }
                                : undefined
                            }
                            onClick={() => onCategoryClick(cat)}
                          >
                            {cat}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Risk Types */}
                {presentRiskTypes.length > 0 && (
                  <div className="col-12">
                    <PillSectionHeader
                      label="Risk Type"
                      info={
                        <InfoPopover
                          id="nc-info-risk"
                          title="Risk Type"
                          body={
                            <>
                              Filter by <strong>nDPI</strong> risk flags assigned to a
                              conversation. Examples: clear-text credentials, unsafe protocols,
                              known malicious signatures.
                              <br />
                              <a
                                href="/ndpi-reference.html"
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                View protocol reference →
                              </a>
                            </>
                          }
                        />
                      }
                      onSelectAll={() =>
                        presentRiskTypes.forEach(r => {
                          if (!activeRiskTypes.includes(r)) onRiskTypeClick(r);
                        })
                      }
                      onDeselectAll={onRiskTypeClear}
                    />
                    <div className="d-flex flex-wrap gap-1 mt-1">
                      {presentRiskTypes.map(risk => {
                        const isActive = activeRiskTypes.includes(risk);
                        return (
                          <button
                            key={risk}
                            type="button"
                            className={filterPillClass(isActive)}
                            style={
                              isActive
                                ? { backgroundColor: RISK_BADGE.bg, color: RISK_BADGE.text }
                                : undefined
                            }
                            onClick={() => onRiskTypeClick(risk)}
                          >
                            {risk.replace(/_/g, ' ')}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Custom Signatures */}
                {presentCustomSigs.length > 0 && (
                  <div className="col-12">
                    <PillSectionHeader
                      label="Custom Rules"
                      info={
                        <InfoPopover
                          id="nc-info-customrules"
                          title="Custom Rules"
                          body="Filter by your own custom detection rules defined in signatures.yml. Only rules that matched at least one conversation in this file are shown."
                        />
                      }
                      onSelectAll={() =>
                        presentCustomSigs.forEach(s => {
                          if (!activeCustomSigs.includes(s)) onCustomSigClick(s);
                        })
                      }
                      onDeselectAll={onCustomSigClear}
                    />
                    <div className="d-flex flex-wrap gap-1 mt-1">
                      {presentCustomSigs.map(sig => {
                        const isActive = activeCustomSigs.includes(sig);
                        const bg = getAppColor(sig);
                        return (
                          <button
                            key={sig}
                            type="button"
                            className={filterPillClass(isActive)}
                            style={
                              isActive
                                ? { backgroundColor: bg, color: getTextColor(bg) }
                                : undefined
                            }
                            onClick={() => onCustomSigClick(sig)}
                          >
                            {sig.replace(/_/g, ' ')}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* File Types */}
                {presentFileTypes.length > 0 && (
                  <div className="col-12">
                    <PillSectionHeader
                      label="File Types"
                      info={
                        <InfoPopover
                          id="nc-info-filetypes"
                          title="File Types"
                          body="Shows only conversations containing at least one packet where a file signature (magic bytes) was detected in the payload — e.g. PDF, ZIP, PNG."
                        />
                      }
                      onSelectAll={() =>
                        presentFileTypes.forEach(f => {
                          if (!activeFileTypes.includes(f)) onFileTypeClick(f);
                        })
                      }
                      onDeselectAll={onFileTypeClear}
                    />
                    <div className="d-flex flex-wrap gap-1 mt-1">
                      {presentFileTypes.map(ft => {
                        const isActive = activeFileTypes.includes(ft);
                        const bg = getAppColor(ft);
                        return (
                          <button
                            key={ft}
                            type="button"
                            className={filterPillClass(isActive)}
                            style={
                              isActive
                                ? { backgroundColor: bg, color: getTextColor(bg) }
                                : undefined
                            }
                            onClick={() => onFileTypeClick(ft)}
                          >
                            {ft}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Countries */}
                {presentCountries.length > 0 && (
                  <div className="col-12">
                    <PillSectionHeader
                      label="Country"
                      info={
                        <InfoPopover
                          id="nc-info-country"
                          title="Country filter"
                          body="Filter by the country of external IP addresses (source or destination). Based on ip-api.com geolocation data."
                        />
                      }
                      onSelectAll={() =>
                        presentCountries.forEach(c => {
                          if (!activeCountries.includes(c)) onCountryClick(c);
                        })
                      }
                      onDeselectAll={onCountryClear}
                    />
                    <div className="d-flex flex-wrap gap-1 mt-1">
                      {presentCountries.map(code => {
                        const isActive = activeCountries.includes(code);
                        return (
                          <button
                            key={code}
                            type="button"
                            className={filterPillClass(isActive)}
                            style={
                              isActive ? { backgroundColor: '#0d6efd', color: '#fff' } : undefined
                            }
                            onClick={() => onCountryClick(code)}
                          >
                            {countryFlag(code)} {code}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

              {activeFilterCount > 0 && (
                <div className="mt-3 pt-2 border-top">
                  <button
                    type="button"
                    className="btn btn-sm btn-outline-secondary"
                    onClick={onClearAllFilters}
                  >
                    <i className="bi bi-x-circle me-1" />
                    Clear filters
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Node colour priority modal */}
      {showColorInfo && (
        <div
          className="modal fade show d-block"
          style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
          onClick={e => {
            if (e.target === e.currentTarget) setShowColorInfo(false);
          }}
        >
          <div className="modal-dialog modal-dialog-scrollable">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  <i className="bi bi-palette me-2" />
                  Node Colour Priority
                </h5>
                <button
                  type="button"
                  className="btn-close"
                  onClick={() => setShowColorInfo(false)}
                />
              </div>
              <div className="modal-body">
                <p className="text-muted small mb-3">
                  Each node's colour is determined by the first rule that matches, in order of
                  priority:
                </p>
                <ol className="ps-3" style={{ lineHeight: '2' }}>
                  <li>
                    <span
                      className="badge me-2"
                      style={{ backgroundColor: NODE_TYPE_COLORS['anomaly'], color: '#fff' }}
                    >
                      Anomaly
                    </span>
                    <strong>Anomaly detected</strong> — always shown in red regardless of type.
                  </li>
                  <li>
                    <span className="badge bg-warning text-dark me-2">Specific server role</span>
                    <strong>Port-based server classification</strong> — DNS, web, SSH, FTP, mail,
                    DHCP, NTP, database, and router nodes keep their dedicated colours.
                  </li>
                  <li>
                    <span
                      className="badge me-2"
                      style={{ backgroundColor: '#8b5cf6', color: '#fff' }}
                    >
                      Device type
                    </span>
                    <strong>Device classification</strong> — Mobile, Laptop/Desktop, IoT, etc.
                  </li>
                  <li>
                    <span
                      className="badge me-2"
                      style={{ backgroundColor: NODE_TYPE_COLORS['client'], color: '#fff' }}
                    >
                      Client
                    </span>
                    <strong>Generic node type</strong> — port-based classification colour.
                  </li>
                  <li>
                    <span className="badge bg-secondary me-2">Role fallback</span>
                    <strong>Traffic role</strong> — green for server, purple for both, grey
                    otherwise.
                  </li>
                </ol>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
