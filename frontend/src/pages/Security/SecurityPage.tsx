import { useState, useEffect, useCallback } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import type { AnalysisData, Conversation } from '@/types';
import type { SortField } from '@/features/conversation/types';
import { useConversationFilters } from '@/features/conversation/hooks/useConversationFilters';
import { conversationService } from '@/features/conversation/services/conversationService';
import { SecurityFilterPanel } from '@components/security/SecurityFilterPanel';
import { ConversationDetail } from '@components/conversation/ConversationDetail';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { Pagination } from '@components/common/Pagination';
import { formatIpPort } from '@/utils/formatters';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

const CRITICAL_RISKS = new Set([
  'clear_text_credentials',
  'suspicious_entropy',
  'suspicious_dns_traffic',
  'binary_application_transfer',
  'possible_exploit_detected',
  'xss_attack',
  'sql_injection',
  'rce_injection',
]);

/** Human-readable descriptions for known nDPI risk flags. */
const RISK_DESCRIPTIONS: Record<string, string> = {
  clear_text_credentials:       'Username/password sent without encryption — check ASCII-badged packets in the stream for credentials.',
  suspicious_entropy:           'Payload entropy suggests encryption or compression over an unexpected protocol.',
  suspicious_dns_traffic:       'Unusual DNS query patterns that may indicate tunnelling or C2 beaconing.',
  binary_application_transfer:  'Executable or binary file transferred — potential malware delivery.',
  possible_exploit_detected:    'Payload pattern matches a known exploit signature.',
  xss_attack:                   'Cross-site scripting payload detected in HTTP traffic.',
  sql_injection:                'SQL injection attempt detected in HTTP request.',
  rce_injection:                'Remote code execution payload detected.',
  self_signed_certificate:      'TLS certificate is self-signed and not issued by a trusted CA.',
  obsolete_tls_version:         'Connection uses an outdated TLS version (e.g. TLS 1.0/1.1).',
  weak_tls_cipher:              'Negotiated cipher suite is considered cryptographically weak.',
  tls_certificate_expired:      'Server certificate validity period has passed.',
  unsafe_protocol:              'Protocol known to transmit data without encryption (e.g. FTP, Telnet, HTTP).',
  known_protocol_on_non_standard_port: 'A well-known protocol is running on an unexpected port — possible evasion.',
  desktop_or_file_sharing:      'File or desktop sharing protocol detected.',
};

/** Hint shown inside the modal for risks that have packet-level indicators. */
const RISK_PACKET_HINTS: Partial<Record<string, string>> = {
  clear_text_credentials: '💡 Look for packets with the yellow ASCII badge — they likely contain the cleartext credentials.',
  unsafe_protocol:        '💡 This protocol sends data unencrypted. ASCII-badged packets may reveal transferred content.',
  xss_attack:             '💡 Open ASCII-badged packets to inspect the HTTP payload containing the XSS string.',
  sql_injection:          '💡 Open ASCII-badged packets to inspect the HTTP request containing the SQL payload.',
};

function riskBadgeClass(risk: string): string {
  return CRITICAL_RISKS.has(risk) ? 'badge bg-danger me-1' : 'badge bg-warning text-dark me-1';
}

function formatRiskLabel(risk: string): string {
  return risk.replace(/_/g, ' ');
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export const SecurityPage = () => {
  const { fileId, data } = useOutletContext<AnalysisOutletContext>();
  const navigate = useNavigate();
  const { filters, setFilters, clearAll } = useConversationFilters();

  const [alerts, setAlerts]               = useState<Conversation[]>([]);
  const [loading, setLoading]             = useState(true);
  const [error, setError]                 = useState<string | null>(null);
  const [totalItems, setTotalItems]       = useState(0);
  const [totalPages, setTotalPages]       = useState(0);
  const [riskTypeOptions, setRiskTypeOptions] = useState<string[]>([]);

  const [selectedConversation, setSelectedConversation] = useState<Conversation | null>(null);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [detailLoading, setDetailLoading] = useState(false);

  // Fetch available risk types once per file
  useEffect(() => {
    if (!fileId) return;
    conversationService.getRiskTypes(fileId).then(setRiskTypeOptions).catch(console.error);
  }, [fileId]);

  // Fetch security alerts (always hasRisks: true) whenever filters change
  useEffect(() => {
    if (!fileId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    conversationService.getConversations(fileId, { ...filters, hasRisks: true })
      .then(r => {
        if (cancelled) return;
        setAlerts(r.data);
        setTotalItems(r.total);
        setTotalPages(r.totalPages);
      })
      .catch(e => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : 'Failed to load security alerts');
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [fileId, filters]);

  const openConversation = useCallback(async (conv: Conversation, index: number) => {
    setSelectedIndex(index);
    setDetailLoading(true);
    try {
      const full = await conversationService.getConversationDetail(conv.id);
      setSelectedConversation(full);
    } catch (err) {
      console.error('Failed to load conversation details:', err);
      setSelectedConversation(conv);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const closeModal = useCallback(() => setSelectedConversation(null), []);

  const handlePrev = useCallback(() => {
    if (selectedIndex > 0) openConversation(alerts[selectedIndex - 1], selectedIndex - 1);
  }, [selectedIndex, alerts, openConversation]);

  const handleNext = useCallback(() => {
    if (selectedIndex < alerts.length - 1) openConversation(alerts[selectedIndex + 1], selectedIndex + 1);
  }, [selectedIndex, alerts, openConversation]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeModal();
      if (!selectedConversation) return;
      if (e.key === 'ArrowLeft') handlePrev();
      if (e.key === 'ArrowRight') handleNext();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [closeModal, selectedConversation, handlePrev, handleNext]);

  useEffect(() => {
    document.body.style.overflow = selectedConversation ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [selectedConversation]);

  const protocolOptions = (data.protocolDistribution ?? []).map(p => ({ protocol: p.protocol, count: p.count }));

  const handleSort = (field: SortField) => {
    if (filters.sortBy !== field) {
      setFilters({ sortBy: field, sortDir: 'asc' });
    } else if (filters.sortDir === 'asc') {
      setFilters({ sortBy: field, sortDir: 'desc' });
    } else {
      setFilters({ sortBy: '', sortDir: 'asc' });
    }
  };

  const SortableHeader = ({ field, label }: { field: SortField; label: string }) => {
    const isActive = filters.sortBy === field;
    const icon = !isActive
      ? 'bi-arrow-down-up text-muted'
      : filters.sortDir === 'asc' ? 'bi-sort-up' : 'bi-sort-down';
    return (
      <th onClick={() => handleSort(field)} style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}>
        {label} <i className={`bi ${icon} ms-1`}></i>
      </th>
    );
  };

  // activeFilterCount excludes hasRisks (always true on this page) and fields not shown in this panel
  const securityFilterCount = [
    filters.ip,
    filters.protocols.length > 0,
    filters.riskTypes.length > 0,
  ].filter(Boolean).length;

  const modalTitle = selectedConversation
    ? `${formatIpPort(selectedConversation.endpoints[0].ip, selectedConversation.endpoints[0].port)} ↔ ${formatIpPort(selectedConversation.endpoints[1].ip, selectedConversation.endpoints[1].port)}`
    : '';

  const packetHints = selectedConversation
    ? selectedConversation.flowRisks
        .map(r => RISK_PACKET_HINTS[r])
        .filter((hint): hint is string => Boolean(hint))
    : [];

  if (error) return <ErrorMessage title="Failed to Load Security Alerts" message={error} />;

  return (
    <div className="security-page">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h4>
          <i className="bi bi-shield-exclamation text-danger me-2"></i>
          Security Alerts
          <span className="text-muted fs-6 fw-normal ms-2">({totalItems.toLocaleString()})</span>
        </h4>
        <a
          href={conversationService.getExportUrl(fileId, { ...filters, hasRisks: true })}
          download="security-alerts.csv"
          className="btn btn-sm btn-outline-secondary"
          title="Export current filtered results as CSV"
        >
          <i className="bi bi-download me-1"></i>Export CSV
        </a>
      </div>

      <SecurityFilterPanel
        filters={filters}
        onFiltersChange={setFilters}
        onClearAll={clearAll}
        protocols={protocolOptions}
        riskTypes={riskTypeOptions}
        activeFilterCount={securityFilterCount}
      />

      <div className="card overflow-hidden">
        <div className="card-body p-0">
          {loading ? (
            <LoadingSpinner size="medium" message="Scanning for security alerts..." />
          ) : alerts.length === 0 ? (
            <div className="text-center py-5">
              <i className="bi bi-shield-check display-3 text-success mb-3 d-block"></i>
              <h5>No security issues detected</h5>
              <p className="text-muted">nDPI found no risk flags matching the current filters.</p>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="table table-hover align-middle mb-0">
                <thead className="table-light">
                  <tr>
                    <SortableHeader field="srcIp"     label="Source" />
                    <SortableHeader field="dstIp"     label="Destination" />
                    <th>Protocol</th>
                    <th>Risk Flags</th>
                    <SortableHeader field="packets"   label="Packets" />
                    <SortableHeader field="bytes"     label="Bytes" />
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((conv, idx) => (
                    <tr
                      key={conv.id}
                      onClick={() => openConversation(conv, idx)}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') openConversation(conv, idx); }}
                      tabIndex={0}
                      role="button"
                      style={{ cursor: 'pointer' }}
                      className={selectedConversation?.id === conv.id ? 'table-active' : undefined}
                    >
                      <td className="font-monospace small">
                        {conv.endpoints[0].ip}:{conv.endpoints[0].port}
                      </td>
                      <td className="font-monospace small">
                        {conv.endpoints[1].ip}:{conv.endpoints[1].port}
                      </td>
                      <td>
                        <span className="badge bg-secondary">{conv.protocol.name}</span>
                        {conv.appName && (
                          <span className="badge bg-info ms-1">{conv.appName}</span>
                        )}
                      </td>
                      <td>
                        {conv.flowRisks.map(risk => (
                          <span
                            key={risk}
                            className={riskBadgeClass(risk)}
                            title={RISK_DESCRIPTIONS[risk] ?? risk}
                          >
                            {formatRiskLabel(risk)}
                          </span>
                        ))}
                      </td>
                      <td>{conv.packetCount.toLocaleString()}</td>
                      <td>{formatBytes(conv.totalBytes)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        {totalPages > 1 && (
          <div className="card-footer">
            <Pagination
              currentPage={filters.page}
              totalPages={totalPages}
              onPageChange={(page) => setFilters({ page })}
              pageSize={filters.pageSize}
              totalItems={totalItems}
              showPageSizeSelector
              onPageSizeChange={(pageSize) => setFilters({ pageSize, page: 1 })}
            />
          </div>
        )}
      </div>

      {/* Conversation detail modal */}
      {selectedConversation && (
        <div
          className="modal fade show d-block"
          style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
          onClick={(e) => { if (e.target === e.currentTarget) closeModal(); }}
          role="dialog"
          aria-modal="true"
          aria-labelledby="security-modal-title"
        >
          <div className="modal-dialog modal-xl modal-dialog-scrollable">
            <div className="modal-content">

              <div className="modal-header">
                <div className="d-flex align-items-center gap-3 flex-grow-1 min-w-0">
                  <button className="btn btn-sm btn-outline-secondary" onClick={handlePrev} disabled={selectedIndex <= 0} title="Previous">
                    ‹ Prev
                  </button>
                  <h5 id="security-modal-title" className="modal-title text-truncate mb-0 font-monospace small">{modalTitle}</h5>
                  <button className="btn btn-sm btn-outline-secondary" onClick={handleNext} disabled={selectedIndex >= alerts.length - 1} title="Next">
                    Next ›
                  </button>
                  <span className="text-muted small text-nowrap">{selectedIndex + 1} / {alerts.length}</span>
                </div>
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary ms-2 text-nowrap"
                  title="View this conversation in the Conversations tab"
                  onClick={() => {
                    closeModal();
                    navigate(`/analysis/${fileId}/conversations?ip=${encodeURIComponent(selectedConversation!.endpoints[0].ip)}&hasRisks=true`);
                  }}
                >
                  <i className="bi bi-arrow-right-circle me-1"></i>View in Conversations
                </button>
                <button type="button" className="btn-close ms-3" onClick={closeModal} title="Close (Esc)" />
              </div>

              {packetHints.length > 0 && (
                <div className="px-3 pt-2">
                  {packetHints.map((hint, i) => (
                    <div key={i} className="alert alert-warning py-2 mb-2 small">{hint}</div>
                  ))}
                </div>
              )}

              <div className="modal-body">
                {detailLoading
                  ? <LoadingSpinner size="medium" message="Loading conversation..." />
                  : <ConversationDetail conversation={selectedConversation} />
                }
              </div>

            </div>
          </div>
        </div>
      )}
    </div>
  );
};
