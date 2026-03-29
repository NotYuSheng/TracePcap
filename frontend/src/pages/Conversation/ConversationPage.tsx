import { useState, useEffect, useCallback } from 'react';
import { useOutletContext, useSearchParams } from 'react-router-dom';
import type { AnalysisData, Conversation } from '@/types';
import type { SortField } from '@/features/conversation/types';
import { loadVisibleColumns, COLUMN_STORAGE_KEY } from '@/features/conversation/constants';
import type { ColumnKey } from '@/features/conversation/constants';
import { useConversationFilters } from '@/features/conversation/hooks/useConversationFilters';
import { conversationService } from '@/features/conversation/services/conversationService';
import { ConversationList } from '@components/conversation/ConversationList';
import { ConversationDetail } from '@components/conversation/ConversationDetail';
import { ConversationFilterPanel } from '@components/conversation/ConversationFilterPanel';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { Pagination } from '@components/common/Pagination';
import { formatIpPort } from '@/utils/formatters';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const ConversationPage = () => {
  const { fileId, data } = useOutletContext<AnalysisOutletContext>();
  const [searchParams, setSearchParams] = useSearchParams();
  const { filters, activeFilterCount, setFilters, clearAll } = useConversationFilters();

  const [conversations, setConversations]       = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<Conversation | null>(null);
  const [selectedIndex, setSelectedIndex]       = useState<number>(-1);
  const [detailLoading, setDetailLoading]       = useState(false);
  const [loading, setLoading]                   = useState(true);
  const [error, setError]                       = useState<string | null>(null);
  const [totalItems, setTotalItems]             = useState(0);
  const [totalPages, setTotalPages]             = useState(0);
  const [fileTypeOptions, setFileTypeOptions]         = useState<string[]>([]);
  const [riskTypeOptions, setRiskTypeOptions]         = useState<string[]>([]);
  const [customSignatureOptions, setCustomSignatureOptions] = useState<string[]>([]);
  const [signatureSeverities, setSignatureSeverities] = useState<Record<string, string>>({});
  const [visibleColumns, setVisibleColumns]     = useState<Set<ColumnKey>>(loadVisibleColumns);

  const toggleColumn = useCallback((key: ColumnKey) => {
    setVisibleColumns(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      localStorage.setItem(COLUMN_STORAGE_KEY, JSON.stringify([...next]));
      return next;
    });
  }, []);

  // Fetch available file types and risk types once per file
  useEffect(() => {
    if (!fileId) return;
    conversationService.getFileTypes(fileId).then(setFileTypeOptions).catch(console.error);
    conversationService.getRiskTypes(fileId).then(setRiskTypeOptions).catch(console.error);
    conversationService.getCustomSignatures(fileId).then(setCustomSignatureOptions).catch(console.error);
    conversationService.getSignatureRules().then(rules => {
      const map: Record<string, string> = {};
      rules.forEach(r => { map[r.name] = r.severity; });
      setSignatureSeverities(map);
    }).catch(console.error);
  }, [fileId]);

  // One-shot migration of legacy URL params from NodeDetails and Overview navigation
  useEffect(() => {
    const srcIp  = searchParams.get('srcIp');
    const peerIp = searchParams.get('peerIp');
    const app    = searchParams.get('app');
    if (srcIp || peerIp || app) {
      const next = new URLSearchParams(searchParams);
      if (srcIp || peerIp) {
        next.set('ip', srcIp ?? peerIp ?? '');
        next.delete('srcIp');
        next.delete('peerIp');
      }
      if (app) {
        next.set('apps', app);
        next.delete('app');
      }
      setSearchParams(next, { replace: true });
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch conversations whenever filters change
  useEffect(() => {
    if (!fileId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    conversationService.getConversations(fileId, filters)
      .then(r => {
        if (cancelled) return;
        setConversations(r.data);
        setTotalItems(r.total);
        setTotalPages(r.totalPages);
      })
      .catch(e => {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : 'Failed to load conversations');
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [fileId, filters]);

  const openConversation = useCallback(async (conversation: Conversation, index: number) => {
    setSelectedIndex(index);
    setDetailLoading(true);
    try {
      if (conversation.packets && conversation.packets.length > 0) {
        setSelectedConversation(conversation);
      } else {
        const full = await conversationService.getConversationDetail(conversation.id);
        setSelectedConversation(full);
      }
    } catch (err) {
      console.error('Failed to load conversation details:', err);
      setSelectedConversation(conversation);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const closeModal = useCallback(() => setSelectedConversation(null), []);

  const exportConversationCsv = useCallback((conversation: Conversation) => {
    const hexToAscii = (hex: string) => {
      if (!hex) return '';
      let out = '';
      for (let i = 0; i < hex.length; i += 2) {
        const byte = parseInt(hex.slice(i, i + 2), 16);
        out += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.';
      }
      return out;
    };
    const esc = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows: string[] = [];
    // Summary header + row
    rows.push('srcIp,srcPort,dstIp,dstPort,protocol,appName,category,hostname,packetCount,totalBytes,startTime,endTime,flowRisks,customSignatures');
    rows.push([
      esc(conversation.endpoints[0].ip), esc(conversation.endpoints[0].port),
      esc(conversation.endpoints[1].ip), esc(conversation.endpoints[1].port),
      esc(conversation.protocol.name), esc(conversation.appName),
      esc(conversation.category), esc(conversation.hostname),
      esc(conversation.packetCount), esc(conversation.totalBytes),
      esc(conversation.startTime), esc(conversation.endTime),
      esc((conversation.flowRisks ?? []).join('; ')),
      esc((conversation.customSignatures ?? []).join('; ')),
    ].join(','));
    // Packets
    if (conversation.packets && conversation.packets.length > 0) {
      rows.push('');
      rows.push('packetNumber,timestamp,srcIp,srcPort,dstIp,dstPort,protocol,size,info,hexPayload,asciiPayload');
      conversation.packets.forEach((p, i) => {
        rows.push([
          esc(i + 1), esc(p.timestamp),
          esc(p.source.ip), esc(p.source.port),
          esc(p.destination.ip), esc(p.destination.port),
          esc(p.protocol.name), esc(p.size), esc(p.info),
          esc(p.payload), esc(hexToAscii(p.payload)),
        ].join(','));
      });
    }
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const src = conversation.endpoints[0].ip.replace(/[^a-zA-Z0-9.]/g, '_');
    const dst = conversation.endpoints[1].ip.replace(/[^a-zA-Z0-9.]/g, '_');
    const ts = new Date().toISOString().slice(0, 16).replace('T', '_').replace(':', '-');
    a.download = `conversation_${src}_${dst}_${ts}.csv`;
    a.href = url;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  const handlePrev = useCallback(() => {
    if (selectedIndex > 0) openConversation(conversations[selectedIndex - 1], selectedIndex - 1);
  }, [selectedIndex, conversations, openConversation]);

  const handleNext = useCallback(() => {
    if (selectedIndex < conversations.length - 1)
      openConversation(conversations[selectedIndex + 1], selectedIndex + 1);
  }, [selectedIndex, conversations, openConversation]);

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

  // Sort: cycle empty → asc → desc → empty
  const handleSort = (field: SortField) => {
    if (!field) {
      setFilters({ sortBy: '', sortDir: 'asc' });
    } else if (filters.sortBy !== field) {
      setFilters({ sortBy: field, sortDir: 'asc' });
    } else if (filters.sortDir === 'asc') {
      setFilters({ sortBy: field, sortDir: 'desc' });
    } else {
      setFilters({ sortBy: '', sortDir: 'asc' });
    }
  };

  // Filter options from the already-loaded analysis summary
  const protocolOptions = (data.protocolDistribution ?? []).map(p => ({ protocol: p.protocol, count: p.count }));
  const appOptions      = (data.detectedApplications ?? []).map(a => ({ name: a.name }));
  const categoryOptions = (data.categoryDistribution ?? []).map(c => ({ category: c.category }));

  // CSV export URL
  const exportUrl = conversationService.getExportUrl(fileId, filters);
  const exportFilename = (() => {
    const base = (data.fileName ?? 'conversations').replace(/\.[^.]+$/, '');
    const ts = new Date().toISOString().slice(0, 16).replace('T', '_').replace(':', '-');
    return `${base}_${ts}.csv`;
  })();

  const modalTitle = selectedConversation
    ? `${formatIpPort(selectedConversation.endpoints[0].ip, selectedConversation.endpoints[0].port)} ↔ ${formatIpPort(selectedConversation.endpoints[1].ip, selectedConversation.endpoints[1].port)}`
    : '';

  if (error) return <ErrorMessage title="Failed to Load Conversations" message={error} />;

  return (
    <div className="conversation-page">
      <div className="row mb-3">
        <div className="col-12">
          <div className="d-flex justify-content-between align-items-center mb-3">
            <h4 className="mb-0">
              Network Conversations
              <span className="text-muted fs-6 fw-normal ms-2">({totalItems.toLocaleString()})</span>
            </h4>
            <a
              href={exportUrl}
              download={exportFilename}
              className="btn btn-sm btn-outline-secondary"
              title="Export current filtered results as CSV"
            >
              <i className="bi bi-download me-1"></i>
              Export CSV
            </a>
          </div>

          <ConversationFilterPanel
            filters={filters}
            onFiltersChange={setFilters}
            onClearAll={clearAll}
            protocols={protocolOptions}
            l7Protocols={data.detectedL7Protocols ?? []}
            apps={appOptions}
            categories={categoryOptions}
            fileTypes={fileTypeOptions}
            riskTypes={riskTypeOptions}
            customSignatureOptions={customSignatureOptions}
            signatureSeverities={signatureSeverities}
            activeFilterCount={activeFilterCount}
            visibleColumns={visibleColumns}
            onToggleColumn={toggleColumn}
          />
        </div>
      </div>

      <div className="row">
        <div className="col-12">
          <div className="card">
            <div className="card-header d-flex justify-content-between align-items-center">
              <h6 className="mb-0">Conversations</h6>
              <small className="text-muted">Click a row to view details</small>
            </div>
            <div className="card-body p-0">
              {loading ? (
                <LoadingSpinner size="medium" message="Loading conversations..." />
              ) : (
                <ConversationList
                  conversations={conversations}
                  onSelectConversation={(c) => {
                    const idx = conversations.findIndex(x => x.id === c.id);
                    openConversation(c, idx);
                  }}
                  sortBy={filters.sortBy}
                  sortDir={filters.sortDir}
                  onSort={handleSort}
                  onRiskFilterClick={() => setFilters({ hasRisks: true })}
                  visibleColumns={visibleColumns}
                  signatureSeverities={signatureSeverities}
                />
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
        </div>
      </div>

      {/* Conversation detail modal */}
      {selectedConversation && (
        <div
          className="modal fade show d-block"
          style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
          onClick={(e) => { if (e.target === e.currentTarget) closeModal(); }}
        >
          <div className="modal-dialog modal-xl modal-dialog-scrollable">
            <div className="modal-content">
              <div className="modal-header">
                <div className="d-flex align-items-center gap-3 flex-grow-1 min-w-0">
                  <button
                    className="btn btn-sm btn-outline-secondary"
                    onClick={handlePrev}
                    disabled={selectedIndex <= 0}
                    title="Previous conversation"
                  >
                    ‹ Prev
                  </button>
                  <h5 className="modal-title text-truncate mb-0 font-monospace small">
                    {modalTitle}
                  </h5>
                  <button
                    className="btn btn-sm btn-outline-secondary"
                    onClick={handleNext}
                    disabled={selectedIndex >= conversations.length - 1}
                    title="Next conversation"
                  >
                    Next ›
                  </button>
                  <span className="text-muted small text-nowrap">
                    {selectedIndex + 1} / {conversations.length}
                  </span>
                </div>
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary ms-2"
                  onClick={() => exportConversationCsv(selectedConversation)}
                  title="Export this conversation as CSV"
                >
                  <i className="bi bi-download me-1"></i>CSV
                </button>
                <button
                  type="button"
                  className="btn-close ms-2"
                  onClick={closeModal}
                  title="Close (Esc)"
                />
              </div>
              <div className="modal-body">
                {detailLoading
                  ? <LoadingSpinner size="medium" message="Loading conversation..." />
                  : <ConversationDetail conversation={selectedConversation} signatureSeverities={signatureSeverities} />
                }
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
