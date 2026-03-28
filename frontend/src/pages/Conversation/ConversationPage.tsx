import { useState, useEffect, useCallback } from 'react';
import { useOutletContext, useSearchParams } from 'react-router-dom';
import type { AnalysisData, Conversation } from '@/types';
import type { SortField } from '@/features/conversation/types';
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
    } catch {
      setSelectedConversation(conversation);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const closeModal = useCallback(() => setSelectedConversation(null), []);

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
              download="conversations.csv"
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
            apps={appOptions}
            categories={categoryOptions}
            activeFilterCount={activeFilterCount}
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
                  className="btn-close ms-3"
                  onClick={closeModal}
                  title="Close (Esc)"
                />
              </div>
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
