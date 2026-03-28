import { useState, useEffect, useCallback, useRef } from 'react';
import { useOutletContext, useSearchParams } from 'react-router-dom';
import type { AnalysisData, Conversation } from '@/types';
import { conversationService } from '@/features/conversation/services/conversationService';
import { ConversationList } from '@components/conversation/ConversationList';
import { ConversationDetail } from '@components/conversation/ConversationDetail';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { Pagination } from '@components/common/Pagination';
import { formatIpPort } from '@/utils/formatters';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const ConversationPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>();
  const [searchParams, setSearchParams] = useSearchParams();

  // URL-driven filters (from external navigation)
  const filterSrcIp = searchParams.get('srcIp');
  const filterPeerIp = searchParams.get('peerIp');
  const urlApp = searchParams.get('app');

  // Search bar state — initialised from URL ?app= param
  const [search, setSearch] = useState(urlApp ?? '');
  const [activeSearch, setActiveSearch] = useState(urlApp ?? '');
  const searchInputRef = useRef<HTMLInputElement>(null);

  // When URL app param changes (e.g. navigating from Overview), sync search bar
  useEffect(() => {
    if (urlApp !== null) {
      setSearch(urlApp);
      setActiveSearch(urlApp);
    }
  }, [urlApp]);

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<Conversation | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number>(-1);
  const [detailLoading, setDetailLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(25);
  const [totalItems, setTotalItems] = useState(0);
  const [totalPages, setTotalPages] = useState(0);

  useEffect(() => {
    const fetchConversations = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await conversationService.getConversations(fileId, currentPage, pageSize, activeSearch || undefined);
        setConversations(response.data);
        setTotalItems(response.total);
        setTotalPages(response.totalPages);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load conversations');
      } finally {
        setLoading(false);
      }
    };
    if (fileId) fetchConversations();
  }, [fileId, currentPage, pageSize, activeSearch]);

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

  const handlePrev = useCallback(() => {
    if (selectedIndex > 0) openConversation(conversations[selectedIndex - 1], selectedIndex - 1);
  }, [selectedIndex, conversations, openConversation]);

  const handleNext = useCallback(() => {
    if (selectedIndex < conversations.length - 1)
      openConversation(conversations[selectedIndex + 1], selectedIndex + 1);
  }, [selectedIndex, conversations, openConversation]);

  // ESC closes modal; arrow keys navigate
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

  // Prevent background scroll while modal is open
  useEffect(() => {
    document.body.style.overflow = selectedConversation ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  }, [selectedConversation]);

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    setSelectedConversation(null);
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setCurrentPage(1);
    setActiveSearch(search);
    // Clear URL params when user types a manual search
    setSearchParams({});
  };

  const handleSearchClear = () => {
    setSearch('');
    setActiveSearch('');
    setCurrentPage(1);
    setSearchParams({});
  };

  // IP-pair filter (from node details navigation) — applied client-side on top of server results
  const displayedConversations = (filterSrcIp && filterPeerIp)
    ? conversations.filter(c => {
        const [a, b] = c.endpoints;
        return (a.ip === filterSrcIp && b.ip === filterPeerIp) ||
               (a.ip === filterPeerIp && b.ip === filterSrcIp);
      })
    : conversations;

  if (loading) return <LoadingSpinner size="large" message="Loading conversations..." />;
  if (error) return <ErrorMessage title="Failed to Load Conversations" message={error} />;

  const modalTitle = selectedConversation
    ? `${formatIpPort(selectedConversation.endpoints[0].ip, selectedConversation.endpoints[0].port)} ↔ ${formatIpPort(selectedConversation.endpoints[1].ip, selectedConversation.endpoints[1].port)}`
    : '';

  return (
    <div className="conversation-page">
      <div className="row mb-3">
        <div className="col-12">
          <div className="d-flex justify-content-between align-items-center mb-2">
            <h4 className="mb-0">
              Network Conversations ({totalItems.toLocaleString()})
            </h4>
          </div>

          {/* Search bar */}
          <form onSubmit={handleSearchSubmit} className="d-flex gap-2 mb-2">
            <div className="input-group">
              <span className="input-group-text"><i className="bi bi-search"></i></span>
              <input
                ref={searchInputRef}
                type="text"
                className="form-control"
                placeholder="Filter by app, protocol, IP or hostname…"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
              {(search || activeSearch) && (
                <button type="button" className="btn btn-outline-secondary" onClick={handleSearchClear} title="Clear filter">
                  ×
                </button>
              )}
            </div>
            <button type="submit" className="btn btn-primary text-nowrap">Apply</button>
          </form>

          {/* Active search badge */}
          {activeSearch && (
            <div className="d-flex align-items-center gap-2 mb-1">
              <small className="text-muted">Filtered by:</small>
              <span className="badge bg-primary">
                {activeSearch}
                <button
                  type="button"
                  className="btn-close btn-close-white ms-1"
                  style={{ fontSize: '0.6rem' }}
                  onClick={handleSearchClear}
                  aria-label="Clear filter"
                />
              </span>
            </div>
          )}

          {/* IP-pair filter banner (from node details navigation) */}
          {filterSrcIp && filterPeerIp && (
            <div className="alert alert-info py-2 mb-0 mt-2 d-flex align-items-center justify-content-between">
              <span>
                <i className="bi bi-funnel me-2"></i>
                Showing conversations between <strong className="font-monospace mx-1">{filterSrcIp}</strong> and <strong className="font-monospace mx-1">{filterPeerIp}</strong>
                {displayedConversations.length === 0 && ' — none found on this page'}
              </span>
              <button className="btn btn-sm btn-outline-secondary ms-3" onClick={() => setSearchParams({})}>
                Clear filter ×
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="row">
        <div className="col-12">
          <div className="card">
            <div className="card-header d-flex justify-content-between align-items-center">
              <h6 className="mb-0">All Conversations</h6>
              <small className="text-muted">Click a row to view details</small>
            </div>
            <div className="card-body p-0">
              <ConversationList
                conversations={displayedConversations}
                onSelectConversation={(c) => {
                  const idx = displayedConversations.findIndex(x => x.id === c.id);
                  openConversation(c, idx);
                }}
              />
            </div>
            {totalPages > 1 && (
              <div className="card-footer">
                <Pagination
                  currentPage={currentPage}
                  totalPages={totalPages}
                  onPageChange={handlePageChange}
                  pageSize={pageSize}
                  totalItems={totalItems}
                />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Modal */}
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
