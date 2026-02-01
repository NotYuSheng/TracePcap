import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { AnalysisData, Conversation } from '@/types'
import { conversationService } from '@/features/conversation/services/conversationService'
import { ConversationList } from '@components/conversation/ConversationList'
import { ConversationDetail } from '@components/conversation/ConversationDetail'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { ErrorMessage } from '@components/common/ErrorMessage'
import { Pagination } from '@components/common/Pagination'

interface AnalysisOutletContext {
  data: AnalysisData
  fileId: string
}

export const ConversationPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>()
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [selectedConversation, setSelectedConversation] = useState<Conversation | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize] = useState(25)
  const [totalItems, setTotalItems] = useState(0)
  const [totalPages, setTotalPages] = useState(0)

  useEffect(() => {
    const fetchConversations = async () => {
      try {
        setLoading(true)
        setError(null)
        const response = await conversationService.getConversations(fileId, currentPage, pageSize)
        setConversations(response.data)
        setTotalItems(response.total)
        setTotalPages(response.totalPages)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load conversations')
      } finally {
        setLoading(false)
      }
    }

    if (fileId) {
      fetchConversations()
    }
  }, [fileId, currentPage, pageSize])

  const handleSelectConversation = async (conversation: Conversation) => {
    try {
      // If conversation already has packets, use it directly
      if (conversation.packets && conversation.packets.length > 0) {
        setSelectedConversation(conversation)
      } else {
        // Otherwise fetch full conversation details
        const fullConversation = await conversationService.getConversationDetail(conversation.id)
        setSelectedConversation(fullConversation)
      }
    } catch (err) {
      console.error('Failed to load conversation details:', err)
      // Fallback to showing basic conversation info
      setSelectedConversation(conversation)
    }
  }

  if (loading) {
    return <LoadingSpinner size="large" message="Loading conversations..." />
  }

  if (error) {
    return <ErrorMessage title="Failed to Load Conversations" message={error} />
  }

  const handlePageChange = (page: number) => {
    setCurrentPage(page)
    setSelectedConversation(null) // Clear selection when changing pages
  }

  return (
    <div className="conversation-page">
      <div className="row">
        <div className="col-12 mb-3">
          <div className="d-flex justify-content-between align-items-center">
            <h4>Network Conversations ({totalItems.toLocaleString()})</h4>
          </div>
        </div>
      </div>

      <div className="row">
        <div className={selectedConversation ? 'col-md-5' : 'col-12'}>
          <div className="card">
            <div className="card-header">
              <h6 className="mb-0">All Conversations</h6>
            </div>
            <div className="card-body p-0">
              <ConversationList
                conversations={conversations}
                onSelectConversation={handleSelectConversation}
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

        {selectedConversation && (
          <div className="col-md-7">
            <ConversationDetail conversation={selectedConversation} />
          </div>
        )}
      </div>
    </div>
  )
}
