import { useState, useEffect } from 'react'
import { conversationService } from '@/features/conversation/services/conversationService'
import { networkService } from '../services/networkService'
import type { NetworkGraphData, GraphNode, GraphEdge, NetworkStats } from '../types'
import type { AnalysisSummary } from '@/types'

interface UseNetworkDataReturn extends NetworkGraphData {
  loading: boolean
  error: string | null
  refetch: () => void
}

/**
 * Custom hook for fetching and transforming network data into graph format
 * Follows the same pattern as useAnalysisData
 * @param fileId - The file ID to fetch conversations for
 * @param analysisSummary - Optional analysis summary for anomaly detection
 * @param maxConversations - Maximum conversations to render (default: 500 for performance)
 */
export function useNetworkData(
  fileId: string,
  analysisSummary?: AnalysisSummary,
  maxConversations: number = 500
): UseNetworkDataReturn {
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [edges, setEdges] = useState<GraphEdge[]>([])
  const [stats, setStats] = useState<NetworkStats>({
    totalNodes: 0,
    totalEdges: 0,
    totalPackets: 0,
    totalBytes: 0,
    protocolBreakdown: {},
  })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchData = async () => {
    if (!fileId) {
      setLoading(false)
      return
    }

    try {
      setLoading(true)
      setError(null)

      // Fetch conversations from API
      // For network visualization, fetch all conversations (use large page size)
      const response = await conversationService.getConversations(fileId, 1, 10000)
      const conversations = response.data

      // Transform to graph data with conversation limit
      const graphData = networkService.buildNetworkGraph(
        conversations,
        analysisSummary,
        maxConversations
      )

      setNodes(graphData.nodes)
      setEdges(graphData.edges)
      setStats({
        ...graphData.stats,
        isLimited: graphData.isLimited,
        totalConversations: graphData.totalConversations,
        displayedConversations: graphData.displayedConversations,
      })
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : 'Failed to load network data'
      setError(errorMessage)
      console.error('Error fetching network data:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [fileId, maxConversations])

  return {
    nodes,
    edges,
    stats,
    loading,
    error,
    refetch: fetchData,
  }
}
