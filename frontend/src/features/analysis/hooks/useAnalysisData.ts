import { useEffect, useState } from 'react'
import { useStore } from '@/store'
import { analysisService } from '../services/analysisService'
import { apiClient } from '@/services/api/client'
import { API_ENDPOINTS } from '@/services/api/endpoints'
import type { AnalysisSummary } from '@/types'

export const useAnalysisData = (fileId: string) => {
  const [data, setData] = useState<AnalysisSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const setCurrentFileId = useStore((state) => state.setCurrentFileId)
  const setAnalysisSummary = useStore((state) => state.setAnalysisSummary)
  const cachedSummary = useStore((state) => state.analysisSummaries[fileId])

  useEffect(() => {
    let cancelled = false
    let pollInterval: number | null = null

    const checkStatusAndFetch = async () => {
      // Check if we have cached data first
      if (cachedSummary) {
        setData(cachedSummary)
        setLoading(false)
        return
      }

      setLoading(true)
      setError(null)

      // Poll analysis endpoint using HTTP status codes
      const pollStatus = async () => {
        try {
          // Try to fetch the analysis summary
          const response = await apiClient.get(`${API_ENDPOINTS.ANALYSIS_SUMMARY(fileId)}`, {
            validateStatus: (status) => {
              // Accept 200 (completed), 202 (processing), and 500 (failed)
              return status === 200 || status === 202 || status === 500
            }
          })

          console.log(`[useAnalysisData] File ${fileId} HTTP status: ${response.status}`)

          if (response.status === 200) {
            // 200 OK: Analysis completed successfully
            console.log(`[useAnalysisData] Analysis completed, received data`)
            if (!cancelled) {
              setData(response.data)
              setCurrentFileId(fileId)
              setAnalysisSummary(fileId, response.data)
              setError(null)
              setLoading(false)
              if (pollInterval) clearInterval(pollInterval)
              console.log(`[useAnalysisData] Set loading=false, cleared interval`)
            }
          } else if (response.status === 202) {
            // 202 Accepted: Still processing, keep polling
            const retryAfter = response.headers['retry-after'] || '2'
            console.log(`[useAnalysisData] Still processing, retry after ${retryAfter}s`)
            // Keep polling (interval handles this)
          } else if (response.status === 500) {
            // 500 Internal Server Error: Analysis failed
            if (!cancelled) {
              setError(new Error('Analysis failed on server'))
              setLoading(false)
              if (pollInterval) clearInterval(pollInterval)
            }
          }
        } catch (err: any) {
          console.error(`[useAnalysisData] Error polling analysis:`, err)
          // Handle unexpected errors (404, network errors, etc.)
          if (!cancelled) {
            const error = err instanceof Error ? err : new Error('Failed to fetch analysis')
            setError(error)
            setLoading(false)
            if (pollInterval) clearInterval(pollInterval)
          }
        }
      }

      // Initial status check
      await pollStatus()

      // Set up polling every 2 seconds
      pollInterval = setInterval(pollStatus, 2000)

      // Timeout after 60 seconds
      setTimeout(() => {
        if (pollInterval) {
          clearInterval(pollInterval)
          if (!cancelled && loading) {
            setError(new Error('Analysis timeout - file is taking too long to process'))
            setLoading(false)
          }
        }
      }, 60000)
    }

    checkStatusAndFetch()

    return () => {
      cancelled = true
      if (pollInterval) clearInterval(pollInterval)
    }
  }, [fileId, cachedSummary, setCurrentFileId, setAnalysisSummary])

  const refetch = async () => {
    setLoading(true)
    setError(null)

    try {
      const summary = await analysisService.getAnalysisSummary(fileId)
      setData(summary)
      setAnalysisSummary(fileId, summary)
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Failed to fetch analysis')
      setError(error)
    } finally {
      setLoading(false)
    }
  }

  return {
    data,
    loading,
    error,
    refetch,
  }
}
