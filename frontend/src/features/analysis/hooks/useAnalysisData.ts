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

      // Poll file status until completed or failed
      const pollStatus = async () => {
        try {
          const fileMetadata = await apiClient.get(`${API_ENDPOINTS.FILE_METADATA(fileId)}`)
          const status = fileMetadata.data.status

          console.log(`File ${fileId} status: ${status}`)

          if (status === 'COMPLETED') {
            // Analysis is done, fetch the results
            console.log(`[useAnalysisData] File ${fileId} is COMPLETED, fetching analysis...`)
            try {
              const summary = await analysisService.getAnalysisSummary(fileId)
              console.log(`[useAnalysisData] Successfully fetched analysis for ${fileId}`, summary)
              if (!cancelled) {
                setData(summary)
                setCurrentFileId(fileId)
                setAnalysisSummary(fileId, summary)
                setError(null)
                setLoading(false)
                if (pollInterval) clearInterval(pollInterval)
                console.log(`[useAnalysisData] Set loading=false, cleared interval`)
              } else {
                console.log(`[useAnalysisData] Request was cancelled, not updating state`)
              }
            } catch (err) {
              console.error(`[useAnalysisData] Error fetching analysis:`, err)
              if (!cancelled) {
                const error = err instanceof Error ? err : new Error('Failed to fetch analysis')
                setError(error)
                setLoading(false)
                if (pollInterval) clearInterval(pollInterval)
              }
            }
          } else if (status === 'FAILED') {
            // Analysis failed
            if (!cancelled) {
              setError(new Error('Analysis failed'))
              setLoading(false)
              if (pollInterval) clearInterval(pollInterval)
            }
          }
          // If status is PROCESSING, keep polling
        } catch (err) {
          if (!cancelled) {
            const error = err instanceof Error ? err : new Error('Failed to check file status')
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
