import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { AnalysisData, TimelineDataPoint } from '@/types'
import { timelineService } from '@/features/timeline/services/timelineService'
import { TrafficTimeline } from '@components/timeline/TrafficTimeline'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { ErrorMessage } from '@components/common/ErrorMessage'

interface AnalysisOutletContext {
  data: AnalysisData
  fileId: string
}

export const TimelinePage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>()
  const [timelineData, setTimelineData] = useState<TimelineDataPoint[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        setLoading(true)
        setError(null)
        const data = await timelineService.getTimelineData(fileId)
        setTimelineData(data)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load timeline data')
      } finally {
        setLoading(false)
      }
    }

    if (fileId) {
      fetchTimeline()
    }
  }, [fileId])

  if (loading) {
    return <LoadingSpinner size="large" message="Loading timeline..." />
  }

  if (error) {
    return <ErrorMessage title="Failed to Load Timeline" message={error} />
  }

  if (timelineData.length === 0) {
    return (
      <div className="alert alert-warning">
        No timeline data available for this capture.
      </div>
    )
  }

  // Calculate summary statistics
  const totalPackets = timelineData.reduce((sum, point) => sum + (point.packetCount || 0), 0)
  const totalBytes = timelineData.reduce((sum, point) => sum + (point.bytes || 0), 0)
  const avgPackets = Math.round(totalPackets / timelineData.length) || 0
  const packetCounts = timelineData.map((p) => p.packetCount || 0).filter(n => !isNaN(n))
  const maxPackets = packetCounts.length > 0 ? Math.max(...packetCounts) : 0

  return (
    <div className="timeline-page">
      <div className="row mb-4">
        <div className="col-12">
          <h4>Traffic Timeline</h4>
          <p className="text-muted">
            Visualization of network traffic patterns over time
          </p>
        </div>
      </div>

      <div className="row mb-4">
        <div className="col-md-3">
          <div className="card">
            <div className="card-body text-center">
              <h6 className="text-muted mb-1">Total Packets</h6>
              <h3 className="mb-0">{totalPackets.toLocaleString()}</h3>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card">
            <div className="card-body text-center">
              <h6 className="text-muted mb-1">Total Bytes</h6>
              <h3 className="mb-0">{(totalBytes / 1024 / 1024).toFixed(2)} MB</h3>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card">
            <div className="card-body text-center">
              <h6 className="text-muted mb-1">Avg Packets/Min</h6>
              <h3 className="mb-0">{avgPackets.toLocaleString()}</h3>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card">
            <div className="card-body text-center">
              <h6 className="text-muted mb-1">Peak Packets/Min</h6>
              <h3 className="mb-0">{maxPackets.toLocaleString()}</h3>
            </div>
          </div>
        </div>
      </div>

      <div className="row">
        <div className="col-12">
          <div className="card">
            <div className="card-body">
              <TrafficTimeline data={timelineData} />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
