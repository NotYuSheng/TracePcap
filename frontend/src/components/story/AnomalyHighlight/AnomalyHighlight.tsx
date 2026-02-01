import type { Highlight } from '@/types'
import { formatTimestamp } from '@/utils/formatters'

interface AnomalyHighlightProps {
  highlights: Highlight[]
}

export const AnomalyHighlight = ({ highlights }: AnomalyHighlightProps) => {
  const getHighlightClass = (type: string) => {
    const classes: Record<string, string> = {
      anomaly: 'alert-danger',
      warning: 'alert-warning',
      insight: 'alert-info',
      info: 'alert-primary',
    }
    return classes[type] || 'alert-secondary'
  }

  const getHighlightIcon = (type: string) => {
    const icons: Record<string, string> = {
      anomaly: 'bi-shield-exclamation',
      warning: 'bi-exclamation-triangle',
      insight: 'bi-lightbulb',
      info: 'bi-info-circle',
    }
    return icons[type] || 'bi-circle'
  }

  const sortedHighlights = [...highlights].sort((a, b) => {
    // Sort by severity: anomaly > warning > insight > info
    const severityOrder: Record<string, number> = {
      anomaly: 0,
      warning: 1,
      insight: 2,
      info: 3,
    }
    return (severityOrder[a.type] || 4) - (severityOrder[b.type] || 4)
  })

  return (
    <div className="anomaly-highlight">
      <h5 className="mb-3">Key Highlights</h5>

      {sortedHighlights.map((highlight) => (
        <div key={highlight.id} className={`alert ${getHighlightClass(highlight.type)} d-flex`} role="alert">
          <div className="flex-shrink-0 me-3">
            <i className={`bi ${getHighlightIcon(highlight.type)} fs-4`}></i>
          </div>
          <div className="flex-grow-1">
            <h6 className="alert-heading mb-1">{highlight.title}</h6>
            <p className="mb-1">{highlight.description}</p>
            {highlight.timestamp && (
              <small className="text-muted">
                <i className="bi bi-clock me-1"></i>
                {formatTimestamp(highlight.timestamp)}
              </small>
            )}
          </div>
        </div>
      ))}

      {highlights.length === 0 && (
        <div className="alert alert-secondary">
          <p className="mb-0">No highlights to display</p>
        </div>
      )}
    </div>
  )
}
