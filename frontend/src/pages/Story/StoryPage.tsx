import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import type { AnalysisData, Story } from '@/types'
import { storyService } from '@/features/story/services/storyService'
import { NarrativeView } from '@components/story/NarrativeView'
import { AnomalyHighlight } from '@components/story/AnomalyHighlight'
import { StoryTimeline } from '@components/story/StoryTimeline'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { ErrorMessage } from '@components/common/ErrorMessage'

interface AnalysisOutletContext {
  data: AnalysisData
  fileId: string
}

export const StoryPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>()
  const [story, setStory] = useState<Story | null>(null)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleGenerateStory = async () => {
    try {
      setGenerating(true)
      setError(null)
      const generatedStory = await storyService.generateStory(fileId)
      setStory(generatedStory)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate story')
    } finally {
      setGenerating(false)
    }
  }

  useEffect(() => {
    // Auto-generate story on page load
    if (fileId && !story) {
      handleGenerateStory()
    }
  }, [fileId])

  if (generating) {
    return (
      <div className="text-center py-5">
        <LoadingSpinner size="large" message="Generating narrative story... This may take a few moments." />
        <p className="text-muted mt-3">
          AI is analyzing the network traffic and creating a comprehensive narrative...
        </p>
      </div>
    )
  }

  if (error && !story) {
    return (
      <ErrorMessage
        title="Failed to Generate Story"
        message={error}
        onRetry={handleGenerateStory}
      />
    )
  }

  if (!story) {
    return (
      <div className="text-center py-5">
        <h4>No Story Generated Yet</h4>
        <p className="text-muted mb-4">
          Generate an AI-powered narrative analysis of this network capture
        </p>
        <button className="btn btn-primary" onClick={handleGenerateStory}>
          <i className="bi bi-magic me-2"></i>
          Generate Story
        </button>
      </div>
    )
  }

  return (
    <div className="story-page">
      <div className="row mb-4">
        <div className="col-12">
          <div className="d-flex justify-content-between align-items-center">
            <div>
              <h4>Network Traffic Story</h4>
              <p className="text-muted mb-0">
                AI-generated narrative analysis of network activity
              </p>
            </div>
            <button
              className="btn btn-outline-primary btn-sm"
              onClick={handleGenerateStory}
              disabled={generating}
            >
              <i className="bi bi-arrow-clockwise me-2"></i>
              Regenerate
            </button>
          </div>
        </div>
      </div>

      {/* Key Highlights Section */}
      {story.highlights && story.highlights.length > 0 && (
        <div className="row mb-4">
          <div className="col-12">
            <div className="card">
              <div className="card-body">
                <AnomalyHighlight highlights={story.highlights} />
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="row">
        {/* Narrative Section */}
        <div className="col-lg-8">
          <NarrativeView sections={story.narrative} />
        </div>

        {/* Timeline Section */}
        <div className="col-lg-4">
          <div className="card sticky-top" style={{ top: '20px' }}>
            <div className="card-body">
              {story.timeline && story.timeline.length > 0 && (
                <StoryTimeline events={story.timeline} />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
