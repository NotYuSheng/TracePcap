import { useState, useEffect } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { AnalysisData, Story, TimelineDataPoint } from '@/types';
import { storyService } from '@/features/story/services/storyService';
import { timelineService } from '@/features/timeline/services/timelineService';
import { NarrativeView } from '@components/story/NarrativeView';
import { AnomalyHighlight } from '@components/story/AnomalyHighlight';
import { StoryTimeline } from '@components/story/StoryTimeline';
import { TrafficTimeline } from '@components/timeline/TrafficTimeline';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const StoryPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>();
  const [story, setStory] = useState<Story | null>(null);
  const [timelineData, setTimelineData] = useState<TimelineDataPoint[]>([]);
  const [generating, setGenerating] = useState(false);
  const [loadingTimeline, setLoadingTimeline] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const handleGenerateStory = async () => {
    try {
      setGenerating(true);
      setError(null);
      const generatedStory = await storyService.generateStory(fileId);
      setStory(generatedStory);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate story');
    } finally {
      setGenerating(false);
    }
  };

  useEffect(() => {
    // Load timeline data
    const fetchTimeline = async () => {
      try {
        setLoadingTimeline(true);
        const data = await timelineService.getTimelineData(fileId);
        setTimelineData(data);
      } catch (err) {
        console.error('Failed to load timeline:', err);
      } finally {
        setLoadingTimeline(false);
      }
    };

    if (fileId) {
      fetchTimeline();
    }
  }, [fileId]);

  useEffect(() => {
    // Auto-generate story on page load
    if (fileId && !story) {
      handleGenerateStory();
    }
  }, [fileId]);

  // Calculate traffic statistics
  const totalPackets = timelineData.reduce((sum, point) => sum + (point.packetCount || 0), 0);
  const totalBytes = timelineData.reduce((sum, point) => sum + (point.bytes || 0), 0);
  const avgPackets = timelineData.length > 0 ? Math.round(totalPackets / timelineData.length) : 0;
  const packetCounts = timelineData.map(p => p.packetCount || 0).filter(n => !isNaN(n));
  const maxPackets = packetCounts.length > 0 ? Math.max(...packetCounts) : 0;

  if (generating && !story) {
    return (
      <div className="text-center py-5">
        <LoadingSpinner
          size="large"
          message="Generating narrative story... This may take a few moments."
        />
        <p className="text-muted mt-3">
          AI is analyzing the network traffic and creating a comprehensive narrative...
        </p>
      </div>
    );
  }

  if (error && !story) {
    return (
      <ErrorMessage
        title="Failed to Generate Story"
        message={error}
        onRetry={handleGenerateStory}
      />
    );
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
    );
  }

  return (
    <div className="story-page">
      {/* Header */}
      <div className="row mb-4">
        <div className="col-12">
          <div className="d-flex justify-content-between align-items-center">
            <div>
              <h4>Network Traffic Story</h4>
              <p className="text-muted mb-0">
                AI-generated narrative analysis with traffic visualization
              </p>
            </div>
            <button
              className="btn btn-outline-primary btn-sm"
              onClick={handleGenerateStory}
              disabled={generating}
            >
              <i className="bi bi-arrow-clockwise me-2"></i>
              {generating ? 'Generating...' : 'Regenerate'}
            </button>
          </div>
        </div>
      </div>

      {/* Traffic Statistics Cards */}
      {!loadingTimeline && timelineData.length > 0 && (
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
                <h6 className="text-muted mb-1">Total Data</h6>
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
      )}

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

      {/* Traffic Timeline Visualization */}
      {!loadingTimeline && timelineData.length > 0 && (
        <div className="row mb-4">
          <div className="col-12">
            <div className="card">
              <div className="card-body">
                <TrafficTimeline data={timelineData} />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Narrative and Event Timeline */}
      <div className="row">
        {/* Narrative Section */}
        <div className="col-lg-8">
          <NarrativeView sections={story.narrative} />
        </div>

        {/* Story Event Timeline Section */}
        <div className="col-lg-4">
          <div className="card sticky-top" style={{ top: '20px', zIndex: 10 }}>
            <div className="card-body">
              <h5 className="mb-3">Key Events</h5>
              {story.timeline && story.timeline.length > 0 ? (
                <StoryTimeline events={story.timeline} />
              ) : (
                <p className="text-muted small">No key events identified in this capture.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
