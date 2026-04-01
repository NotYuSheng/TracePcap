import { useState, useEffect, useRef, useCallback } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { AnalysisData, Story, TimelineDataPoint } from '@/types';
import { apiClient } from '@/services/api/client';
import { storyService } from '@/features/story/services/storyService';
import { timelineService } from '@/features/timeline/services/timelineService';
import {
  AUTO_GRANULARITY_INTERVAL,
  AUTO_GRANULARITY_MAX_DATAPOINTS,
} from '@/features/timeline/constants';
import { NarrativeView } from '@components/story/NarrativeView';
import { AnomalyHighlight } from '@components/story/AnomalyHighlight';
import { StoryTimeline } from '@components/story/StoryTimeline';
import { StoryInfoCard } from '@components/story/StoryInfoCard';
import { StoryChat } from '@components/story/StoryChat';
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
  const [granularity, setGranularity] = useState<number | 'auto'>('auto');
  const [additionalContext, setAdditionalContext] = useState('');
  const [generating, setGenerating] = useState(false);
  const [loadingStory, setLoadingStory] = useState(true);
  const [loadingTimeline, setLoadingTimeline] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [llmTimeoutMs, setLlmTimeoutMs] = useState<number>(300000);
  const [loadingLimits, setLoadingLimits] = useState(true);
  const autoTriggeredRef = useRef(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    apiClient.get<{ llmTimeoutMs?: number }>('/system/limits')
      .then(res => {
        if (res.data.llmTimeoutMs) setLlmTimeoutMs(res.data.llmTimeoutMs);
      })
      .catch(() => {/* keep default */})
      .finally(() => setLoadingLimits(false));
  }, []);

  useEffect(() => {
    if (generating) {
      setElapsedSeconds(0);
      timerRef.current = setInterval(() => setElapsedSeconds(s => s + 1), 1000);
    } else {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [generating]);

  const handleGenerateStory = useCallback(async () => {
    try {
      setGenerating(true);
      setError(null);
      const generatedStory = await storyService.generateStory(fileId, additionalContext, llmTimeoutMs);
      setStory(generatedStory);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const status = (err as { response?: { status?: number } })?.response?.status;
      const isTimeout = (err as { code?: string })?.code === 'ECONNABORTED' || msg.toLowerCase().includes('timeout') || msg.toLowerCase().includes('exceeded');
      if (isTimeout) {
        const minutes = Math.round(llmTimeoutMs / 60000);
        setError(
          `Story generation timed out after ${minutes} minute${minutes !== 1 ? 's' : ''}. The LLM is taking too long to respond. Try again or reduce the capture size.`
        );
      } else if (
        status === 500 ||
        msg.includes('500') ||
        msg.toLowerCase().includes('llm') ||
        msg.toLowerCase().includes('connection')
      ) {
        setError(
          'The LLM server is not responding. Make sure the LLM service is running and reachable, then try again.'
        );
      } else {
        setError(msg || 'Failed to generate story');
      }
    } finally {
      setGenerating(false);
    }
  }, [fileId, additionalContext, llmTimeoutMs]);

  useEffect(() => {
    const fetchExistingStory = async () => {
      try {
        setLoadingStory(true);
        const existing = await storyService.getStoryByFileId(fileId);
        if (existing) setStory(existing);
      } catch (err) {
        console.error('Failed to load existing story:', err);
      } finally {
        setLoadingStory(false);
      }
    };

    if (fileId) {
      fetchExistingStory();
    } else {
      setLoadingStory(false);
    }
  }, [fileId]);

  // Auto-generate story if none exists yet — wait for limits to load so the correct timeout is used
  useEffect(() => {
    if (!loadingStory && !loadingLimits && !story && !generating && !error && !autoTriggeredRef.current) {
      autoTriggeredRef.current = true;
      handleGenerateStory();
    }
  }, [loadingStory, loadingLimits, story, generating, error, handleGenerateStory]);

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        setLoadingTimeline(true);
        const data =
          granularity === 'auto'
            ? await timelineService.getTimelineData(
                fileId,
                AUTO_GRANULARITY_INTERVAL,
                AUTO_GRANULARITY_MAX_DATAPOINTS
              )
            : await timelineService.getTimelineData(fileId, granularity);
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
  }, [fileId, granularity]);

  // Calculate traffic statistics
  const totalPackets = timelineData.reduce((sum, point) => sum + (point.packetCount || 0), 0);
  const totalBytes = timelineData.reduce((sum, point) => sum + (point.bytes || 0), 0);
  const avgPackets = timelineData.length > 0 ? Math.round(totalPackets / timelineData.length) : 0;
  const packetCounts = timelineData.map(p => p.packetCount || 0).filter(n => !isNaN(n));
  const maxPackets = packetCounts.length > 0 ? Math.max(...packetCounts) : 0;

  if (loadingStory) {
    return (
      <div className="text-center py-5">
        <LoadingSpinner size="large" message="Loading story..." />
      </div>
    );
  }

  if (generating && !story) {
    const minutes = Math.floor(elapsedSeconds / 60);
    const seconds = elapsedSeconds % 60;
    const elapsed = minutes > 0
      ? `${minutes}m ${seconds.toString().padStart(2, '0')}s`
      : `${seconds}s`;
    const timeoutMinutes = Math.round(llmTimeoutMs / 60000);
    return (
      <div className="text-center py-5">
        <LoadingSpinner
          size="large"
          message="Generating narrative story... This may take a few moments."
        />
        <p className="text-muted mt-3">
          AI is analyzing the network traffic and creating a comprehensive narrative...
        </p>
        <p className="text-muted small mt-1">
          Elapsed: <strong>{elapsed}</strong> &nbsp;|&nbsp; Timeout: {timeoutMinutes} min
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
      <div className="py-4">
        <div className="mb-4">
          <StoryInfoCard
            additionalContext={additionalContext}
            onAdditionalContextChange={setAdditionalContext}
          />
        </div>

        <div className="text-center">
          <h4>No Story Generated Yet</h4>
          <p className="text-muted mb-4">
            Generate an AI-powered narrative analysis of this network capture
          </p>
          <button className="btn btn-primary" onClick={handleGenerateStory}>
            <i className="bi bi-magic me-2"></i>
            Generate Story
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="story-page">
      {/* Header */}
      <div className="row mb-4">
        <div className="col-12">
          <div className="d-flex align-items-center justify-content-between">
            <h4 className="mb-0">Network Traffic Story</h4>
            <button
              className="btn btn-outline-primary btn-sm"
              onClick={handleGenerateStory}
              disabled={generating}
              title={generating ? 'Generating...' : 'Regenerate'}
            >
              <i className={`bi bi-arrow-clockwise${generating ? ' spin' : ''} me-1`}></i>
              {generating ? 'Generating...' : 'Regenerate'}
            </button>
          </div>
        </div>
      </div>

      {/* How stories are generated */}
      <div className="row mb-4">
        <div className="col-12">
          <StoryInfoCard
            additionalContext={additionalContext}
            onAdditionalContextChange={setAdditionalContext}
          />
        </div>
      </div>

      {/* Story Q&A */}
      <div className="row mb-4">
        <div className="col-12">
          <StoryChat storyId={story.id} suggestedQuestions={story.suggestedQuestions} />
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
                <TrafficTimeline
                  data={timelineData}
                  granularity={granularity}
                  onGranularityChange={setGranularity}
                />
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
