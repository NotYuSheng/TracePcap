import { useState, useEffect, useRef, useCallback } from 'react';
import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';
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
import { StoryTimeline } from '@components/story/StoryTimeline';
import { StoryInfoCard } from '@components/story/StoryInfoCard';
import { StoryChat } from '@components/story/StoryChat';
import { AggregatesPanel } from '@components/story/AggregatesPanel';
import { FindingsPanel } from '@components/story/FindingsPanel';
import { InvestigationPanel } from '@components/story/InvestigationPanel';
import { TrafficTimeline } from '@components/timeline/TrafficTimeline';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

function NarrativeInfoPopover() {
  const popover = (
    <Popover id="info-narrative" style={{ maxWidth: '340px' }}>
      <Popover.Header>Narrative — How it works</Popover.Header>
      <Popover.Body className="small">
        <p className="mb-2">
          The narrative is written by the LLM using deterministic findings computed from the full
          dataset — it writes prose, not analysis. Every CRITICAL and HIGH finding is guaranteed to
          appear in at least one highlight and timeline event.
        </p>
        <p className="mb-2">
          <strong>Not included:</strong> packet payloads, HTTP bodies, DNS query names, TLS SNI, or
          raw conversation lists (replaced by structured findings).
        </p>
        <p className="mb-0">
          <strong>Limitations:</strong> Treat this as a starting point for investigation. The LLM
          cannot invent findings not listed in the Deterministic Findings panel above.
        </p>
      </Popover.Body>
    </Popover>
  );
  return (
    <OverlayTrigger trigger="click" placement="right" overlay={popover} rootClose>
      <button
        type="button"
        className="btn btn-link p-0 text-muted ms-2"
        style={{ lineHeight: 1 }}
        aria-label="About Narrative"
      >
        <i className="bi bi-info-circle" style={{ fontSize: '0.9rem' }}></i>
      </button>
    </OverlayTrigger>
  );
}

export const StoryPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>();
  const [story, setStory] = useState<Story | null>(null);
  const [timelineData, setTimelineData] = useState<TimelineDataPoint[]>([]);
  const [granularity, setGranularity] = useState<number | 'auto'>('auto');
  const [additionalContext, setAdditionalContext] = useState('');
  const [maxFindings, setMaxFindings] = useState(20);
  const [maxRiskMatrix, setMaxRiskMatrix] = useState(15);
  const [totalFindings, setTotalFindings] = useState<number | undefined>(undefined);
  const [totalRiskMatrix, setTotalRiskMatrix] = useState<number | undefined>(undefined);
  const [generating, setGenerating] = useState(false);
  const [loadingStory, setLoadingStory] = useState(true);
  const [loadingTimeline, setLoadingTimeline] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [contextError, setContextError] = useState<{
    promptText: string;
    promptTokens: number;
    contextLength: number;
  } | null>(null);
  const [editablePrompt, setEditablePrompt] = useState('');
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [llmTimeoutMs, setLlmTimeoutMs] = useState<number>(300000);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    apiClient
      .get<{ llmTimeoutMs?: number }>('/system/limits')
      .then(res => {
        if (res.data.llmTimeoutMs) setLlmTimeoutMs(res.data.llmTimeoutMs);
      })
      .catch(() => {
        /* keep default */
      });
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

  const handleGenerateStory = useCallback(async (customPrompt?: string) => {
    try {
      setGenerating(true);
      setError(null);
      setContextError(null);
      const generatedStory = await storyService.generateStory(
        fileId,
        additionalContext,
        llmTimeoutMs,
        customPrompt,
        maxFindings,
        maxRiskMatrix
      );
      setStory(generatedStory);
      if (generatedStory.findings?.length) setTotalFindings(generatedStory.findings.length);
      if (generatedStory.aggregates?.protocolRiskMatrix?.length) setTotalRiskMatrix(generatedStory.aggregates.protocolRiskMatrix.length);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const status = (err as { response?: { status?: number } })?.response?.status;
      const data = (err as { response?: { data?: Record<string, unknown> } })?.response?.data ?? {};
      const serverMsg: string = (data.message as string) ?? '';
      const isTimeout = (err as { code?: string })?.code === 'ECONNABORTED' || msg.toLowerCase().includes('timeout');
      if (data.errorCode === 'CONTEXT_LENGTH_EXCEEDED') {
        setContextError({
          promptText: (data.promptText as string) ?? '',
          promptTokens: (data.promptTokens as number) ?? 0,
          contextLength: (data.contextLength as number) ?? 0,
        });
        setEditablePrompt((data.promptText as string) ?? '');
      } else if (isTimeout) {
        const minutes = Math.round(llmTimeoutMs / 60000);
        setError(
          `Story generation timed out after ${minutes} minute${minutes !== 1 ? 's' : ''}. The LLM is taking too long to respond. Try again or reduce the capture size.`
        );
      } else if (status === 502 || serverMsg.toLowerCase().includes('llm') || serverMsg.toLowerCase().includes('reach')) {
        setError(
          'The LLM server is not responding. Make sure the LLM service is running and reachable, then try again.'
        );
      } else {
        setError(serverMsg || msg || 'Failed to generate story');
      }
    } finally {
      setGenerating(false);
    }
  }, [fileId, additionalContext, llmTimeoutMs, maxFindings, maxRiskMatrix]);

  useEffect(() => {
    const fetchExistingStory = async () => {
      try {
        setLoadingStory(true);
        const existing = await storyService.getStoryByFileId(fileId);
        if (existing) {
          setStory(existing);
          if (existing.findings?.length) setTotalFindings(existing.findings.length);
          if (existing.aggregates?.protocolRiskMatrix?.length) setTotalRiskMatrix(existing.aggregates.protocolRiskMatrix.length);
        }
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
    const elapsed =
      minutes > 0 ? `${minutes}m ${seconds.toString().padStart(2, '0')}s` : `${seconds}s`;
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

  if (contextError && !story) {
    const remaining = contextError.contextLength - contextError.promptTokens;
    return (
      <div className="py-4">
        <div className="alert alert-danger mb-3" role="alert">
          <h5 className="alert-heading">
            <i className="bi bi-exclamation-triangle-fill me-2"></i>
            Prompt Too Large for Model
          </h5>
          <p className="mb-0">
            The prompt used <strong>{contextError.promptTokens.toLocaleString()}</strong> tokens
            but the model's context window is{' '}
            <strong>{contextError.contextLength.toLocaleString()}</strong> tokens, leaving only{' '}
            <strong>{remaining.toLocaleString()}</strong> for the response.
          </p>
        </div>
        <p className="text-muted small mb-2">
          Edit the prompt below to reduce its size (e.g. remove findings or aggregates sections),
          then retry:
        </p>
        <textarea
          className="form-control form-control-sm font-monospace mb-3"
          rows={20}
          value={editablePrompt}
          onChange={e => setEditablePrompt(e.target.value)}
        />
        <div className="d-flex gap-2">
          <button
            className="btn btn-primary"
            onClick={() => handleGenerateStory(editablePrompt)}
            disabled={generating}
          >
            <i className="bi bi-arrow-repeat me-2"></i>
            Retry with edited prompt
          </button>
          <button
            className="btn btn-outline-secondary"
            onClick={() => { setContextError(null); setEditablePrompt(''); }}
            disabled={generating}
          >
            Start over
          </button>
        </div>
      </div>
    );
  }

  if (error && !story) {
    return (
      <ErrorMessage
        title="Failed to Generate Story"
        message={error}
        onRetry={() => handleGenerateStory()}
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
            maxFindings={maxFindings}
            onMaxFindingsChange={setMaxFindings}
            totalFindings={totalFindings}
            maxRiskMatrix={maxRiskMatrix}
            onMaxRiskMatrixChange={setMaxRiskMatrix}
            totalRiskMatrix={totalRiskMatrix}
          />
        </div>

        <div className="text-center">
          <h4>No Story Generated Yet</h4>
          <p className="text-muted mb-4">
            Generate an AI-powered narrative analysis of this network capture
          </p>
          <button className="btn btn-primary" onClick={() => handleGenerateStory()}>
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
              onClick={() => handleGenerateStory()}
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
            maxFindings={maxFindings}
            onMaxFindingsChange={setMaxFindings}
            totalFindings={totalFindings}
            maxRiskMatrix={maxRiskMatrix}
            onMaxRiskMatrixChange={setMaxRiskMatrix}
            totalRiskMatrix={totalRiskMatrix}
          />
        </div>
      </div>

      {/* Story Q&A */}
      <div className="row mb-4">
        <div className="col-12">
          <StoryChat storyId={story.id} suggestedQuestions={story.suggestedQuestions} />
        </div>
      </div>

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

      {/* Aggregates Panel — pre-computed full-dataset analytics */}
      {story.aggregates && (
        <div className="row mb-4">
          <div className="col-12">
            <AggregatesPanel aggregates={story.aggregates} />
          </div>
        </div>
      )}

      {/* Findings Panel — deterministic detector output */}
      {story.findings && story.findings.length > 0 && (
        <div className="row mb-4">
          <div className="col-12">
            <FindingsPanel findings={story.findings} />
          </div>
        </div>
      )}

      {/* Investigation Panel — LLM-directed retrieval results */}
      {story.investigationSteps && story.investigationSteps.length > 0 && (
        <div className="row mb-4">
          <div className="col-12">
            <InvestigationPanel steps={story.investigationSteps} />
          </div>
        </div>
      )}

      {/* Narrative and Event Timeline */}
      <div className="row">
        {/* Narrative Section */}
        <div className="col-lg-8">
          <h5 className="mb-3 d-flex align-items-center">
            Narrative
            <NarrativeInfoPopover />
          </h5>
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
