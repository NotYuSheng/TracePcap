import { SideDrawer } from '@components/common/SideDrawer';
import { useState, useEffect, useMemo, useRef } from 'react';
import { useNetworkContext } from '@/features/detectionRules/useNetworkContext';
import { Button, Card, Form, Modal } from '@govtechsg/sgds-react';
import { PermissionLock } from '@components/common/PermissionLock';
import { usePermission } from '@/features/me/useMe';
import { Alert } from '@components/common/Alert';
import { createPortal } from 'react-dom';
import { useOutletContext } from 'react-router-dom';
import type { Answer, CaptureContext, CategoryStatus, GoalOutcome, Honeypots, TimelineDataPoint } from '@/types';
import type { AnalysisOutletContext } from '@/pages/Analysis/AnalysisPage';
import { timelineService } from '@/features/timeline/services/timelineService';
import { storyService } from '@/features/story/services/storyService';
import {
  AUTO_GRANULARITY_INTERVAL,
  AUTO_GRANULARITY_MAX_DATAPOINTS,
} from '@/features/timeline/constants';
import { StoryProgress } from '@components/story/StoryProgress/StoryProgress';
import { AiJobStatus } from '@components/common/AiJobStatus/AiJobStatus';
import { placeInLine } from '@/features/aiJobs/aiJobText';
import { StorySummary } from '@components/story/StorySummary';
import { StoryNarrative } from '@components/story/StoryNarrative';
import { StoryHowItWorks, StoryPromptSettings } from '@components/story/StoryInfoCard';
import { StoryChat } from '@components/story/StoryChat';
import { AggregatesPanel } from '@components/story/AggregatesPanel';
import { FindingsPanel } from '@components/story/FindingsPanel';
import { InvestigationPanel } from '@components/story/InvestigationPanel';
import { TrafficTimeline } from '@components/timeline/TrafficTimeline';
import { ErrorMessage } from '@components/common/ErrorMessage';
import './StoryPage.css';

type EvidenceTab = 'findings' | 'aggregates' | 'investigation' | 'traffic';

const written = (ms: number) =>
  new Date(ms).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });

/**
 * Story mode, laid out as an investigation: where it stands first (summary-first, design F), the
 * narrative told as a timeline, Q&A open beside it, and the evidence the story rests on in tabs
 * underneath. Settings live in the Regenerate dialog rather than on the page.
 */
/** Where the chat column sticks: just under the top bar (matches .story-aside's top). */
const STICKY_TOP = 96;

export const StoryPage = () => {
  const { fileId, storyState, asideSlot } = useOutletContext<AnalysisOutletContext>();
  const [networkContext] = useNetworkContext();
  const {
    story, generating, error,
    contextError, setContextError,
    editablePrompt, setEditablePrompt,
    elapsedSeconds, llmTimeoutMs,
    generateStory: handleGenerateStory,
    additionalContext, setAdditionalContext,
    maxFindings, setMaxFindings,
    maxRiskMatrix, setMaxRiskMatrix,
    totalFindings,
    totalRiskMatrix,
    background,
    job,
    cancelJob,
  } = storyState;

  const [timelineData, setTimelineData] = useState<TimelineDataPoint[]>([]);
  const [granularity, setGranularity] = useState<number | 'auto'>('auto');
  const [loadingTimeline, setLoadingTimeline] = useState(true);
  const [goals, setGoals] = useState<GoalOutcome[]>([]);
  const [additional, setAdditional] = useState<Answer[]>([]);
  const [categories, setCategories] = useState<CategoryStatus[] | null>(null);
  const [captureContext, setCaptureContext] = useState<CaptureContext | null>(null);
  const [honeypots, setHoneypots] = useState<Honeypots | null>(null);
  // Bumped when an analyst overrides or adds evidence to the capture context or a host's honeypot
  // role, to re-read it.
  const [investigationRev, setInvestigationRev] = useState(0);
  const loadedFileId = useRef<string | null>(null);
  const [goalsLoaded, setGoalsLoaded] = useState(false);
  const [showRegenerate, setShowRegenerate] = useState(false);
  const ai = usePermission('ASK_AI');
  const [showHowItWorks, setShowHowItWorks] = useState(false);
  const [evidenceTab, setEvidenceTab] = useState<EvidenceTab | null>(null);

  // The chat column fills the visible part of the story grid: from the grid's top (or the sticky
  // line under the header, once scrolled past it) to the window's bottom (or the grid's end, near
  // the footer). Both move while the page scrolls, so it is measured rather than set in CSS.
  const asideRef = useRef<HTMLElement>(null);
  const hasStory = !!story;
  useEffect(() => {
    const el = asideRef.current;
    // Docked in the page's own column, the chat is that column's height: nothing to measure.
    if (!el || asideSlot) return;
    let frame = 0;
    const fit = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const grid = (el.parentElement ?? el).getBoundingClientRect();
        const start = Math.max(grid.top, STICKY_TOP);
        const end = Math.min(window.innerHeight - 16, grid.bottom);
        el.style.setProperty('--story-chat-h', `${Math.max(360, end - start)}px`);
      });
    };
    fit();
    window.addEventListener('scroll', fit, { passive: true });
    window.addEventListener('resize', fit);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('scroll', fit);
      window.removeEventListener('resize', fit);
    };
  }, [hasStory, asideSlot]);

  // The investigation as reported — every goal with its outcome — so a conclusion reached by
  // following a lead (a beacon classified as a C2 with no IDS rule) shows on its card too.
  useEffect(() => {
    let alive = true;
    // Only a new capture shows the loading state: re-reading after an override keeps the summary
    // (and the modal the analyst is in) on screen.
    const refresh = loadedFileId.current === fileId;
    if (!refresh) setGoalsLoaded(false);
    loadedFileId.current = fileId;
    storyService
      .getInvestigationReport(fileId)
      .then(r => {
        if (!alive) return;
        setGoals(r.goals);
        setAdditional(r.additional);
        setCategories(r.categories ?? null);
        setCaptureContext(r.context ?? null);
        setHoneypots(r.honeypots ?? null);
      })
      .catch(() => {
        // A failed re-read keeps what was shown; only a new capture starts from nothing.
        if (!alive || refresh) return;
        setGoals([]);
        setAdditional([]);
        setCategories(null);
        setCaptureContext(null);
        setHoneypots(null);
      })
      .finally(() => { if (alive) setGoalsLoaded(true); });
    return () => { alive = false; };
  }, [fileId, investigationRev]);

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        setLoadingTimeline(true);
        const data =
          granularity === 'auto'
            ? await timelineService.getTimelineData(fileId, AUTO_GRANULARITY_INTERVAL, AUTO_GRANULARITY_MAX_DATAPOINTS)
            : await timelineService.getTimelineData(fileId, granularity);
        setTimelineData(data);
      } catch (err) {
        console.error('Failed to load timeline:', err);
      } finally {
        setLoadingTimeline(false);
      }
    };
    if (fileId) fetchTimeline();
  }, [fileId, granularity]);

  // The evidence tabs that have something in them (above the early returns: hooks can't follow them).
  const tabs = useMemo(() => {
    const t: { id: EvidenceTab; label: string; count?: number }[] = [];
    if (story?.findings?.length) t.push({ id: 'findings', label: 'Findings', count: story.findings.length });
    if (story?.aggregates) t.push({ id: 'aggregates', label: 'Traffic intelligence' });
    if (story?.investigationSteps?.length)
      t.push({ id: 'investigation', label: 'LLM investigation', count: story.investigationSteps.length });
    if (!loadingTimeline && timelineData.length > 0) t.push({ id: 'traffic', label: 'Traffic over time' });
    return t;
  }, [story, loadingTimeline, timelineData.length]);
  const activeTab = tabs.find(t => t.id === evidenceTab)?.id ?? tabs[0]?.id;

  const settings = (
    <StoryPromptSettings
      additionalContext={additionalContext}
      onAdditionalContextChange={setAdditionalContext}
      maxFindings={maxFindings}
      onMaxFindingsChange={setMaxFindings}
      totalFindings={totalFindings}
      maxRiskMatrix={maxRiskMatrix}
      onMaxRiskMatrixChange={setMaxRiskMatrix}
      totalRiskMatrix={totalRiskMatrix}
    />
  );

  // Where the investigation stands needs no model, so it shows before a story is written too.
  const summary = (
    <StorySummary
      fileId={fileId}
      goals={goals}
      additional={additional}
      categories={categories}
      context={captureContext}
      honeypots={honeypots}
      onContextChanged={() => setInvestigationRev(r => r + 1)}
      loading={!goalsLoaded}
    />
  );

  const howItWorks = (
    <Modal show={showHowItWorks} onHide={() => setShowHowItWorks(false)} size="lg" scrollable>
      <Modal.Header closeButton>
        <Modal.Title>How the story is written</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <StoryHowItWorks />
      </Modal.Body>
    </Modal>
  );

  // No story yet, and one is waiting for the model: say where it is in line.
  if (generating && !story && job?.status === 'WAITING') {
    return (
      <div className="story-start">
        {summary}
        <Card className="story-start-card" data-testid="story-waiting">
          <Card.Body>
            <span className="story-pill story-pill-writing">Queued</span>
            <h1 className="story-start-title">The story is waiting its turn</h1>
            <p className="text-muted">
              {job.trigger === 'UPLOAD'
                ? 'It was asked for when this capture was uploaded. '
                : ''}
              The model writes one thing at a time and this is {placeInLine(job.position)}. You can
              leave this page; it shows here when it is ready.
            </p>
            {job.trigger !== 'UPLOAD' && (
              <Button variant="outline-secondary" size="sm" onClick={() => cancelJob()}>
                Cancel
              </Button>
            )}
          </Card.Body>
        </Card>
      </div>
    );
  }

  if (generating && !story) {
    const timeoutSec = Math.round(llmTimeoutMs / 1000);
    const timeoutLabel = timeoutSec < 60 ? `${timeoutSec}s` : `${Math.round(timeoutSec / 60)} min`;
    return <StoryProgress elapsedSeconds={elapsedSeconds} timeoutLabel={timeoutLabel} />;
  }

  if (contextError && !story) {
    const remaining = contextError.contextLength - contextError.promptTokens;
    return (
      <div className="py-4">
        <Alert variant="danger" className="mb-3">
          <Alert.Heading>
            <i className="bi bi-exclamation-triangle-fill me-2"></i>
            Prompt Too Large for Model
          </Alert.Heading>
          <p className="mb-0">
            The prompt used <strong>{contextError.promptTokens.toLocaleString()}</strong> tokens
            but the model's context window is{' '}
            <strong>{contextError.contextLength.toLocaleString()}</strong> tokens, leaving only{' '}
            <strong>{remaining.toLocaleString()}</strong> for the response.
          </p>
        </Alert>
        <p className="text-muted small mb-2">
          Edit the prompt below to reduce its size (e.g. remove findings or aggregates sections),
          then retry:
        </p>
        <Form.Control
          as="textarea"
          size="sm"
          className="font-monospace mb-3"
          rows={20}
          value={editablePrompt}
          onChange={e => setEditablePrompt(e.target.value)}
        />
        <div className="d-flex gap-2">
          <Button
            variant="primary"
            onClick={() => handleGenerateStory(editablePrompt)}
            disabled={generating}
          >
            <i className="bi bi-arrow-repeat me-2"></i>
            Retry with edited prompt
          </Button>
          <Button
            variant="outline-secondary"
            onClick={() => { setContextError(null); setEditablePrompt(''); }}
            disabled={generating}
          >
            Start over
          </Button>
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

  // Asked for at upload and still on its way: the page fills in by itself when it lands.
  if (!story && background && background.status !== 'FAILED') {
    return (
      <div className="story-start">
        {summary}
        <Card className="story-start-card" data-testid="story-background">
          <Card.Body>
            <span className="story-pill story-pill-writing">
              {background.status === 'QUEUED' ? 'Queued' : 'Writing…'}
            </span>
            <h1 className="story-start-title">
              {background.status === 'QUEUED'
                ? 'The story is waiting its turn'
                : 'The story is being written'}
            </h1>
            <p className="text-muted mb-0">
              It was asked for when this capture was uploaded and is written in the background, one
              capture at a time. You can leave this page; it shows here when it is ready.
            </p>
          </Card.Body>
        </Card>
      </div>
    );
  }

  // The chat is there before a story is: it answers from the findings and its tools (#1161).
  // On a wide screen it sits in the analysis page's own column, beside the capture bar and the
  // story and the window's full height; otherwise beside or under the story, as before.
  const chatPanel = (
    <StoryChat
      fileId={fileId}
      networkId={networkContext}
      suggestedQuestions={story?.suggestedQuestions}
      hasStory={!!story}
    />
  );
  const chat = asideSlot ? (
    createPortal(<aside className="story-aside story-aside-docked">{chatPanel}</aside>, asideSlot)
  ) : (
    <aside className="story-aside" ref={asideRef}>
      {chatPanel}
    </aside>
  );
  const gridClass = asideSlot ? 'story-grid story-grid-docked' : 'story-grid';

  if (!story) {
    return (
      <div className={gridClass}>
      <div className="story-start">
        {summary}
        {background?.status === 'FAILED' && (
          <Alert variant="warning" className="mb-3">
            The story asked for at upload couldn&apos;t be written
            {background.error ? <>: {background.error.replace(/\.?\s*$/, '')}</> : ''}. Try again below.
          </Alert>
        )}
        <Card className="story-start-card">
          <Card.Body>
            <span className="story-pill">No story yet</span>
            <h1 className="story-start-title">Have the LLM write this capture's story</h1>
            <p className="text-muted">
              It reads the findings TracePcap measured (not raw packets) and tells you what happened, in
              order, with what to look at next. A few minutes on a local model.{' '}
              <Button variant="link" className="p-0 align-baseline" onClick={() => setShowHowItWorks(true)}>
                How it works
              </Button>
            </p>
            {settings}
            <Button variant="primary" className="mt-3" onClick={() => handleGenerateStory()} disabled={!ai.allowed}>
              <i className="bi bi-stars me-2" aria-hidden="true"></i>
              Write the story
            </Button>
            <PermissionLock action="ASK_AI" className="ms-2 mt-3" />
          </Card.Body>
        </Card>
        {howItWorks}
      </div>
      {chat}
      </div>
    );
  }

  return (
    <div className="story-page">
      <div className="story-head">
        <div className="story-head-text">
          <h1 className="story-title">Story</h1>
          <small className="text-muted" data-testid="story-rules-scope">
            Written {written(story.generatedAt)} ·{' '}
            {story.networkId
              ? <>uses the shared detection rules and <strong>{story.networkName ?? 'a network'}</strong>'s own.</>
              : <>Uses the shared detection rules. Pick a network under “Custom detection rules” and regenerate to include its rules.</>}
          </small>
        </div>
        <Button variant="link" size="sm" onClick={() => setShowHowItWorks(true)}>
          How it works
        </Button>
        <Button variant="outline-primary" size="sm" onClick={() => setShowRegenerate(true)} disabled={generating || !ai.allowed}>
          <i className={`bi bi-arrow-clockwise${generating ? ' spin' : ''} me-1`} aria-hidden="true"></i>
          {generating ? 'Writing…' : 'Regenerate…'}
        </Button>
        <PermissionLock action="ASK_AI" />
      </div>

      {error && (
        <Alert variant="danger" className="py-2 mb-3">
          <i className="bi bi-exclamation-triangle-fill me-2" aria-hidden="true"></i>
          {error}
        </Alert>
      )}

      <div className={gridClass}>
        <div className="story-main">
          {summary}

          {generating && job && (
            <AiJobStatus
              job={job}
              doing="Rewriting the story"
              whenDone="The new story replaces this one when it's ready."
              onCancel={() => cancelJob()}
            />
          )}

          <Card className="story-card">
            <Card.Body>
              <h2 className="story-card-title">The story</h2>
              <StoryNarrative sections={story.narrative} events={story.timeline ?? []} />
            </Card.Body>
          </Card>

          {tabs.length > 0 && activeTab && (
            <Card className="story-card">
              <div className="story-tabs" role="tablist" aria-label="What the story rests on">
                {tabs.map(t => (
                  <button
                    key={t.id}
                    type="button"
                    role="tab"
                    aria-selected={activeTab === t.id}
                    className={`story-tab${activeTab === t.id ? ' active' : ''}`}
                    onClick={() => setEvidenceTab(t.id)}
                  >
                    {t.label}
                    {t.count !== undefined && <span className="story-tab-count">{t.count}</span>}
                  </button>
                ))}
              </div>
              <div className="story-tab-body" role="tabpanel">
                {activeTab === 'findings' && story.findings && <FindingsPanel findings={story.findings} />}
                {activeTab === 'aggregates' && story.aggregates && <AggregatesPanel aggregates={story.aggregates} />}
                {activeTab === 'investigation' && story.investigationSteps && (
                  <InvestigationPanel steps={story.investigationSteps} />
                )}
                {activeTab === 'traffic' && (
                  <TrafficTimeline data={timelineData} granularity={granularity} onGranularityChange={setGranularity} />
                )}
              </div>
            </Card>
          )}
        </div>

        {chat}
      </div>

      <SideDrawer
        show={showRegenerate}
        onHide={() => setShowRegenerate(false)}
        title="Regenerate the story"
        titleId="regenerate-story-title"
        wide
        footer={
          <>
            <Button variant="outline-secondary" onClick={() => setShowRegenerate(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={() => {
                setShowRegenerate(false);
                handleGenerateStory();
              }}
            >
              Regenerate
            </Button>
          </>
        }
      >
        <p className="text-muted small mb-0">
          The LLM writes the story again from the current findings. Tell it anything it can't see, or
          lower the limits if the last attempt ran out of context.
        </p>
        {settings}
      </SideDrawer>
      {howItWorks}
    </div>
  );
};
