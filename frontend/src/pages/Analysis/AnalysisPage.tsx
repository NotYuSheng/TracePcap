import { AnalysisRail, type RailItem } from './AnalysisRail';
import { FavouriteStar } from '@/features/captureKeep/FavouriteStar';
import { useNetworkContext } from '@/features/detectionRules/useNetworkContext';
import { NetworkContextPicker } from '@/features/detectionRules/NetworkContextPicker';
import { describeLlmError } from '@utils/llmError';
import {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
  type Dispatch,
  type SetStateAction,
} from 'react';
import { Button, Card } from '@govtechsg/sgds-react';
import { Link, useParams, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAnalysisData } from '@features/analysis/hooks/useAnalysisData';
import { useNetworkDiagramFilterState } from '@/features/network/hooks/useNetworkDiagramFilterState';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { AnalysisLoadingView } from './AnalysisLoadingView';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { storyService } from '@/features/story/services/storyService';
import { aiJobsService } from '@/features/aiJobs/aiJobsService';
import { useAiJob } from '@/features/aiJobs/useAiJob';
import { useNow } from '@/features/aiJobs/useNow';
import type { AiJob } from '@/features/aiJobs/aiJobs.types';
import type { Story } from '@/types';
import { ReportDrawer } from '@/features/report/ReportDrawer';
import type { DeviceLink, GraphNode, GraphEdge } from '@/features/network/types';
import type { AnalysisData } from '@/types';
import { formatSpan } from '@/utils/formatters';

export interface NetworkGraphState {
  filteredNodes: GraphNode[];
  filteredEdges: GraphEdge[];
  activeFilterLabels: string[];
  nodeLimitNote: string | null;
  /** Same-device links between nodes shown, so the report's map draws them too. */
  deviceLinks?: DeviceLink[];
}

export interface NetworkDiagramFilterState {
  nodeLimit: number;
  setNodeLimit: Dispatch<SetStateAction<number>>;
  ipFilter: string;
  setIpFilter: Dispatch<SetStateAction<string>>;
  portFilter: string;
  setPortFilter: Dispatch<SetStateAction<string>>;
  hasRisksOnly: boolean;
  setHasRisksOnly: Dispatch<SetStateAction<boolean>>;
  activeLegendProtocols: string[];
  setActiveLegendProtocols: Dispatch<SetStateAction<string[]>>;
  activeNodeFilters: string[];
  setActiveNodeFilters: Dispatch<SetStateAction<string[]>>;
  activeAppFilters: string[];
  setActiveAppFilters: Dispatch<SetStateAction<string[]>>;
  activeL7Protocols: string[];
  setActiveL7Protocols: Dispatch<SetStateAction<string[]>>;
  activeCategories: string[];
  setActiveCategories: Dispatch<SetStateAction<string[]>>;
  activeRiskTypes: string[];
  setActiveRiskTypes: Dispatch<SetStateAction<string[]>>;
  activeCustomSigs: string[];
  setActiveCustomSigs: Dispatch<SetStateAction<string[]>>;
  activeFileTypes: string[];
  setActiveFileTypes: Dispatch<SetStateAction<string[]>>;
  activeCountries: string[];
  setActiveCountries: Dispatch<SetStateAction<string[]>>;
  activeGhostFilters: string[];
  setActiveGhostFilters: Dispatch<SetStateAction<string[]>>;
}

export interface StoryGenerationState {
  story: Story | null;
  setStory: Dispatch<SetStateAction<Story | null>>;
  generating: boolean;
  generateStory: (customPrompt?: string) => Promise<void>;
  error: string | null;
  setError: Dispatch<SetStateAction<string | null>>;
  contextError: { promptText: string; promptTokens: number; contextLength: number } | null;
  setContextError: Dispatch<
    SetStateAction<{ promptText: string; promptTokens: number; contextLength: number } | null>
  >;
  editablePrompt: string;
  setEditablePrompt: Dispatch<SetStateAction<string>>;
  elapsedSeconds: number;
  llmTimeoutMs: number;
  additionalContext: string;
  setAdditionalContext: Dispatch<SetStateAction<string>>;
  maxFindings: number;
  setMaxFindings: Dispatch<SetStateAction<number>>;
  maxRiskMatrix: number;
  setMaxRiskMatrix: Dispatch<SetStateAction<number>>;
  totalFindings: number | undefined;
  setTotalFindings: Dispatch<SetStateAction<number | undefined>>;
  totalRiskMatrix: number | undefined;
  setTotalRiskMatrix: Dispatch<SetStateAction<number | undefined>>;
  /** The story asked for at upload, while it is on its way (or if it failed). */
  background: { status: 'QUEUED' | 'WRITING' | 'FAILED'; error?: string | null } | null;
  /** The story being written in the background (waiting for the model, or running), if any. */
  job: AiJob | null;
  /** Takes a waiting story out of line. */
  cancelJob: () => Promise<void>;
}

export interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
  networkGraphStateRef: React.MutableRefObject<NetworkGraphState>;
  networkDiagramFilters: NetworkDiagramFilterState;
  storyState: StoryGenerationState;
  /** Reloads the summary without blanking the page, e.g. after a rule change (#925). */
  refreshSummary: () => void;
  /**
   * The column beside the whole page, the capture bar included, on sections that have one (Story's
   * chat). A section portals into it; null where there's no such column.
   */
  asideSlot: HTMLElement | null;
}

// Re-export so NetworkDiagramPage can import from one place
export type { AnalysisData };

/** The analysis page's sections, in rail order. */
const RAIL_ITEMS: RailItem[] = [
  { key: 'overview', label: 'Overview', short: 'Overview', icon: 'bi-speedometer2' },
  {
    key: 'conversations',
    label: 'Conversations',
    short: 'Conversations',
    icon: 'bi-arrow-left-right',
  },
  { key: 'story', label: 'Story', short: 'Story', icon: 'bi-journal-text' },
  {
    key: 'network-diagram',
    label: 'Network Visualization',
    short: 'Network',
    icon: 'bi-diagram-3',
  },
  {
    key: 'extracted-files',
    label: 'Extracted Files',
    short: 'Files',
    icon: 'bi-file-earmark-arrow-down',
  },
  {
    key: 'file',
    label: 'Capture, rules and report',
    short: 'Capture',
    icon: 'bi-file-earmark-binary',
  },
];

/** "913 packets · 26 min" for the capture bar. */
function captureFacts(d: { totalPackets?: number; timeRange?: [number, number] }): string {
  const parts: string[] = [];
  if (d.totalPackets != null) parts.push(`${d.totalPackets.toLocaleString()} packets`);
  if (d.timeRange && d.timeRange[1] > d.timeRange[0]) {
    parts.push(formatSpan(d.timeRange[1] - d.timeRange[0]));
  }
  return parts.join(' · ');
}

export const AnalysisPage = () => {
  const { fileId } = useParams<{ fileId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { data, loading, error, refetch } = useAnalysisData(fileId!);
  const [activeTab, setActiveTab] = useState('overview');
  // The "Viewing with" network (#925): the report includes its rules' matches.
  const [networkContext] = useNetworkContext();
  // Story's chat gets a column of its own beside the capture bar and the story, the window's full
  // height. Rendered only on the Story tab; null elsewhere.
  const [asideSlot, setAsideSlot] = useState<HTMLElement | null>(null);
  const [showReport, setShowReport] = useState(false);

  // ── Story generation state (lifted here so it survives tab switches) ──────
  const [story, setStory] = useState<Story | null>(null);
  const [storyError, setStoryError] = useState<string | null>(null);
  const [storyContextError, setStoryContextError] = useState<{
    promptText: string;
    promptTokens: number;
    contextLength: number;
  } | null>(null);
  const [storyEditablePrompt, setStoryEditablePrompt] = useState('');
  const [llmTimeoutMs, setLlmTimeoutMs] = useState<number>(300000);
  const [additionalContext, setAdditionalContext] = useState('');
  const [maxFindings, setMaxFindings] = useState(20);
  const [maxRiskMatrix, setMaxRiskMatrix] = useState(15);
  const [totalFindings, setTotalFindings] = useState<number | undefined>(undefined);
  const [totalRiskMatrix, setTotalRiskMatrix] = useState<number | undefined>(undefined);

  useEffect(() => {
    apiClient
      .get<{ llmTimeoutMs?: number }>('/system/limits')
      .then(res => {
        if (res.data.llmTimeoutMs) setLlmTimeoutMs(res.data.llmTimeoutMs);
      })
      .catch(() => {});
  }, []);

  // The story is written in the background, one AI job at a time: the page follows the job, so
  // leaving or reloading the page doesn't lose it, and the current story stays until it's replaced.
  const [background, setBackground] = useState<StoryGenerationState['background']>(null);
  const storyJob = useAiJob<Story | null>('STORY', fileId, {
    onDone: written => {
      setBackground(null);
      if (!written) return;
      setStory(written);
      if (written.findings?.length) setTotalFindings(written.findings.length);
      if (written.aggregates?.protocolRiskMatrix?.length)
        setTotalRiskMatrix(written.aggregates.protocolRiskMatrix.length);
    },
    onFailed: job => {
      const e = job.error ?? {};
      if (job.trigger === 'UPLOAD') {
        setBackground({ status: 'FAILED', error: e.message });
      } else if (e.errorCode === 'CONTEXT_LENGTH_EXCEEDED') {
        setStoryContextError({
          promptText: e.promptText ?? '',
          promptTokens: e.promptTokens ?? 0,
          contextLength: e.contextLength ?? 0,
        });
        setStoryEditablePrompt(e.promptText ?? '');
      } else {
        setStoryError(
          describeLlmError(
            { response: { data: { errorCode: e.errorCode, message: e.message } } },
            {
              subject: 'Story generation',
              timeoutMs: llmTimeoutMs,
              timeoutHint: 'reduce the capture size',
              fallback: 'Failed to generate story',
            }
          )
        );
      }
    },
  });
  const storyGenerating = storyJob.active;
  const storyStartedAt = storyJob.job?.startedAt ?? null;

  const now = useNow(storyGenerating ? 1000 : 60000);
  const storyElapsedSeconds =
    storyGenerating && storyStartedAt
      ? Math.max(0, Math.round((now - new Date(storyStartedAt).getTime()) / 1000))
      : 0;

  const startStoryJob = storyJob.start;
  const generateStory = useCallback(
    async (customPrompt?: string) => {
      setStoryError(null);
      setStoryContextError(null);
      try {
        await startStoryJob(() =>
          aiJobsService.startStory(fileId!, {
            additionalContext,
            customPrompt,
            maxFindings,
            maxRiskMatrix,
            networkId: networkContext,
          })
        );
      } catch (err) {
        setStoryError(
          describeLlmError(err, {
            subject: 'Story generation',
            timeoutMs: llmTimeoutMs,
            timeoutHint: 'reduce the capture size',
            fallback: "Couldn't start writing the story",
          })
        );
      }
    },
    [fileId, additionalContext, llmTimeoutMs, maxFindings, maxRiskMatrix, networkContext, startStoryJob]
  );

  // Load existing story once on mount
  useEffect(() => {
    if (!fileId) return;
    storyService
      .getStoryByFileId(fileId)
      .then(existing => {
        if (existing) {
          setStory(existing);
          if (existing.findings?.length) setTotalFindings(existing.findings.length);
          if (existing.aggregates?.protocolRiskMatrix?.length)
            setTotalRiskMatrix(existing.aggregates.protocolRiskMatrix.length);
        }
      })
      .catch(err => console.error('Failed to load existing story:', err));
  }, [fileId]);

  // The story asked for at upload ("write the story when analysis finishes"): while it is queued or
  // being written, check every 15 s and show it the moment it lands.
  useEffect(() => {
    if (!fileId) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const check = async () => {
      try {
        const { data: meta } = await apiClient.get<{ storyStatus?: string | null; storyError?: string | null }>(
          API_ENDPOINTS.FILE_METADATA(fileId)
        );
        if (!alive) return;
        const status = meta.storyStatus;
        if (status === 'QUEUED' || status === 'WRITING') {
          setBackground({ status });
          timer = setTimeout(check, 15_000);
        } else if (status === 'READY') {
          setBackground(null);
          const existing = await storyService.getStoryByFileId(fileId);
          if (alive && existing) setStory(prev => prev ?? existing);
        } else if (status === 'FAILED') {
          setBackground({ status, error: meta.storyError });
        } else {
          setBackground(null);
        }
      } catch {
        // No background story to follow; the page works as before.
      }
    };
    check();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [fileId]);

  const storyState: StoryGenerationState = useMemo(
    () => ({
      story,
      setStory,
      background: story ? null : background,
      generating: storyGenerating,
      generateStory,
      error: storyError,
      setError: setStoryError,
      contextError: storyContextError,
      setContextError: setStoryContextError,
      editablePrompt: storyEditablePrompt,
      setEditablePrompt: setStoryEditablePrompt,
      elapsedSeconds: storyElapsedSeconds,
      llmTimeoutMs,
      job: storyJob.job,
      cancelJob: storyJob.cancel,
      additionalContext,
      setAdditionalContext,
      maxFindings,
      setMaxFindings,
      maxRiskMatrix,
      setMaxRiskMatrix,
      totalFindings,
      setTotalFindings,
      totalRiskMatrix,
      setTotalRiskMatrix,
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }),
    [
      story,
      background,
      storyGenerating,
      generateStory,
      storyError,
      storyContextError,
      storyEditablePrompt,
      storyElapsedSeconds,
      llmTimeoutMs,
      storyJob.job,
      storyJob.cancel,
      additionalContext,
      maxFindings,
      maxRiskMatrix,
      totalFindings,
      totalRiskMatrix,
    ]
  );

  // ── Network diagram filter state (lifted here so it survives tab switches) ──
  const networkDiagramFilters = useNetworkDiagramFilterState();

  // NetworkDiagramPage writes its current filtered nodes/edges here so the
  // report captures exactly what the user sees.
  const networkGraphStateRef = useRef<NetworkGraphState>({
    filteredNodes: [],
    filteredEdges: [],
    activeFilterLabels: [],
    nodeLimitNote: null,
  });

  useEffect(() => {
    const path = location.pathname;
    if (path.includes('/conversations')) setActiveTab('conversations');
    else if (path.includes('/story')) setActiveTab('story');
    else if (path.includes('/network-diagram')) setActiveTab('network-diagram');
    else if (path.includes('/extracted-files')) setActiveTab('extracted-files');
    else if (path.endsWith('/file')) setActiveTab('file');
    else setActiveTab('overview');
  }, [location.pathname]);

  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
    // Keep the network context (#925 phase 3) when moving between tabs.
    const ctx = new URLSearchParams(location.search).get('networkId');
    navigate({
      pathname: tab === 'overview' ? `/analysis/${fileId}` : `/analysis/${fileId}/${tab}`,
      search: ctx ? `?networkId=${encodeURIComponent(ctx)}` : '',
    });
  };

  if (loading) return <AnalysisLoadingView fileId={fileId!} />;
  if (error)
    return (
      <ErrorMessage
        title="Failed to Load Analysis"
        message={error.message}
        onRetry={() => refetch()}
      />
    );
  if (!data)
    return (
      <ErrorMessage title="No Data Available" message="No analysis data found for this file." />
    );

  return (
    <div className="analysis-page">
      <div className="analysis-shell">
        <AnalysisRail
          items={RAIL_ITEMS.map(i => (i.key === 'story' ? { ...i, busy: storyGenerating } : i))}
          active={activeTab}
          onSelect={handleTabChange}
        />
        <div className={`analysis-main${activeTab === 'story' ? ' analysis-main-with-aside' : ''}`}>
          <div className="analysis-main-column">
          {/* The capture bar: which capture, and the page-wide controls. */}
          <div className="analysis-capture-bar">
            <div className="analysis-capture-id">
              <div className="analysis-capture-crumb">
                <Link to="/">Captures</Link>
                <span aria-hidden="true" className="text-muted mx-1">
                  ›
                </span>
              </div>
              <h2 className="analysis-capture-name">
                <FavouriteStar fileId={fileId!} fileName={data.fileName} />
                {data.fileName}
              </h2>
              <div className="analysis-capture-facts">{captureFacts(data)}</div>
            </div>
          </div>

          <div className="analysis-body">
            {activeTab === 'file' && (
              <Card className="mb-4">
                <Card.Body>
                  <h2 className="h6 mb-1">Detection rules and report</h2>
                  <p className="small text-muted mb-3">
                    Which custom detection rules apply to this capture, and a PDF of the whole
                    analysis.
                  </p>
                  <div className="d-flex flex-wrap align-items-start gap-3">
                    <NetworkContextPicker fileId={fileId!} />
                    <div className="d-flex flex-column align-items-end gap-1">
                      <Button variant="outline-primary" size="sm" onClick={() => setShowReport(true)}>
                        <i className="bi bi-file-earmark-pdf me-2" aria-hidden="true"></i>
                        Download report
                      </Button>
                    </div>
                  </div>
                </Card.Body>
              </Card>
            )}
            <ReportDrawer
              show={showReport}
              onHide={() => setShowReport(false)}
              fileId={fileId!}
              fileName={data.fileName}
              networkId={networkContext ?? undefined}
              summary={data}
              hasStory={!!story}
              graphStateRef={networkGraphStateRef}
            />

            {/* Tab Content */}
            <Outlet
              context={
                {
                  data,
                  fileId: fileId!,
                  networkGraphStateRef,
                  networkDiagramFilters,
                  storyState,
                  refreshSummary: () => void refetch({ silent: true }),
                  asideSlot: activeTab === 'story' ? asideSlot : null,
                } satisfies AnalysisOutletContext
              }
            />
          </div>
          </div>
          {activeTab === 'story' && <div className="analysis-aside" ref={setAsideSlot} />}
        </div>
      </div>
    </div>
  );
};
