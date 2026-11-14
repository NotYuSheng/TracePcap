import { AnalysisRail, type RailItem } from './AnalysisRail';
import { useNetworkContext } from '@/features/detectionRules/useNetworkContext';
import { NetworkContextPicker } from '@/features/detectionRules/NetworkContextPicker';
import { Spinner } from '@components/common/Spinner/Spinner';
import { describeLlmError } from '@utils/llmError';
import { Alert } from '@components/common/Alert';
import { useState, useEffect, useRef, useCallback, useMemo, type Dispatch, type SetStateAction } from 'react';
import { Button, Card } from '@govtechsg/sgds-react';
import { Link, useParams, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAnalysisData } from '@features/analysis/hooks/useAnalysisData';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { AnalysisLoadingView } from './AnalysisLoadingView';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { storyService } from '@/features/story/services/storyService';
import type { Story } from '@/types';
import { captureNetworkDiagrams } from '@/features/report/captureNetworkDiagrams';
import { MAX_DIAGRAM_NODES } from '@/features/network/hooks/useNetworkData';
import { buildActiveFilterLabels } from '@/features/network/constants';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import type { AnalysisData } from '@/types';

export interface NetworkGraphState {
  filteredNodes: GraphNode[];
  filteredEdges: GraphEdge[];
  activeFilterLabels: string[];
  nodeLimitNote: string | null;
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
  setContextError: Dispatch<SetStateAction<{ promptText: string; promptTokens: number; contextLength: number } | null>>;
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
}

export interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
  networkGraphStateRef: React.MutableRefObject<NetworkGraphState>;
  networkDiagramFilters: NetworkDiagramFilterState;
  storyState: StoryGenerationState;
  /** Reloads the summary without blanking the page, e.g. after a rule change (#925). */
  refreshSummary: () => void;
}

// Re-export so NetworkDiagramPage can import from one place
export type { AnalysisData };

/** The analysis page's sections, in rail order. */
const RAIL_ITEMS: RailItem[] = [
  { key: 'overview', label: 'Overview', short: 'Overview', icon: 'bi-speedometer2' },
  { key: 'conversations', label: 'Conversations', short: 'Conversations', icon: 'bi-arrow-left-right' },
  { key: 'story', label: 'Story', short: 'Story', icon: 'bi-journal-text' },
  { key: 'network-diagram', label: 'Network Visualization', short: 'Network', icon: 'bi-diagram-3' },
  { key: 'network-cluster', label: 'Network Cluster', short: 'Cluster', icon: 'bi-globe-europe-africa' },
  { key: 'extracted-files', label: 'Extracted Files', short: 'Files', icon: 'bi-file-earmark-arrow-down' },
  { key: 'filter-generator', label: 'Filter Generator', short: 'Filters', icon: 'bi-funnel' },
  { key: 'file', label: 'Capture details', short: 'Capture', icon: 'bi-file-earmark-binary' },
];

/** "913 packets · 26 min" for the capture bar. */
function captureFacts(d: { totalPackets?: number; timeRange?: [number, number] }): string {
  const parts: string[] = [];
  if (d.totalPackets != null) parts.push(`${d.totalPackets.toLocaleString()} packets`);
  if (d.timeRange && d.timeRange[1] > d.timeRange[0]) {
    const s = Math.round((d.timeRange[1] - d.timeRange[0]) / 1000);
    parts.push(s < 90 ? `${s} s` : s < 5400 ? `${Math.round(s / 60)} min` : `${Math.round((s / 3600) * 10) / 10} h`);
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
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportMemoryError, setReportMemoryError] = useState<{
    message: string;
    attemptedSizeMb: number;
    recommendedAppMemoryMb: number | null;
  } | null>(null);
  const [reportStep, setReportStep] = useState<string | null>(null);

  // ── Story generation state (lifted here so it survives tab switches) ──────
  const [story, setStory] = useState<Story | null>(null);
  const [storyGenerating, setStoryGenerating] = useState(false);
  const [storyError, setStoryError] = useState<string | null>(null);
  const [storyContextError, setStoryContextError] = useState<{ promptText: string; promptTokens: number; contextLength: number } | null>(null);
  const [storyEditablePrompt, setStoryEditablePrompt] = useState('');
  const [storyElapsedSeconds, setStoryElapsedSeconds] = useState(0);
  const [llmTimeoutMs, setLlmTimeoutMs] = useState<number>(300000);
  const [additionalContext, setAdditionalContext] = useState('');
  const [maxFindings, setMaxFindings] = useState(20);
  const [maxRiskMatrix, setMaxRiskMatrix] = useState(15);
  const [totalFindings, setTotalFindings] = useState<number | undefined>(undefined);
  const [totalRiskMatrix, setTotalRiskMatrix] = useState<number | undefined>(undefined);
  const storyTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    apiClient
      .get<{ llmTimeoutMs?: number }>('/system/limits')
      .then(res => { if (res.data.llmTimeoutMs) setLlmTimeoutMs(res.data.llmTimeoutMs); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (storyGenerating) {
      setStoryElapsedSeconds(0);
      storyTimerRef.current = setInterval(() => setStoryElapsedSeconds(s => s + 1), 1000);
    } else {
      if (storyTimerRef.current) { clearInterval(storyTimerRef.current); storyTimerRef.current = null; }
    }
    return () => { if (storyTimerRef.current) clearInterval(storyTimerRef.current); };
  }, [storyGenerating]);

  const generateStory = useCallback(async (customPrompt?: string) => {
    try {
      setStoryGenerating(true);
      setStoryError(null);
      setStoryContextError(null);
      const generated = await storyService.generateStory(
        fileId!, additionalContext, llmTimeoutMs, customPrompt, maxFindings, maxRiskMatrix, networkContext
      );
      setStory(generated);
      if (generated.findings?.length) setTotalFindings(generated.findings.length);
      if (generated.aggregates?.protocolRiskMatrix?.length) setTotalRiskMatrix(generated.aggregates.protocolRiskMatrix.length);
    } catch (err) {
      const data = (err as { response?: { data?: Record<string, unknown> } })?.response?.data ?? {};
      if (data.errorCode === 'CONTEXT_LENGTH_EXCEEDED') {
        setStoryContextError({
          promptText: (data.promptText as string) ?? '',
          promptTokens: (data.promptTokens as number) ?? 0,
          contextLength: (data.contextLength as number) ?? 0,
        });
        setStoryEditablePrompt((data.promptText as string) ?? '');
      } else {
        setStoryError(
          describeLlmError(err, {
            subject: 'Story generation',
            timeoutMs: llmTimeoutMs,
            timeoutHint: 'reduce the capture size',
            fallback: 'Failed to generate story',
          })
        );
      }
    } finally {
      setStoryGenerating(false);
    }
  }, [fileId, additionalContext, llmTimeoutMs, maxFindings, maxRiskMatrix, networkContext]);

  // Load existing story once on mount
  useEffect(() => {
    if (!fileId) return;
    storyService.getStoryByFileId(fileId)
      .then(existing => {
        if (existing) {
          setStory(existing);
          if (existing.findings?.length) setTotalFindings(existing.findings.length);
          if (existing.aggregates?.protocolRiskMatrix?.length) setTotalRiskMatrix(existing.aggregates.protocolRiskMatrix.length);
        }
      })
      .catch(err => console.error('Failed to load existing story:', err));
  }, [fileId]);

  const storyState: StoryGenerationState = useMemo(() => ({
    story, setStory,
    generating: storyGenerating,
    generateStory,
    error: storyError, setError: setStoryError,
    contextError: storyContextError, setContextError: setStoryContextError,
    editablePrompt: storyEditablePrompt, setEditablePrompt: setStoryEditablePrompt,
    elapsedSeconds: storyElapsedSeconds,
    llmTimeoutMs,
    additionalContext, setAdditionalContext,
    maxFindings, setMaxFindings,
    maxRiskMatrix, setMaxRiskMatrix,
    totalFindings, setTotalFindings,
    totalRiskMatrix, setTotalRiskMatrix,
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [story, storyGenerating, generateStory, storyError, storyContextError, storyEditablePrompt, storyElapsedSeconds, llmTimeoutMs, additionalContext, maxFindings, maxRiskMatrix, totalFindings, totalRiskMatrix]);

  // ── Network diagram filter state (lifted here so it survives tab switches) ──
  const [nodeLimit, setNodeLimit] = useState(MAX_DIAGRAM_NODES);
  const [ipFilter, setIpFilter] = useState('');
  const [portFilter, setPortFilter] = useState('');
  const [hasRisksOnly, setHasRisksOnly] = useState(false);
  const [activeLegendProtocols, setActiveLegendProtocols] = useState<string[]>([]);
  const [activeNodeFilters, setActiveNodeFilters] = useState<string[]>([]);
  const [activeAppFilters, setActiveAppFilters] = useState<string[]>([]);
  const [activeL7Protocols, setActiveL7Protocols] = useState<string[]>([]);
  const [activeCategories, setActiveCategories] = useState<string[]>([]);
  const [activeRiskTypes, setActiveRiskTypes] = useState<string[]>([]);
  const [activeCustomSigs, setActiveCustomSigs] = useState<string[]>([]);
  const [activeFileTypes, setActiveFileTypes] = useState<string[]>([]);
  const [activeCountries, setActiveCountries] = useState<string[]>([]);
  const [activeGhostFilters, setActiveGhostFilters] = useState<string[]>([]);

  const networkDiagramFilters: NetworkDiagramFilterState = {
    nodeLimit, setNodeLimit,
    ipFilter, setIpFilter,
    portFilter, setPortFilter,
    hasRisksOnly, setHasRisksOnly,
    activeLegendProtocols, setActiveLegendProtocols,
    activeNodeFilters, setActiveNodeFilters,
    activeAppFilters, setActiveAppFilters,
    activeL7Protocols, setActiveL7Protocols,
    activeCategories, setActiveCategories,
    activeRiskTypes, setActiveRiskTypes,
    activeCustomSigs, setActiveCustomSigs,
    activeFileTypes, setActiveFileTypes,
    activeCountries, setActiveCountries,
    activeGhostFilters, setActiveGhostFilters,
  };

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
    else if (path.includes('/filter-generator')) setActiveTab('filter-generator');
    else if (path.includes('/network-diagram')) setActiveTab('network-diagram');
    else if (path.includes('/extracted-files')) setActiveTab('extracted-files');
    else if (path.includes('/network-cluster')) setActiveTab('network-cluster');
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

  const handleDownloadReport = async () => {
    if (!fileId) return;
    setReportLoading(true);
    setReportError(null);
    setReportMemoryError(null);
    setReportStep('Rendering network diagrams…');
    try {
      const { filteredNodes, filteredEdges, nodeLimitNote: refNodeLimitNote } = networkGraphStateRef.current;

      // Build filter labels from the lifted state — always accurate regardless
      // of whether the Network Diagram tab has been visited.
      const activeFilterLabels = buildActiveFilterLabels({
        ipFilter, portFilter, hasRisksOnly,
        activeLegendProtocols, activeNodeFilters, activeAppFilters,
        activeL7Protocols, activeCategories, activeRiskTypes,
        activeCustomSigs, activeFileTypes, activeCountries,
        activeGhostFilters,
      });

      let diagramNodes = filteredNodes;
      let diagramEdges = filteredEdges;
      let nodeLimitNote: string | null = refNodeLimitNote ?? null;

      // If the user never visited the Network Diagram tab the ref will be empty.
      // Fetch the raw graph then apply the same client-side filters so the PDF
      // matches what the user would see on the diagram tab.
      if (diagramNodes.length === 0) {
        setReportStep('Fetching network data…');
        const { conversationService } = await import(
          '@/features/conversation/services/conversationService'
        );
        const { networkService } = await import('@/features/network/services/networkService');
        const [convResponse, hostClassifications] = await Promise.all([
          conversationService.getConversations(fileId, {
            ip: '', port: '', payloadContains: '', protocols: [], l7Protocols: [], apps: [],
            categories: [], hasRisks: false, fileTypes: [], riskTypes: [], customSignatures: [],
            suricataAlerts: [],
            deviceTypes: [], countries: [], sortBy: '', sortDir: 'asc', page: 1, pageSize: 10000,
          }),
          conversationService.getHostClassifications(fileId).catch(() => undefined),
        ]);
        const graph = networkService.buildNetworkGraph(
          convResponse.data, data ?? undefined, 500, hostClassifications, nodeLimit
        );

        // Apply the same client-side filters the diagram tab would use.
        const { filteredNodes: fn, filteredEdges: fe } = networkService.applyNetworkFilters(
          graph.nodes, graph.edges, {
            hasRisksOnly, activeLegendProtocols, activeAppFilters, activeL7Protocols,
            activeCategories, activeRiskTypes, activeCustomSigs, activeFileTypes,
            activeCountries, activeNodeFilters, portFilter, ipFilter, activeGhostFilters,
          }
        );

        // If all filters are default (no active filters), use the full graph.
        diagramNodes = fn.length > 0 || activeFilterLabels.length > 0 ? fn : graph.nodes;
        diagramEdges = fn.length > 0 || activeFilterLabels.length > 0 ? fe : graph.edges;
        if (graph.hiddenNodes && graph.hiddenNodes > 0) {
          nodeLimitNote = `Showing the ${nodeLimit} most significant nodes (${graph.hiddenNodes} hidden). Ranked by traffic volume, risk signals, and connectivity.`;
        }
        setReportStep('Rendering network diagrams…');
      }

      const diagrams = await captureNetworkDiagrams(diagramNodes, diagramEdges);

      setReportStep('Building PDF…');
      const response = await apiClient.post(
        API_ENDPOINTS.REPORT_DOWNLOAD(fileId),
        {
          forceDirectedImage: diagrams.forceDirected,
          hierarchicalImage: diagrams.hierarchical,
          activeFilters: activeFilterLabels,
          nodeLimitNote,
          networkId: networkContext,
        },
        { responseType: 'blob' }
      );

      const url = URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `tracepcap-report-${fileId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Report generation failed', e);

      // This request uses responseType: 'blob' (it's a PDF on success), so axios applies that
      // same responseType to an error body too — a JSON error comes back as a Blob, not a parsed
      // object, and has to be read out explicitly before its fields are usable.
      const raw = (e as { response?: { data?: unknown } })?.response?.data;
      let data: Record<string, unknown> = {};
      if (raw instanceof Blob) {
        try {
          data = JSON.parse(await raw.text());
        } catch {
          // Not a JSON body (e.g. an HTML error page from a proxy) — fall through below.
        }
      } else if (raw && typeof raw === 'object') {
        data = raw as Record<string, unknown>;
      }

      if (data.errorCode === 'PAYLOAD_STRING_TOO_LARGE') {
        setReportMemoryError({
          message:
            (data.message as string) ??
            'The network topology diagram was too large to include in the report.',
          attemptedSizeMb: (data.attemptedSizeMb as number) ?? 0,
          recommendedAppMemoryMb: (data.recommendedAppMemoryMb as number | null) ?? null,
        });
      } else {
        setReportError('Report generation failed. Please try again.');
      }
    } finally {
      setReportLoading(false);
      setReportStep(null);
    }
  };

  if (loading) return <AnalysisLoadingView fileId={fileId!} />;
  if (error)
    return (
      <ErrorMessage title="Failed to Load Analysis" message={error.message} onRetry={() => refetch()} />
    );
  if (!data)
    return (
      <ErrorMessage title="No Data Available" message="No analysis data found for this file." />
    );

  return (
    <div className="analysis-page">
      {reportStep && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 10001,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Card className="shadow-lg p-4 text-center" style={{ minWidth: 320 }}>
            <Spinner animation="border" className="text-primary mb-3" />
            <h6 className="mb-1">Generating Report</h6>
            <p className="text-muted small mb-0">{reportStep}</p>
            <p className="text-muted small mt-1">This may take up to 60 seconds.</p>
          </Card>
        </div>
      )}
      <div className="analysis-shell">
        <AnalysisRail items={RAIL_ITEMS.map(i => (i.key === 'story' ? { ...i, busy: storyGenerating } : i))} active={activeTab} onSelect={handleTabChange} />
        <div className="analysis-main">
      {/* The capture bar: which capture, and the page-wide controls. */}
      <div className="analysis-capture-bar">
        <div className="analysis-capture-id">
          <div className="analysis-capture-crumb">
            <Link to="/">Captures</Link>
            <span aria-hidden="true" className="text-muted mx-1">›</span>
          </div>
          <h2 className="analysis-capture-name">{data.fileName}</h2>
          <div className="analysis-capture-facts">{captureFacts(data)}</div>
        </div>
        <div className="analysis-capture-actions">
          <NetworkContextPicker fileId={fileId!} />
          <div className="d-flex flex-column align-items-end gap-1">
            <Button variant="outline-primary" size="sm" onClick={handleDownloadReport} disabled={reportLoading}>
              {reportLoading ? (
                <>
                  <Spinner animation="border" size="sm" className="me-2" />
                  Generating report…
                </>
              ) : (
                <>
                  <i className="bi bi-file-earmark-pdf me-2" aria-hidden="true"></i>
                  Download report
                </>
              )}
            </Button>
            {reportError && <small className="text-danger">{reportError}</small>}
          </div>
        </div>
      </div>

      <div className="analysis-body">
      {reportMemoryError && (
        <Alert variant="danger" className="mb-3" onClose={() => setReportMemoryError(null)} dismissible>
          <Alert.Heading>
            <i className="bi bi-exclamation-triangle-fill me-2"></i>
            Report Too Large for This Deployment
          </Alert.Heading>
          <p className="mb-2">
            The network topology diagram was <strong>{reportMemoryError.attemptedSizeMb} MB</strong>,
            over what this deployment currently accepts in a single request.
          </p>
          {reportMemoryError.recommendedAppMemoryMb ? (
            <p className="mb-0">
              Raise <code>APP_MEMORY_MB</code> to at least{' '}
              <strong>{reportMemoryError.recommendedAppMemoryMb}</strong> in the backend's
              environment and restart it, then try downloading the report again. (Everything else
              in this app — the JVM heap, upload size, and analysis timeout — is derived from the
              same setting, so this also gives the backend more headroom overall.)
            </p>
          ) : (
            <p className="mb-0">{reportMemoryError.message}</p>
          )}
        </Alert>
      )}

      {/* Tab Content */}
          <Outlet context={{ data, fileId: fileId!, networkGraphStateRef, networkDiagramFilters, storyState, refreshSummary: () => void refetch({ silent: true }) } satisfies AnalysisOutletContext} />
      </div>
        </div>
      </div>
    </div>
  );
};
