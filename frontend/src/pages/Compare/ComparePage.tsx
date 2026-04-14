import { useState, useMemo, useRef, useEffect } from 'react';
import { MAX_DIAGRAM_NODES } from '@/features/network/hooks/useNetworkData';
import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import type { GraphNode } from '@/features/network/types';
import { useCompareData } from '@/features/network/hooks/useCompareData';
import { NetworkGraph } from '@components/network/NetworkGraph';
import { NetworkControls } from '@components/network/NetworkControls';
import { NodeDetails } from '@components/network/NodeDetails';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { toggleSet } from '@/features/network/constants';
import { edgeMatchesLegendKey, applyNetworkFilters } from '@/features/network/services/networkService';
import { formatBytes } from '@/utils/formatters';
import { captureNetworkDiagrams } from '@/features/report/captureNetworkDiagrams';

// Distinct colours for up to ~8 files; cycles if more.
const SOURCE_COLORS = [
  '#0d6efd', // blue
  '#6c757d', // grey
  '#198754', // green
  '#dc3545', // red
  '#fd7e14', // orange
  '#6f42c1', // purple
  '#0dcaf0', // cyan
  '#ffc107', // yellow
];

// ── Component ────────────────────────────────────────────────────────────────

export const ComparePage = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const fileIds = useMemo(() => {
    const raw = searchParams.get('files') ?? '';
    return raw.split(',').filter(Boolean);
  }, [searchParams]);

  // Redirect if fewer than 2 files
  useEffect(() => {
    if (fileIds.length < 2) navigate('/', { replace: true });
  }, [fileIds, navigate]);

  // Resolve file names from the file list before kicking off the compare fetch.
  // We hold off passing labels to useCompareData until names are resolved so that
  // the sources tags on nodes/edges match what the toggle buttons display.
  const [fileNames, setFileNames] = useState<string[] | null>(null);

  useEffect(() => {
    if (fileIds.length < 2) return;
    Promise.all(
      fileIds.map((id, i) =>
        apiClient
          .get(API_ENDPOINTS.FILE_METADATA(id))
          .then(res => res.data.fileName as string)
          .catch(() => `File ${i + 1}`)
      )
    ).then(setFileNames);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileIds.join(',')]);

  const [nodeLimit, setNodeLimit] = useState(MAX_DIAGRAM_NODES);
  const [customInput, setCustomInput] = useState('');

  const { mergedNodes, mergedEdges, totalNodes, hiddenNodes, perFileStats, labels, loading, error } =
    useCompareData(fileIds, fileNames ?? [], nodeLimit);

  // ── Hidden sources toggle ────────────────────────────────────────────────
  const [hiddenSources, setHiddenSources] = useState<Set<string>>(new Set());

  const toggleSource = (label: string) =>
    setHiddenSources(prev => {
      const next = new Set(prev);
      next.has(label) ? next.delete(label) : next.add(label);
      return next;
    });

  // ── Filter state (mirrors NetworkDiagramPage) ────────────────────────────
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [activeLegendProtocols, setActiveLegendProtocols] = useState<string[]>([]);
  const [activeNodeFilters, setActiveNodeFilters] = useState<string[]>([]);
  const [ipFilter, setIpFilter] = useState('');
  const [portFilter, setPortFilter] = useState('');
  const [activeAppFilters, setActiveAppFilters] = useState<string[]>([]);
  const [activeL7Protocols, setActiveL7Protocols] = useState<string[]>([]);
  const [activeCategories, setActiveCategories] = useState<string[]>([]);
  const [activeRiskTypes, setActiveRiskTypes] = useState<string[]>([]);
  const [activeCustomSigs, setActiveCustomSigs] = useState<string[]>([]);
  const [activeFileTypes, setActiveFileTypes] = useState<string[]>([]);
  const [activeCountries, setActiveCountries] = useState<string[]>([]);
  const [hasRisksOnly, setHasRisksOnly] = useState(false);

  const toggleLegendProtocol = toggleSet(setActiveLegendProtocols);
  const toggleNodeFilter = toggleSet(setActiveNodeFilters);
  const toggleAppFilter = toggleSet(setActiveAppFilters);
  const toggleL7Protocol = toggleSet(setActiveL7Protocols);
  const toggleCategory = toggleSet(setActiveCategories);
  const toggleRiskType = toggleSet(setActiveRiskTypes);
  const toggleCustomSig = toggleSet(setActiveCustomSigs);
  const toggleFileType = toggleSet(setActiveFileTypes);
  const toggleCountry = toggleSet(setActiveCountries);

  const clearAllFilters = () => {
    setActiveLegendProtocols([]);
    setActiveNodeFilters([]);
    setIpFilter('');
    setPortFilter('');
    setActiveAppFilters([]);
    setActiveL7Protocols([]);
    setActiveCategories([]);
    setActiveRiskTypes([]);
    setActiveCustomSigs([]);
    setActiveFileTypes([]);
    setActiveCountries([]);
    setHasRisksOnly(false);
  };

  const [layoutType, setLayoutType] = useState<'forceDirected2d' | 'hierarchicalTd'>(
    'forceDirected2d'
  );

  const graphCardRef = useRef<HTMLDivElement>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportStep, setReportStep] = useState<string | null>(null);

  useEffect(() => {
    const onFsChange = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, []);

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) graphCardRef.current?.requestFullscreen();
    else document.exitFullscreen();
  };

  // ── "Present" sets ───────────────────────────────────────────────────────

  const presentNodeTypes = useMemo(() => {
    const types = new Set<string>();
    mergedNodes.forEach(n => {
      types.add(n.data.nodeType);
    });
    return types;
  }, [mergedNodes]);

  const presentDeviceTypes = useMemo(() => {
    const types = new Set<string>();
    mergedNodes.forEach(n => {
      if (n.data.deviceType) types.add(n.data.deviceType);
    });
    return types;
  }, [mergedNodes]);

  const presentEdgeLegendKeys = useMemo(() => {
    const keys = new Set<string>();
    mergedEdges.forEach(edge => {
      const proto = edge.data.protocol.toUpperCase();
      const app = (edge.data.appName ?? '').toUpperCase();
      ['HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP', 'ICMP', 'ARP', 'STP', 'LLDP', 'CDP', 'EAPOL'].forEach(
        key => {
          if (edgeMatchesLegendKey(proto, app, key)) keys.add(key);
        }
      );
    });
    return keys;
  }, [mergedEdges]);

  const presentAppNames = useMemo(() => {
    const names = new Set<string>();
    mergedEdges.forEach(e => {
      if (e.data.appName) names.add(e.data.appName);
    });
    return [...names].sort();
  }, [mergedEdges]);

  const presentL7Protocols = useMemo(() => {
    const vals = new Set<string>();
    mergedEdges.forEach(e => {
      if (e.data.l7Protocol) vals.add(e.data.l7Protocol);
    });
    return [...vals].sort();
  }, [mergedEdges]);

  const presentCategories = useMemo(() => {
    const vals = new Set<string>();
    mergedEdges.forEach(e => {
      if (e.data.category) vals.add(e.data.category);
    });
    return [...vals].sort();
  }, [mergedEdges]);

  const presentRiskTypes = useMemo(() => {
    const vals = new Set<string>();
    mergedEdges.forEach(e => e.data.flowRisks?.forEach(r => vals.add(r)));
    return [...vals].sort();
  }, [mergedEdges]);

  const presentCustomSigs = useMemo(() => {
    const vals = new Set<string>();
    mergedEdges.forEach(e => e.data.customSignatures?.forEach(s => vals.add(s)));
    return [...vals].sort();
  }, [mergedEdges]);

  const presentFileTypes = useMemo(() => {
    const vals = new Set<string>();
    mergedEdges.forEach(e => e.data.detectedFileTypes?.forEach(f => vals.add(f)));
    return [...vals].sort();
  }, [mergedEdges]);

  const presentCountries = useMemo(() => {
    const map = new Map<string, string>();
    mergedEdges.forEach(e => {
      if (e.data.srcCountry) map.set(e.data.srcCountry, e.data.srcCountry);
      if (e.data.dstCountry) map.set(e.data.dstCountry, e.data.dstCountry);
    });
    return [...map.keys()].sort();
  }, [mergedEdges]);

  // ── Filter logic ─────────────────────────────────────────────────────────

  const { filteredNodes, filteredEdges } = useMemo(() => {
    // Source (file) filter — hide edges belonging only to a hidden source (compare-specific)
    const sourceFilteredEdges =
      hiddenSources.size > 0
        ? mergedEdges.filter(e => {
            const sources = e.data.sources;
            if (!sources) return true;
            return sources.some(s => !hiddenSources.has(s));
          })
        : mergedEdges;

    return applyNetworkFilters(mergedNodes, sourceFilteredEdges, {
      hasRisksOnly, activeLegendProtocols, activeAppFilters, activeL7Protocols,
      activeCategories, activeRiskTypes, activeCustomSigs, activeFileTypes,
      activeCountries, activeNodeFilters, portFilter, ipFilter,
    });
  }, [
    mergedNodes,
    mergedEdges,
    hiddenSources,
    activeLegendProtocols,
    activeNodeFilters,
    activeAppFilters,
    activeL7Protocols,
    activeCategories,
    activeRiskTypes,
    activeCustomSigs,
    activeFileTypes,
    activeCountries,
    hasRisksOnly,
    ipFilter,
    portFilter,
  ]);

  const activeFilterCount =
    activeLegendProtocols.length +
    activeNodeFilters.length +
    activeAppFilters.length +
    activeL7Protocols.length +
    activeCategories.length +
    activeRiskTypes.length +
    activeCustomSigs.length +
    activeFileTypes.length +
    activeCountries.length +
    (ipFilter ? 1 : 0) +
    (portFilter ? 1 : 0) +
    (hasRisksOnly ? 1 : 0);

  // ── Download report ───────────────────────────────────────────────────────

  const handleDownloadReport = async () => {
    setReportLoading(true);
    setReportError(null);
    setReportStep('Rendering network diagrams…');
    try {
      const images = await captureNetworkDiagrams(filteredNodes, filteredEdges);

      setReportStep('Building PDF…');

      // Build active filter labels
      const activeFilterLabels: string[] = [];
      if (ipFilter) activeFilterLabels.push(`IP: ${ipFilter}`);
      if (portFilter) activeFilterLabels.push(`Port: ${portFilter}`);
      if (hasRisksOnly) activeFilterLabels.push('Has Risks: Yes');
      if (activeLegendProtocols.length > 0)
        activeFilterLabels.push(`Protocol: ${activeLegendProtocols.join(', ')}`);
      if (activeAppFilters.length > 0)
        activeFilterLabels.push(`App: ${activeAppFilters.join(', ')}`);
      if (activeL7Protocols.length > 0)
        activeFilterLabels.push(`L7: ${activeL7Protocols.join(', ')}`);
      if (activeCategories.length > 0)
        activeFilterLabels.push(`Category: ${activeCategories.join(', ')}`);
      if (activeRiskTypes.length > 0)
        activeFilterLabels.push(`Risk type: ${activeRiskTypes.join(', ')}`);
      if (hiddenSources.size > 0)
        activeFilterLabels.push(`Hidden sources: ${[...hiddenSources].join(', ')}`);

      let nodeLimitNote: string | null = null;
      if (hiddenNodes > 0) {
        nodeLimitNote = `Showing the ${nodeLimit} most significant nodes (${hiddenNodes} hidden). Ranked by traffic volume, risk signals, and connectivity.`;
      }

      const response = await apiClient.post(
        API_ENDPOINTS.COMPARE_REPORT_DOWNLOAD,
        {
          fileIds,
          fileLabels: labels,
          forceDirectedImage: images.forceDirected,
          hierarchicalImage: images.hierarchical,
          activeFilters: activeFilterLabels,
          nodeLimitNote,
        },
        { responseType: 'blob' }
      );

      const url = URL.createObjectURL(response.data);
      const a = document.createElement('a');
      a.href = url;
      const joined = fileIds.join('-');
      const safeIds = joined.length > 180 ? `${fileIds[0]}-and-${fileIds.length - 1}-more` : joined;
      a.download = `tracepcap-compare-report-${safeIds}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('[ComparePage] Report download failed:', err);
      setReportError('Failed to generate report. Please try again.');
    } finally {
      setReportLoading(false);
      setReportStep(null);
    }
  };

  // ── Render ────────────────────────────────────────────────────────────────

  if (fileNames === null || loading) {
    return <LoadingSpinner size="large" message="Building comparison topology…" fullPage />;
  }

  if (error) {
    return <ErrorMessage title="Failed to Load Comparison Data" message={error} />;
  }

  const primaryLabel = labels[0] ?? '';

  return (
    <div className="network-diagram-page">
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
          <div className="card shadow-lg p-4 text-center" style={{ minWidth: 320 }}>
            <div className="spinner-border text-primary mb-3" role="status" />
            <h6 className="mb-1">Generating Report</h6>
            <p className="text-muted small mb-0">{reportStep}</p>
            <p className="text-muted small mt-1">This may take up to 60 seconds.</p>
          </div>
        </div>
      )}

      {/* Back link + header */}
      <div className="d-flex align-items-center gap-3 mb-3">
        <Link to="/" className="btn btn-link btn-sm p-0 text-muted text-decoration-none">
          <i className="bi bi-arrow-left me-1" />
          Back
        </Link>
        <h4 className="mb-0 flex-grow-1">
          <i className="bi bi-diagram-3 me-2" />
          Compare Topology
        </h4>
        <div className="d-flex flex-column align-items-end gap-1">
          <button
            className="btn btn-outline-primary btn-sm"
            onClick={handleDownloadReport}
            disabled={reportLoading}
          >
            {reportLoading ? (
              <>
                <span className="spinner-border spinner-border-sm me-2" role="status" />
                Generating report…
              </>
            ) : (
              <>
                <i className="bi bi-file-earmark-pdf me-2"></i>
                Download Report
              </>
            )}
          </button>
          {reportError && <small className="text-danger">{reportError}</small>}
        </div>
      </div>

      {/* File labels row */}
      <div className="d-flex align-items-center gap-2 mb-3 flex-wrap">
        {labels.map((label, i) => (
          <span key={label}>
            <span
              className="badge"
              style={{
                fontSize: '0.8rem',
                backgroundColor: SOURCE_COLORS[i % SOURCE_COLORS.length],
              }}
            >
              <i className="bi bi-file-earmark-binary me-1" />
              {label}
            </span>
            {i < labels.length - 1 && <span className="text-muted small ms-2">vs</span>}
          </span>
        ))}
      </div>

      {/* Per-file stats — one column per file, wraps naturally */}
      <div className="card mb-3">
        <div className="card-header">
          <strong>Comparison Overview</strong>
        </div>
        <div className="card-body py-2 px-3">
          <div className="d-flex flex-wrap gap-3">
            {perFileStats.map(({ label, stats }, i) => (
              <div key={label} style={{ minWidth: 200 }}>
                <div className="mb-2">
                  <span
                    className="badge"
                    style={{
                      fontSize: '0.7rem',
                      backgroundColor: SOURCE_COLORS[i % SOURCE_COLORS.length],
                    }}
                  >
                    {label}
                  </span>
                </div>
                <div className="d-flex gap-2 flex-wrap">
                  {[
                    { name: 'Nodes', value: stats.totalNodes.toLocaleString() },
                    { name: 'Connections', value: stats.totalEdges.toLocaleString() },
                    { name: 'Packets', value: stats.totalPackets.toLocaleString() },
                    { name: 'Data', value: formatBytes(stats.totalBytes) },
                  ].map(({ name, value }) => (
                    <div key={name} className="text-center px-2 py-1 tp-stat-box rounded border">
                      <div
                        style={{
                          fontSize: '0.65rem',
                          color: '#6c757d',
                          textTransform: 'uppercase',
                        }}
                      >
                        {name}
                      </div>
                      <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>{value}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="mt-2 text-muted small">
            {filteredNodes.length} nodes · {filteredEdges.length} connections shown
          </div>
        </div>
      </div>

      {totalNodes > MAX_DIAGRAM_NODES &&
        (() => {
          const presets = [25, 50, 100, 200].filter(p => p < totalNodes);
          const applyCustom = () => {
            const n = parseInt(customInput, 10);
            if (!isNaN(n) && n > 0) setNodeLimit(Math.min(n, totalNodes));
            setCustomInput('');
          };
          return (
            <div className="alert alert-info mb-3">
              <div className="d-flex align-items-start gap-2 flex-wrap">
                <div className="flex-grow-1">
                  <div>
                    {hiddenNodes > 0 ? (
                      <>
                        Showing the <strong>{nodeLimit} most significant nodes</strong> (
                        {hiddenNodes} hidden). Ranked by traffic volume, risk signals, and
                        connectivity.
                      </>
                    ) : (
                      <>
                        Showing <strong>all {totalNodes} nodes</strong>. Ranked by traffic volume,
                        risk signals, and connectivity.
                      </>
                    )}
                  </div>
                  <div className="d-flex align-items-center gap-2 mt-2 flex-wrap">
                    <span className="text-muted small fw-semibold me-1">Show:</span>
                    {presets.map(p => (
                      <button
                        key={p}
                        className={`btn btn-sm ${nodeLimit === p ? 'btn-info' : 'btn-outline-secondary'}`}
                        style={{ minWidth: 52 }}
                        onClick={() => setNodeLimit(p)}
                      >
                        Top {p}
                      </button>
                    ))}
                    <button
                      className={`btn btn-sm ${nodeLimit >= totalNodes ? 'btn-info' : 'btn-outline-secondary'}`}
                      style={{ minWidth: 52 }}
                      onClick={() => setNodeLimit(totalNodes)}
                    >
                      All {totalNodes}
                    </button>
                    <span className="text-muted small ms-2 me-1">or</span>
                    <div className="input-group input-group-sm" style={{ width: 120 }}>
                      <input
                        type="number"
                        className="form-control form-control-sm"
                        placeholder="Custom…"
                        min={1}
                        max={totalNodes}
                        value={customInput}
                        onChange={e => setCustomInput(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && applyCustom()}
                        onBlur={applyCustom}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          );
        })()}

      {/* Filters */}
      <div className="mb-3">
        <NetworkControls
          activeLegendProtocols={activeLegendProtocols}
          onLegendProtocolClick={toggleLegendProtocol}
          onLegendProtocolClear={() => setActiveLegendProtocols([])}
          activeNodeFilters={activeNodeFilters}
          onNodeFilterClick={toggleNodeFilter}
          onNodeFilterClear={() => setActiveNodeFilters([])}
          presentNodeTypes={presentNodeTypes}
          presentEdgeLegendKeys={presentEdgeLegendKeys}
          presentDeviceTypes={presentDeviceTypes}
          ipFilter={ipFilter}
          onIpFilterChange={setIpFilter}
          portFilter={portFilter}
          onPortFilterChange={setPortFilter}
          activeAppFilters={activeAppFilters}
          onAppFilterClick={toggleAppFilter}
          onAppFilterClear={() => setActiveAppFilters([])}
          presentAppNames={presentAppNames}
          activeL7Protocols={activeL7Protocols}
          onL7ProtocolClick={toggleL7Protocol}
          onL7ProtocolClear={() => setActiveL7Protocols([])}
          presentL7Protocols={presentL7Protocols}
          activeCategories={activeCategories}
          onCategoryClick={toggleCategory}
          onCategoryClear={() => setActiveCategories([])}
          presentCategories={presentCategories}
          activeRiskTypes={activeRiskTypes}
          onRiskTypeClick={toggleRiskType}
          onRiskTypeClear={() => setActiveRiskTypes([])}
          presentRiskTypes={presentRiskTypes}
          activeCustomSigs={activeCustomSigs}
          onCustomSigClick={toggleCustomSig}
          onCustomSigClear={() => setActiveCustomSigs([])}
          presentCustomSigs={presentCustomSigs}
          activeFileTypes={activeFileTypes}
          onFileTypeClick={toggleFileType}
          onFileTypeClear={() => setActiveFileTypes([])}
          presentFileTypes={presentFileTypes}
          activeCountries={activeCountries}
          onCountryClick={toggleCountry}
          onCountryClear={() => setActiveCountries([])}
          presentCountries={presentCountries}
          hasRisksOnly={hasRisksOnly}
          onHasRisksOnlyChange={setHasRisksOnly}
          activeFilterCount={activeFilterCount}
          onClearAllFilters={clearAllFilters}
          defaultCollapsed
        />
      </div>

      {/* Source toggle pills */}
      <div className="d-flex align-items-center gap-2 mb-3 flex-wrap">
        <span className="small text-muted">Show:</span>
        {labels.map((label, i) => {
          const color = SOURCE_COLORS[i % SOURCE_COLORS.length];
          const hidden = hiddenSources.has(label);
          return (
            <button
              key={label}
              className="btn btn-sm"
              style={{
                backgroundColor: hidden ? 'transparent' : color,
                borderColor: color,
                color: hidden ? color : '#fff',
              }}
              onClick={() => toggleSource(label)}
              title={hidden ? `Show ${label}` : `Hide ${label}`}
            >
              <i className={`bi ${hidden ? 'bi-eye-slash' : 'bi-eye'} me-1`} />
              {label}
            </button>
          );
        })}
        <span className="small text-muted ms-3">
          <i className="bi bi-layers-fill me-1" />
          Layered badge = present in multiple files
        </span>
      </div>

      {/* Graph */}
      <div className="row">
        <div className="col-12">
          <div className="card" ref={graphCardRef}>
            <div className="card-header d-flex justify-content-between align-items-center">
              <strong>Topology Diagram</strong>
              <button
                className="btn btn-link btn-sm p-0 text-muted"
                onClick={toggleFullscreen}
                title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
              >
                <i className={`bi ${isFullscreen ? 'bi-fullscreen-exit' : 'bi-fullscreen'}`} />
              </button>
            </div>
            <div className="card-body p-0 network-diagram-graph-body">
              <NetworkGraph
                key={layoutType}
                nodes={filteredNodes}
                edges={filteredEdges}
                onNodeClick={node => setSelectedNode(node)}
                layoutType={layoutType}
                onLayoutChange={setLayoutType}
                primarySource={primaryLabel}
              />
            </div>
          </div>
        </div>
      </div>

      {selectedNode && (
        <NodeDetails
          node={selectedNode}
          edges={mergedEdges}
          fileId={
            selectedNode.data.sources?.[0]
              ? (fileIds[labels.indexOf(selectedNode.data.sources[0])] ?? fileIds[0])
              : fileIds[0]
          }
          onClose={() => setSelectedNode(null)}
        />
      )}
    </div>
  );
};
