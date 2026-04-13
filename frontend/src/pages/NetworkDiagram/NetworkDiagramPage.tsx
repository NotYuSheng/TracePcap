import { useState, useMemo, useRef, useEffect, type Dispatch, type SetStateAction } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Modal } from '@govtechsg/sgds-react';
import type { GraphNode } from '@/features/network/types';
import {
  useNetworkData,
  CONVERSATION_LIMIT_ENABLED,
  MAX_DIAGRAM_NODES,
} from '@/features/network/hooks/useNetworkData';
import { buildActiveFilterLabels } from '@/features/network/constants';
import { edgeMatchesLegendKey } from '@/features/network/services/networkService';
import { NetworkGraph } from '@components/network/NetworkGraph';
import { NetworkControls } from '@components/network/NetworkControls';
import { NodeDetails } from '@components/network/NodeDetails';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';
import type { AnalysisOutletContext } from '@/pages/Analysis/AnalysisPage';

function toggleSet(setter: Dispatch<SetStateAction<string[]>>) {
  return (val: string) =>
    setter(prev => (prev.includes(val) ? prev.filter(v => v !== val) : [...prev, val]));
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

export const NetworkDiagramPage = () => {
  const { fileId, data, networkGraphStateRef, networkDiagramFilters } =
    useOutletContext<AnalysisOutletContext>();

  const {
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
  } = networkDiagramFilters;

  // Draft value for the custom node count input — only applied on Enter/blur
  const [customInput, setCustomInput] = useState('');
  const [showSignificanceModal, setShowSignificanceModal] = useState(false);
  const { nodes, edges, stats, loading, error, refetch, hiddenNodes, hiddenNodesList, crossEdges } =
    useNetworkData(fileId, data, nodeLimit);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

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

  useEffect(() => {
    const onFsChange = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', onFsChange);
    return () => document.removeEventListener('fullscreenchange', onFsChange);
  }, []);

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      graphCardRef.current?.requestFullscreen();
    } else {
      document.exitFullscreen();
    }
  };

  // ─── "Present" sets: only show options that exist in the data ───────────────

  const presentNodeTypes = useMemo(() => {
    const types = new Set<string>();
    nodes.forEach(n => {
      types.add(n.data.nodeType);
    });
    return types;
  }, [nodes]);

  const presentDeviceTypes = useMemo(() => {
    const types = new Set<string>();
    nodes.forEach(n => {
      if (n.data.deviceType) types.add(n.data.deviceType);
    });
    return types;
  }, [nodes]);

  const presentEdgeLegendKeys = useMemo(() => {
    const keys = new Set<string>();
    edges.forEach(edge => {
      const proto = edge.data.protocol.toUpperCase();
      const app = (edge.data.appName ?? '').toUpperCase();
      ['HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP', 'ICMP', 'ARP', 'STP', 'LLDP', 'CDP', 'EAPOL'].forEach(
        key => {
          if (edgeMatchesLegendKey(proto, app, key)) keys.add(key);
        }
      );
    });
    return keys;
  }, [edges]);

  const presentAppNames = useMemo(() => {
    const names = new Set<string>();
    edges.forEach(e => {
      if (e.data.appName) names.add(e.data.appName);
    });
    return [...names].sort();
  }, [edges]);

  const presentL7Protocols = useMemo(() => {
    const vals = new Set<string>();
    edges.forEach(e => {
      if (e.data.l7Protocol) vals.add(e.data.l7Protocol);
    });
    return [...vals].sort();
  }, [edges]);

  const presentCategories = useMemo(() => {
    const vals = new Set<string>();
    edges.forEach(e => {
      if (e.data.category) vals.add(e.data.category);
    });
    return [...vals].sort();
  }, [edges]);

  const presentRiskTypes = useMemo(() => {
    const vals = new Set<string>();
    edges.forEach(e => e.data.flowRisks?.forEach(r => vals.add(r)));
    return [...vals].sort();
  }, [edges]);

  const presentCustomSigs = useMemo(() => {
    const vals = new Set<string>();
    edges.forEach(e => e.data.customSignatures?.forEach(s => vals.add(s)));
    return [...vals].sort();
  }, [edges]);

  const presentFileTypes = useMemo(() => {
    const vals = new Set<string>();
    edges.forEach(e => e.data.detectedFileTypes?.forEach(f => vals.add(f)));
    return [...vals].sort();
  }, [edges]);

  // country options as "code|name" strings (matching ConversationFilterPanel convention)
  const presentCountries = useMemo(() => {
    const map = new Map<string, string>();
    edges.forEach(e => {
      // The EdgeData only stores the country code; full name not available here.
      // Show code|code so the display is consistent with the flag helper.
      if (e.data.srcCountry) map.set(e.data.srcCountry, e.data.srcCountry);
      if (e.data.dstCountry) map.set(e.data.dstCountry, e.data.dstCountry);
    });
    return [...map.entries()].map(([code]) => code).sort();
  }, [edges]);

  // ─── Filter logic ────────────────────────────────────────────────────────────

  const { filteredNodes, filteredEdges } = useMemo(() => {
    let filtered = edges;

    if (hasRisksOnly) {
      filtered = filtered.filter(e => e.data.hasRisks);
    }

    if (activeLegendProtocols.length > 0) {
      filtered = filtered.filter(edge => {
        const proto = edge.data.protocol.toUpperCase();
        const app = (edge.data.appName ?? '').toUpperCase();
        return activeLegendProtocols.some(key => edgeMatchesLegendKey(proto, app, key));
      });
    }

    if (activeAppFilters.length > 0) {
      filtered = filtered.filter(e => activeAppFilters.includes(e.data.appName ?? ''));
    }

    if (activeL7Protocols.length > 0) {
      filtered = filtered.filter(e => activeL7Protocols.includes(e.data.l7Protocol ?? ''));
    }

    if (activeCategories.length > 0) {
      filtered = filtered.filter(e => activeCategories.includes(e.data.category ?? ''));
    }

    if (activeRiskTypes.length > 0) {
      filtered = filtered.filter(e => activeRiskTypes.some(r => e.data.flowRisks?.includes(r)));
    }

    if (activeCustomSigs.length > 0) {
      filtered = filtered.filter(e =>
        activeCustomSigs.some(s => e.data.customSignatures?.includes(s))
      );
    }

    if (activeFileTypes.length > 0) {
      filtered = filtered.filter(e =>
        activeFileTypes.some(f => e.data.detectedFileTypes?.includes(f))
      );
    }

    if (activeCountries.length > 0) {
      filtered = filtered.filter(
        e =>
          activeCountries.includes(e.data.srcCountry ?? '') ||
          activeCountries.includes(e.data.dstCountry ?? '')
      );
    }

    if (activeNodeFilters.length > 0) {
      const matchingIds = new Set(
        nodes
          .filter(n =>
            activeNodeFilters.some(key => {
              if (key.startsWith('nt:')) {
                const nt = key.slice(3);
                return n.data.nodeType === nt;
              }
              if (key.startsWith('dt:')) return n.data.deviceType === key.slice(3);
              return false;
            })
          )
          .map(n => n.id)
      );
      filtered = filtered.filter(e => matchingIds.has(e.source) || matchingIds.has(e.target));
    }

    if (portFilter) {
      const portNum = parseInt(portFilter, 10);
      if (!isNaN(portNum)) {
        filtered = filtered.filter(e => e.data.srcPort === portNum || e.data.dstPort === portNum);
      }
    }

    const hasActiveFilters =
      activeLegendProtocols.length > 0 ||
      activeNodeFilters.length > 0 ||
      activeAppFilters.length > 0 ||
      activeL7Protocols.length > 0 ||
      activeCategories.length > 0 ||
      activeRiskTypes.length > 0 ||
      activeCustomSigs.length > 0 ||
      activeFileTypes.length > 0 ||
      activeCountries.length > 0 ||
      hasRisksOnly ||
      ipFilter.length > 0 ||
      portFilter.length > 0;

    const ipLower = ipFilter.toLowerCase();
    let visibleNodes = nodes;
    if (ipFilter) {
      visibleNodes = nodes.filter(
        n =>
          n.data.ip.toLowerCase().includes(ipLower) ||
          (n.data.hostname ?? '').toLowerCase().includes(ipLower)
      );
    }

    if (hasActiveFilters) {
      const matchedByIp = new Set(visibleNodes.map(n => n.id));
      if (ipFilter) {
        filtered = filtered.filter(e => matchedByIp.has(e.source) || matchedByIp.has(e.target));
      }
      const visibleNodeIds = new Set<string>();
      filtered.forEach(e => {
        visibleNodeIds.add(e.source);
        visibleNodeIds.add(e.target);
      });
      visibleNodes = nodes.filter(
        n => visibleNodeIds.has(n.id) || (ipFilter && matchedByIp.has(n.id))
      );
    }

    return { filteredNodes: visibleNodes, filteredEdges: filtered };
  }, [
    nodes,
    edges,
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

  // Keep the parent's ref up to date with the currently visible graph state so
  // the report button captures exactly what the user sees.
  useEffect(() => {
    if (!networkGraphStateRef) return;
    const labels = buildActiveFilterLabels({
      ipFilter, portFilter, hasRisksOnly,
      activeLegendProtocols, activeNodeFilters, activeAppFilters,
      activeL7Protocols, activeCategories, activeRiskTypes,
      activeCustomSigs, activeFileTypes, activeCountries,
    });
    const nodeLimitNote =
      hiddenNodes > 0
        ? `Showing the ${nodeLimit} most significant nodes (${hiddenNodes} hidden). Ranked by traffic volume, risk signals, and connectivity.`
        : null;
    networkGraphStateRef.current = { filteredNodes, filteredEdges, activeFilterLabels: labels, nodeLimitNote };
  });

  if (loading) {
    return <LoadingSpinner size="large" message="Building network topology..." fullPage />;
  }

  if (error) {
    return <ErrorMessage title="Failed to Load Network Data" message={error} onRetry={refetch} />;
  }

  return (
    <div className="network-diagram-page">
      {/* Page title */}
      <h4 className="mb-3">
        <i className="bi bi-diagram-3 me-2"></i>
        Network Topology Diagram
      </h4>

      {CONVERSATION_LIMIT_ENABLED &&
        (stats.isLimited ? (
          <div className="alert alert-warning mb-3">
            <i className="bi bi-exclamation-triangle me-2"></i>
            <strong>Performance limit active:</strong> Showing top{' '}
            {stats.displayedConversations?.toLocaleString()} of{' '}
            {stats.totalConversations?.toLocaleString()} conversations by packet count. Set{' '}
            <code>VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT=false</code> to render all.
          </div>
        ) : (
          <div className="alert alert-info mb-3">
            <i className="bi bi-info-circle me-2"></i>
            <strong>Performance limit enabled</strong> — all{' '}
            {stats.totalConversations?.toLocaleString()} conversations are within the 500-connection
            limit and fully rendered.
          </div>
        ))}

      {/* Row 1: Network Statistics */}
      <div className="card mb-3">
        <div className="card-header">
          <strong>Diagram Overview</strong>
        </div>
        <div className="card-body py-2 px-3">
          <div className="d-flex align-items-center gap-3 flex-wrap">
            {[
              { label: 'Nodes', value: stats.totalNodes.toLocaleString() },
              { label: 'Connections', value: stats.totalEdges.toLocaleString() },
              { label: 'Packets', value: stats.totalPackets.toLocaleString() },
              { label: 'Data', value: formatBytes(stats.totalBytes) },
            ].map(({ label, value }) => (
              <div key={label} className="text-center px-3 py-1 tp-stat-box rounded border">
                <div style={{ fontSize: '0.7rem', color: '#6c757d', textTransform: 'uppercase' }}>
                  {label}
                </div>
                <div style={{ fontSize: '1rem', fontWeight: 600 }}>{value}</div>
              </div>
            ))}
            <div className="ms-auto text-muted small">
              {filteredNodes.length} nodes · {filteredEdges.length} connections shown
            </div>
          </div>
        </div>
      </div>

      {stats.totalNodes > MAX_DIAGRAM_NODES &&
        (() => {
          const totalNodes = stats.totalNodes;
          const presets = [25, 50, 100, 200].filter(p => p < totalNodes);
          const applyCustom = () => {
            const n = parseInt(customInput, 10);
            if (!isNaN(n) && n > 0) setNodeLimit(Math.min(n, totalNodes));
            setCustomInput('');
          };
          return (
            <div className="alert alert-info mb-3">
              <div className="d-flex align-items-start gap-2 flex-wrap">
                <button
                  className="btn btn-link p-0 border-0 mt-1 flex-shrink-0"
                  style={{ lineHeight: 1 }}
                  title="How is significance determined?"
                  onClick={() => setShowSignificanceModal(true)}
                >
                  <i className="bi bi-info-circle"></i>
                </button>
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

      {/* Row 2: Legend & Filters */}
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
        />
      </div>

      {/* Row 3: Graph full width */}
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
                hiddenNodesList={hiddenNodesList}
                crossEdges={crossEdges}
                onNodeClick={node => setSelectedNode(node)}
                layoutType={layoutType}
                onLayoutChange={setLayoutType}
              />
            </div>
          </div>
        </div>
      </div>

      {selectedNode && (
        <NodeDetails
          node={selectedNode}
          edges={edges}
          fileId={fileId}
          onClose={() => setSelectedNode(null)}
        />
      )}

      <Modal show={showSignificanceModal} onHide={() => setShowSignificanceModal(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>How node significance is determined</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="text-muted small mb-3">
            When a PCAP has more nodes than the current display limit, TracePcap ranks every host by
            a significance score and shows only the top-ranked ones. The score is a weighted sum of
            three signals:
          </p>
          <table className="table table-sm table-bordered mb-3">
            <thead>
              <tr>
                <th>Signal</th>
                <th style={{ width: 70 }}>Weight</th>
                <th>What it measures</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <i className="bi bi-graph-up me-1 text-primary"></i>Traffic volume
                </td>
                <td>50%</td>
                <td>Bytes transferred relative to the busiest node in the capture</td>
              </tr>
              <tr>
                <td>
                  <i className="bi bi-shield-exclamation me-1 text-danger"></i>Risk signals
                </td>
                <td>30%</td>
                <td>
                  Whether any conversation involving this host has a flagged{' '}
                  <strong>flow risk</strong> (nDPI risk flags) or a <strong>custom rule</strong>{' '}
                  match
                </td>
              </tr>
              <tr>
                <td>
                  <i className="bi bi-diagram-2 me-1 text-success"></i>Connectivity
                </td>
                <td>20%</td>
                <td>Number of distinct peers relative to the most-connected node</td>
              </tr>
            </tbody>
          </table>
        </Modal.Body>
        <Modal.Footer>
          <button className="btn btn-secondary" onClick={() => setShowSignificanceModal(false)}>
            Close
          </button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};
