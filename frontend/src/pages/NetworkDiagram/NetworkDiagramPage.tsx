import { useState, useMemo, useRef, useEffect } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import type { GraphNode } from '@/features/network/types';
import { useNetworkData, CONVERSATION_LIMIT_ENABLED } from '@/features/network/hooks/useNetworkData';
import { NetworkGraph } from '@components/network/NetworkGraph';
import { NetworkControls } from '@components/network/NetworkControls';
import { NodeDetails } from '@components/network/NodeDetails';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

export const NetworkDiagramPage = () => {
  const { fileId, data } = useOutletContext<AnalysisOutletContext>();
  const { nodes, edges, stats, loading, error, refetch } = useNetworkData(fileId, data);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  // Edge legend / protocol filter
  const [activeLegendProtocols, setActiveLegendProtocols] = useState<string[]>([]);
  // Node type / device type filter
  const [activeNodeFilters, setActiveNodeFilters] = useState<string[]>([]);
  // New per-field filters
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

  const toggleSet = (setter: React.Dispatch<React.SetStateAction<string[]>>) => (val: string) =>
    setter(prev => prev.includes(val) ? prev.filter(v => v !== val) : [...prev, val]);

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
      if (n.data.isAnomaly) types.add('anomaly');
      types.add(n.data.nodeType);
    });
    return types;
  }, [nodes]);

  const presentDeviceTypes = useMemo(() => {
    const types = new Set<string>();
    nodes.forEach(n => { if (n.data.deviceType) types.add(n.data.deviceType); });
    return types;
  }, [nodes]);

  const presentEdgeLegendKeys = useMemo(() => {
    const keys = new Set<string>();
    edges.forEach(edge => {
      const proto = edge.data.protocol.toUpperCase();
      const app = (edge.data.appName ?? '').toUpperCase();
      if (proto === 'HTTP' || app === 'HTTP') keys.add('HTTP');
      if (proto === 'HTTPS' || app.includes('TLS') || app.includes('SSL') || app.includes('HTTPS'))
        keys.add('HTTPS');
      if (proto === 'DNS' || app === 'DNS') keys.add('DNS');
      if (proto === 'TCP') keys.add('TCP');
      if (proto === 'UDP') keys.add('UDP');
      if (proto === 'ICMP' || proto === 'ICMPV6') keys.add('ICMP');
      if (proto === 'ARP') keys.add('ARP');
      if (proto === 'STP' || proto === 'RSTP') keys.add('STP');
      if (proto === 'LLDP') keys.add('LLDP');
      if (proto === 'CDP') keys.add('CDP');
      if (proto === 'EAPOL') keys.add('EAPOL');
    });
    return keys;
  }, [edges]);

  const presentAppNames = useMemo(() => {
    const names = new Set<string>();
    edges.forEach(e => { if (e.data.appName) names.add(e.data.appName); });
    return [...names].sort();
  }, [edges]);

  const presentL7Protocols = useMemo(() => {
    const vals = new Set<string>();
    edges.forEach(e => { if (e.data.l7Protocol) vals.add(e.data.l7Protocol); });
    return [...vals].sort();
  }, [edges]);

  const presentCategories = useMemo(() => {
    const vals = new Set<string>();
    edges.forEach(e => { if (e.data.category) vals.add(e.data.category); });
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
        return activeLegendProtocols.some(key => {
          if (key === 'HTTPS')
            return proto === 'HTTPS' || app.includes('TLS') || app.includes('SSL') || app.includes('HTTPS');
          if (key === 'ICMP') return proto === 'ICMP' || proto === 'ICMPV6';
          if (key === 'STP') return proto === 'STP' || proto === 'RSTP';
          return proto === key || app.includes(key);
        });
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
      filtered = filtered.filter(e => activeCustomSigs.some(s => e.data.customSignatures?.includes(s)));
    }

    if (activeFileTypes.length > 0) {
      filtered = filtered.filter(e => activeFileTypes.some(f => e.data.detectedFileTypes?.includes(f)));
    }

    if (activeCountries.length > 0) {
      filtered = filtered.filter(e =>
        activeCountries.includes(e.data.srcCountry ?? '') ||
        activeCountries.includes(e.data.dstCountry ?? '')
      );
    }

    if (activeNodeFilters.length > 0) {
      const matchingIds = new Set(
        nodes.filter(n =>
          activeNodeFilters.some(key => {
            if (key.startsWith('nt:')) {
              const nt = key.slice(3);
              return nt === 'anomaly' ? n.data.isAnomaly : n.data.nodeType === nt;
            }
            if (key.startsWith('dt:')) return n.data.deviceType === key.slice(3);
            return false;
          })
        ).map(n => n.id)
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
      activeLegendProtocols.length > 0 || activeNodeFilters.length > 0 ||
      activeAppFilters.length > 0 || activeL7Protocols.length > 0 ||
      activeCategories.length > 0 || activeRiskTypes.length > 0 ||
      activeCustomSigs.length > 0 || activeFileTypes.length > 0 ||
      activeCountries.length > 0 || hasRisksOnly || ipFilter.length > 0 || portFilter.length > 0;

    const ipLower = ipFilter.toLowerCase();
    let visibleNodes = nodes;
    if (ipFilter) {
      visibleNodes = nodes.filter(n =>
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
      filtered.forEach(e => { visibleNodeIds.add(e.source); visibleNodeIds.add(e.target); });
      visibleNodes = nodes.filter(n => visibleNodeIds.has(n.id) || (ipFilter && matchedByIp.has(n.id)));
    }

    return { filteredNodes: visibleNodes, filteredEdges: filtered };
  }, [
    nodes, edges,
    activeLegendProtocols, activeNodeFilters, activeAppFilters,
    activeL7Protocols, activeCategories, activeRiskTypes,
    activeCustomSigs, activeFileTypes, activeCountries,
    hasRisksOnly, ipFilter, portFilter,
  ]);

  const activeFilterCount =
    activeLegendProtocols.length + activeNodeFilters.length + activeAppFilters.length +
    activeL7Protocols.length + activeCategories.length + activeRiskTypes.length +
    activeCustomSigs.length + activeFileTypes.length + activeCountries.length +
    (ipFilter ? 1 : 0) + (portFilter ? 1 : 0) + (hasRisksOnly ? 1 : 0);

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

      {CONVERSATION_LIMIT_ENABLED && (
        stats.isLimited ? (
          <div className="alert alert-warning mb-3">
            <i className="bi bi-exclamation-triangle me-2"></i>
            <strong>Performance limit active:</strong> Showing top {stats.displayedConversations?.toLocaleString()} of{' '}
            {stats.totalConversations?.toLocaleString()} conversations by packet count.{' '}
            Set <code>VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT=false</code> to render all.
          </div>
        ) : (
          <div className="alert alert-info mb-3">
            <i className="bi bi-info-circle me-2"></i>
            <strong>Performance limit enabled</strong> — all{' '}
            {stats.totalConversations?.toLocaleString()}{' '}
            conversations are within the 500-connection limit and fully rendered.
          </div>
        )
      )}

      {/* Row 1: Network Statistics */}
      <div className="card mb-3">
        <div className="card-header"><strong>Diagram Overview</strong></div>
        <div className="card-body py-2 px-3">
          <div className="d-flex align-items-center gap-3 flex-wrap">
            {[
              { label: 'Nodes', value: stats.totalNodes.toLocaleString() },
              { label: 'Connections', value: stats.totalEdges.toLocaleString() },
              { label: 'Packets', value: stats.totalPackets.toLocaleString() },
              { label: 'Data', value: formatBytes(stats.totalBytes) },
            ].map(({ label, value }) => (
              <div key={label} className="text-center px-3 py-1 bg-light rounded border">
                <div style={{ fontSize: '0.7rem', color: '#6c757d', textTransform: 'uppercase' }}>{label}</div>
                <div style={{ fontSize: '1rem', fontWeight: 600 }}>{value}</div>
              </div>
            ))}
            <div className="ms-auto text-muted small">
              {filteredNodes.length} nodes · {filteredEdges.length} connections shown
            </div>
          </div>
        </div>
      </div>

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
            <div className="card-header d-flex justify-content-between align-items-center py-1 px-2">
              <strong>Topology Diagram</strong>
              <button
                className="btn btn-sm btn-light"
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
    </div>
  );
};
