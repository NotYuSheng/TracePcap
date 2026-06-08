import { Spinner } from '@components/common/Spinner/Spinner';
import { useMemo, useState, useEffect } from 'react';
import { Button, Form, Modal } from '@govtechsg/sgds-react';
import type { NetworkSnapshot, ChangeEvent } from '@/features/monitor/types/monitor.types';
import type { NodeHighlight } from '@/components/network/NetworkGraph/NetworkGraph';
import { NetworkGraph } from '@/components/network/NetworkGraph';
import { NetworkControls } from '@/components/network/NetworkControls';
import { NodeDetails } from '@/components/network/NodeDetails';
import type { GraphNode } from '@/features/network/types';
import { useNetworkData } from '@/features/network/hooks/useNetworkData';
import { toggleSet } from '@/features/network/constants';
import { edgeMatchesLegendKey } from '@/features/network/services/networkService';
import { parseDateTime } from '@/utils/dateUtils';

interface MonitorNetworkDiagramProps {
  show: boolean;
  onHide: () => void;
  initialSnapshotId: string;
  snapshots: NetworkSnapshot[];
  changeEvents: ChangeEvent[];
}

const HIGHLIGHT_COLORS: Record<string, string> = {
  CRITICAL: '#e74c3c',
  WARNING:  '#f39c12',
  INFO:     '#2ecc71',
};

function labelForChange(
  changeType: string,
  oldValue: Record<string, unknown> | null,
  newValue: Record<string, unknown> | null,
): string {
  switch (changeType) {
    case 'MAC_ADDED':      return 'New device';
    case 'IP_MAC_DRIFT':
      return (oldValue?.['mac'] && newValue?.['mac'] && oldValue['mac'] !== newValue['mac']) ? 'Potential ARP spoof' : 'IP reassignment';
    case 'GATEWAY_CHANGE': return 'Gateway changed';
    case 'ASN_CHANGE':     return 'New ISP';
    case 'PROTOCOL_ADDED': return 'New protocol';
    case 'APP_ADDED':      return 'New app';
    case 'VPN_DRIFT':      return newValue?.['riskType'] ? 'VPN detected' : 'VPN stopped';
    default:               return changeType;
  }
}

function severityRank(s: string): number {
  return s === 'CRITICAL' ? 3 : s === 'WARNING' ? 2 : 1;
}

function buildHighlightMap(events: ChangeEvent[], toSnapshotId: string): Map<string, NodeHighlight> {
  const map = new Map<string, NodeHighlight>();
  for (const e of events.filter(ev => ev.toSnapshotId === toSnapshotId)) {
    const color = HIGHLIGHT_COLORS[e.severity] ?? HIGHLIGHT_COLORS.INFO;
    const label = labelForChange(e.changeType, e.oldValue, e.newValue);
    const addHl = (key: string, description?: string) => {
      const existing = map.get(key);
      if (!existing || severityRank(e.severity) > severityRank(existing.label)) {
        map.set(key, { color, label, description });
      }
    };
    switch (e.changeType) {
      case 'MAC_ADDED': {
        const ip = e.newValue?.['ip'] as string | undefined;
        addHl(e.entityKey, `New device appeared${ip ? ` at ${ip}` : ''}`);
        if (ip) addHl(ip, `New device with MAC ${e.entityKey}`);
        break;
      }
      case 'IP_MAC_DRIFT': {
        const oldMac = e.oldValue?.['mac'] as string | undefined;
        const newMac = e.newValue?.['mac'] as string | undefined;
        const oldIp = e.oldValue?.['ip'] as string | undefined;
        const newIp = e.newValue?.['ip'] as string | undefined;
        if (oldMac && newMac && oldMac !== newMac) {
          addHl(e.entityKey, `MAC changed from ${oldMac} to ${newMac}`);
          addHl(newMac, `Now claiming IP ${e.entityKey} (was ${oldMac})`);
        } else {
          addHl(e.entityKey, `IP changed from ${oldIp ?? '?'} to ${newIp ?? '?'}`);
          if (newIp) addHl(newIp, `MAC ${e.entityKey} moved here from ${oldIp ?? '?'}`);
        }
        break;
      }
      case 'GATEWAY_CHANGE': {
        const newIp = e.newValue?.['ip'] as string | undefined;
        const oldIp = e.oldValue?.['ip'] as string | undefined;
        if (newIp) addHl(newIp, `New gateway (was ${oldIp ?? '?'})`);
        if (oldIp) addHl(oldIp, `Previous gateway (replaced by ${newIp ?? '?'})`);
        break;
      }
      default:
        break;
    }
  }
  return map;
}

function formatSnapLabel(snap: NetworkSnapshot): string {
  if (snap.startTime) {
    const ms = parseDateTime(snap.startTime as unknown as string | number[]);
    return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }
  return snap.fileName;
}

export const MonitorNetworkDiagram = ({
  show,
  onHide,
  initialSnapshotId,
  snapshots,
  changeEvents,
}: MonitorNetworkDiagramProps) => {
  const sorted = useMemo(
    () => [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder),
    [snapshots],
  );

  const [selectedId, setSelectedId] = useState<string>(initialSnapshotId);
  const [layoutType, setLayoutType] = useState<'circular' | 'hierarchicalTd'>('circular');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showFilterModal, setShowFilterModal] = useState(false);

  // ── Filter state ──────────────────────────────────────────────────────────
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

  const toggleLegendProtocol = toggleSet(setActiveLegendProtocols);
  const toggleNodeFilter    = toggleSet(setActiveNodeFilters);
  const toggleAppFilter     = toggleSet(setActiveAppFilters);
  const toggleL7Protocol    = toggleSet(setActiveL7Protocols);
  const toggleCategory      = toggleSet(setActiveCategories);
  const toggleRiskType      = toggleSet(setActiveRiskTypes);
  const toggleCustomSig     = toggleSet(setActiveCustomSigs);
  const toggleFileType      = toggleSet(setActiveFileTypes);
  const toggleCountry       = toggleSet(setActiveCountries);

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

  // Sync to the clicked snapshot each time the modal opens; reset UI state
  useEffect(() => {
    if (!show) {
      setSelectedNode(null);
      setShowFilterModal(false);
      return;
    }
    if (initialSnapshotId) {
      setSelectedId(initialSnapshotId);
      setSelectedNode(null);
      setIsFullscreen(false);
    }
  }, [show, initialSnapshotId]);

  const selectedIndex = sorted.findIndex(s => s.id === selectedId);

  // Arrow key navigation between snapshots (only when NodeDetails is not open)
  useEffect(() => {
    if (!show) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (selectedNode) return;
      if (e.key === 'ArrowLeft' && selectedIndex > 0) {
        e.preventDefault();
        setSelectedId(sorted[selectedIndex - 1].id);
      } else if (e.key === 'ArrowRight' && selectedIndex < sorted.length - 1) {
        e.preventDefault();
        setSelectedId(sorted[selectedIndex + 1].id);
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [show, selectedIndex, sorted, selectedNode]);

  const selectedSnap = sorted[selectedIndex] ?? sorted[sorted.length - 1] ?? null;
  const prevSnap = selectedIndex > 0 ? sorted[selectedIndex - 1] : null;

  const highlightedNodes = useMemo(() => {
    if (!selectedSnap) return undefined;
    return buildHighlightMap(changeEvents, selectedSnap.id);
  }, [changeEvents, selectedSnap]);

  const { nodes, edges, loading } = useNetworkData(selectedSnap?.fileId ?? '');

  // ── "Present" sets ────────────────────────────────────────────────────────

  const presentNodeTypes = useMemo(() => {
    const s = new Set<string>();
    nodes.forEach(n => s.add(n.data.nodeType));
    return s;
  }, [nodes]);

  const presentDeviceTypes = useMemo(() => {
    const s = new Set<string>();
    nodes.forEach(n => { if (n.data.deviceType) s.add(n.data.deviceType); });
    return s;
  }, [nodes]);

  const presentEdgeLegendKeys = useMemo(() => {
    const s = new Set<string>();
    edges.forEach(edge => {
      const proto = edge.data.protocol.toUpperCase();
      const app = (edge.data.appName ?? '').toUpperCase();
      ['HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP', 'ICMP', 'ARP', 'STP', 'LLDP', 'CDP', 'EAPOL'].forEach(
        key => { if (edgeMatchesLegendKey(proto, app, key)) s.add(key); }
      );
    });
    return s;
  }, [edges]);

  const presentAppNames = useMemo(() => {
    const s = new Set<string>();
    edges.forEach(e => { if (e.data.appName) s.add(e.data.appName); });
    return [...s].sort();
  }, [edges]);

  const presentL7Protocols = useMemo(() => {
    const s = new Set<string>();
    edges.forEach(e => { if (e.data.l7Protocol) s.add(e.data.l7Protocol); });
    return [...s].sort();
  }, [edges]);

  const presentCategories = useMemo(() => {
    const s = new Set<string>();
    edges.forEach(e => { if (e.data.category) s.add(e.data.category); });
    return [...s].sort();
  }, [edges]);

  const presentRiskTypes = useMemo(() => {
    const s = new Set<string>();
    edges.forEach(e => e.data.flowRisks?.forEach(r => s.add(r)));
    return [...s].sort();
  }, [edges]);

  const presentCustomSigs = useMemo(() => {
    const s = new Set<string>();
    edges.forEach(e => e.data.customSignatures?.forEach(sig => s.add(sig)));
    return [...s].sort();
  }, [edges]);

  const presentFileTypes = useMemo(() => {
    const s = new Set<string>();
    edges.forEach(e => e.data.detectedFileTypes?.forEach(f => s.add(f)));
    return [...s].sort();
  }, [edges]);

  const presentCountries = useMemo(() => {
    const s = new Set<string>();
    edges.forEach(e => {
      if (e.data.srcCountry) s.add(e.data.srcCountry);
      if (e.data.dstCountry) s.add(e.data.dstCountry);
    });
    return [...s].sort();
  }, [edges]);

  // ── Filter logic ──────────────────────────────────────────────────────────

  const { filteredNodes, filteredEdges } = useMemo(() => {
    let filtered = edges;

    if (hasRisksOnly) filtered = filtered.filter(e => e.data.hasRisks);
    if (activeLegendProtocols.length > 0) {
      filtered = filtered.filter(edge => {
        const proto = edge.data.protocol.toUpperCase();
        const app = (edge.data.appName ?? '').toUpperCase();
        return activeLegendProtocols.some(key => edgeMatchesLegendKey(proto, app, key));
      });
    }
    if (activeAppFilters.length > 0)
      filtered = filtered.filter(e => activeAppFilters.includes(e.data.appName ?? ''));
    if (activeL7Protocols.length > 0)
      filtered = filtered.filter(e => activeL7Protocols.includes(e.data.l7Protocol ?? ''));
    if (activeCategories.length > 0)
      filtered = filtered.filter(e => activeCategories.includes(e.data.category ?? ''));
    if (activeRiskTypes.length > 0)
      filtered = filtered.filter(e => activeRiskTypes.some(r => e.data.flowRisks?.includes(r)));
    if (activeCustomSigs.length > 0)
      filtered = filtered.filter(e => activeCustomSigs.some(s => e.data.customSignatures?.includes(s)));
    if (activeFileTypes.length > 0)
      filtered = filtered.filter(e => activeFileTypes.some(f => e.data.detectedFileTypes?.includes(f)));
    if (activeCountries.length > 0)
      filtered = filtered.filter(e =>
        activeCountries.includes(e.data.srcCountry ?? '') ||
        activeCountries.includes(e.data.dstCountry ?? '')
      );
    if (activeNodeFilters.length > 0) {
      const matchingIds = new Set(
        nodes
          .filter(n =>
            activeNodeFilters.some(key => {
              if (key.startsWith('nt:')) return n.data.nodeType === key.slice(3);
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
      if (!isNaN(portNum))
        filtered = filtered.filter(e => e.data.srcPort === portNum || e.data.dstPort === portNum);
    }

    const hasActiveFilters =
      activeLegendProtocols.length > 0 || activeNodeFilters.length > 0 ||
      activeAppFilters.length > 0 || activeL7Protocols.length > 0 ||
      activeCategories.length > 0 || activeRiskTypes.length > 0 ||
      activeCustomSigs.length > 0 || activeFileTypes.length > 0 ||
      activeCountries.length > 0 || hasRisksOnly ||
      ipFilter.length > 0 || portFilter.length > 0;

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
      if (ipFilter)
        filtered = filtered.filter(e => matchedByIp.has(e.source) || matchedByIp.has(e.target));
      const visibleNodeIds = new Set<string>();
      filtered.forEach(e => { visibleNodeIds.add(e.source); visibleNodeIds.add(e.target); });
      visibleNodes = nodes.filter(n => visibleNodeIds.has(n.id) || (ipFilter && matchedByIp.has(n.id)));
    }

    return { filteredNodes: visibleNodes, filteredEdges: filtered };
  }, [
    nodes, edges, activeLegendProtocols, activeNodeFilters, activeAppFilters,
    activeL7Protocols, activeCategories, activeRiskTypes, activeCustomSigs,
    activeFileTypes, activeCountries, hasRisksOnly, ipFilter, portFilter,
  ]);

  const activeFilterCount =
    activeLegendProtocols.length + activeNodeFilters.length + activeAppFilters.length +
    activeL7Protocols.length + activeCategories.length + activeRiskTypes.length +
    activeCustomSigs.length + activeFileTypes.length + activeCountries.length +
    (ipFilter ? 1 : 0) + (portFilter ? 1 : 0) + (hasRisksOnly ? 1 : 0);

  // ── Change legend ─────────────────────────────────────────────────────────

  const legendItems = useMemo(() => {
    if (!highlightedNodes) return [];
    const seen = new Map<string, string>();
    for (const hl of highlightedNodes.values()) {
      if (!seen.has(hl.label)) seen.set(hl.label, hl.color);
    }
    return [...seen.entries()].map(([label, color]) => ({ label, color }));
  }, [highlightedNodes]);

  return (
    <>
    <Modal
      show={show}
      onHide={onHide}
      centered={!isFullscreen}
      size={isFullscreen ? undefined : 'xl'}
      dialogClassName={isFullscreen ? 'modal-fullscreen' : undefined}
    >
      <Modal.Header closeButton>
        <Modal.Title className="d-flex align-items-center w-100 me-2">
          <i className="bi bi-diagram-3 me-2"></i>
          Network Diagram — {selectedSnap?.fileName ?? ''}
          <Button
            variant="link"
            size="sm"
            className="ms-auto p-0 text-muted"
            onClick={() => setIsFullscreen(f => !f)}
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            <i className={`bi ${isFullscreen ? 'bi-fullscreen-exit' : 'bi-fullscreen'}`} />
          </Button>
        </Modal.Title>
      </Modal.Header>

      <Modal.Body
        style={{
          padding: '1rem 1.25rem',
          ...(isFullscreen ? { display: 'flex', flexDirection: 'column', overflow: 'hidden' } : {}),
        }}
      >
        {/* Snapshot selector + comparison info */}
        <div className="d-flex align-items-center gap-3 mb-3 flex-wrap">
          <div className="d-flex align-items-center gap-2">
            <Button
              size="sm"
              variant="outline-secondary"
              disabled={selectedIndex <= 0}
              onClick={() => sorted[selectedIndex - 1] && setSelectedId(sorted[selectedIndex - 1].id)}
              title="Previous snapshot"
            >
              <i className="bi bi-chevron-left" />
            </Button>
            <Form.Select
              size="sm"
              style={{ width: 'auto', minWidth: 220 }}
              value={selectedSnap?.id ?? ''}
              onChange={e => setSelectedId(e.target.value)}
            >
              {sorted.map((snap, i) => (
                <option key={snap.id} value={snap.id}>
                  {i + 1}. {formatSnapLabel(snap)} — {snap.fileName}
                </option>
              ))}
            </Form.Select>
            <Button
              size="sm"
              variant="outline-secondary"
              disabled={selectedIndex >= sorted.length - 1}
              onClick={() => sorted[selectedIndex + 1] && setSelectedId(sorted[selectedIndex + 1].id)}
              title="Next snapshot"
            >
              <i className="bi bi-chevron-right" />
            </Button>
          </div>

          {prevSnap ? (
            <span className="text-muted small">
              <i className="bi bi-arrow-left-right me-1"></i>
              Changes vs <strong>{formatSnapLabel(prevSnap)}</strong>
            </span>
          ) : (
            <span className="text-muted small">Baseline — no previous snapshot to compare</span>
          )}

          {legendItems.length > 0 && (
            <div className="d-flex align-items-center gap-2 ms-auto flex-wrap">
              {legendItems.map(item => (
                <span key={item.label} className="d-flex align-items-center gap-1 small">
                  <span style={{
                    display: 'inline-block', width: 11, height: 11, borderRadius: '50%',
                    background: item.color, flexShrink: 0,
                  }} />
                  {item.label}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Graph */}
        <div
          className="monitor-diagram-graph"
          style={isFullscreen ? { flex: 1, minHeight: 0 } : { height: 480 }}
        >
          {loading ? (
            <div className="d-flex align-items-center justify-content-center h-100 text-muted">
              <Spinner animation="border" size="sm" className="me-2" />
              Loading graph…
            </div>
          ) : (
            <NetworkGraph
              nodes={filteredNodes}
              edges={filteredEdges}
              highlightedNodes={highlightedNodes}
              layoutType={layoutType}
              onLayoutChange={setLayoutType}
              onNodeClick={node => setSelectedNode(node)}
              onFilterClick={() => setShowFilterModal(true)}
              activeFilterCount={activeFilterCount}
            />
          )}
        </div>

        {highlightedNodes && highlightedNodes.size === 0 && !loading && prevSnap && (
          <div className="text-center text-muted small mt-2">
            <i className="bi bi-check-circle me-1 text-success"></i>
            No node-level changes detected between these two snapshots.
          </div>
        )}
      </Modal.Body>
    </Modal>

    {selectedNode && selectedSnap && (
      <NodeDetails
        node={selectedNode}
        edges={edges}
        fileId={selectedSnap.fileId}
        onClose={() => setSelectedNode(null)}
        changeHighlight={highlightedNodes?.get(selectedNode.label ?? '') ?? highlightedNodes?.get(selectedNode.data.ip ?? '') ?? highlightedNodes?.get(selectedNode.data.mac ?? '')}
        zIndex={1070}
      />
    )}

    {/* Filter modal — rendered outside the main modal so it stacks on top */}
    <Modal show={showFilterModal} onHide={() => setShowFilterModal(false)} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>Filters</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <NetworkControls
          activeLegendProtocols={activeLegendProtocols}
          onLegendProtocolClick={toggleLegendProtocol}
          onLegendProtocolClear={() => setActiveLegendProtocols([])}
          presentEdgeLegendKeys={presentEdgeLegendKeys}
          activeNodeFilters={activeNodeFilters}
          onNodeFilterClick={toggleNodeFilter}
          onNodeFilterClear={() => setActiveNodeFilters([])}
          presentNodeTypes={presentNodeTypes}
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
          defaultCollapsed={false}
        />
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={() => setShowFilterModal(false)}>Close</Button>
      </Modal.Footer>
    </Modal>
    </>
  );
};
