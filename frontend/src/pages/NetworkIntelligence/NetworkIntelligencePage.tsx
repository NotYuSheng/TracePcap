import { useState, useEffect, useRef, useMemo } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Alert, Button, Card, Modal } from '@govtechsg/sgds-react';
import type { AnalysisData } from '@/types';
import {
  intelligenceService,
  type GroupBy,
  type ClusterGraphResponse,
  type IntelClusterFilters,
  type ClusterNode,
} from '@/features/intelligence/services/intelligenceService';
import { conversationService } from '@/features/conversation/services/conversationService';
import { ipOrgRuleService } from '@/features/intelligence/services/ipOrgRuleService';
import { SummaryStatsBar } from '@components/intelligence/SummaryStatsBar/SummaryStatsBar';
import { ClusterGraph } from '@components/intelligence/ClusterGraph/ClusterGraph';
import { NetworkControls } from '@components/network/NetworkControls';
import { toggleSet } from '@/features/network/constants';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const NetworkIntelligencePage = () => {
  const { data, fileId } = useOutletContext<AnalysisOutletContext>();

  const [groupBy, setGroupBy] = useState<GroupBy>('asn');

  const [clusterData, setClusterData] = useState<ClusterGraphResponse | null>(null);
  const [clusterLoading, setClusterLoading] = useState(false);
  const [clusterError, setClusterError] = useState<string | null>(null);

  const graphCardRef = useRef<HTMLDivElement>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showFilterModal, setShowFilterModal] = useState(false);
  const [selectedCluster, setSelectedCluster] = useState<ClusterNode | null>(null);

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
  const [activeNetLabels, setActiveNetLabels] = useState<string[]>([]);

  // ── Present-value state (loaded from API) ─────────────────────────────────
  const [presentRiskTypes, setPresentRiskTypes] = useState<string[]>([]);
  const [presentFileTypes, setPresentFileTypes] = useState<string[]>([]);
  const [presentCustomSigs, setPresentCustomSigs] = useState<string[]>([]);
  const [presentCountries, setPresentCountries] = useState<string[]>([]);
  const [presentDeviceTypes, setPresentDeviceTypes] = useState<Set<string>>(new Set());
  const [presentNetLabels, setPresentNetLabels] = useState<string[]>([]);

  useEffect(() => {
    if (!fileId) return;
    let active = true;
    conversationService.getRiskTypes(fileId).then(v => { if (active) setPresentRiskTypes(v); }).catch(() => {});
    conversationService.getFileTypes(fileId).then(v => { if (active) setPresentFileTypes(v); }).catch(() => {});
    conversationService.getCustomSignatures(fileId).then(v => { if (active) setPresentCustomSigs(v); }).catch(() => {});
    conversationService.getCountries(fileId).then(codes => {
      if (active) setPresentCountries(codes.map(c => c.split('|')[0]).filter(Boolean).sort());
    }).catch(() => {});
    conversationService.getHostClassifications(fileId).then(hosts => {
      if (active) setPresentDeviceTypes(new Set(hosts.map(h => h.deviceType).filter(Boolean) as string[]));
    }).catch(() => {});
    ipOrgRuleService.list().then(rules => {
      if (active) setPresentNetLabels([...new Set(rules.map(r => r.label))].sort());
    }).catch(() => {});
    return () => { active = false; };
  }, [fileId]);

  // ── Derive present-values from AnalysisData ───────────────────────────────
  const presentEdgeLegendKeys = useMemo(() => {
    const keys = new Set<string>();
    (data.protocolDistribution ?? []).forEach(p => {
      const upper = p.protocol.toUpperCase();
      ['TCP', 'UDP', 'ICMP', 'ARP', 'STP', 'LLDP', 'CDP', 'EAPOL'].forEach(k => {
        if (upper === k) keys.add(k);
      });
    });
    return keys;
  }, [data]);

  const presentAppNames = useMemo(
    () => (data.detectedApplications ?? []).map(a => a.name).filter(Boolean).sort(),
    [data],
  );

  const presentL7Protocols = useMemo(
    () => [...(data.detectedL7Protocols ?? [])].sort(),
    [data],
  );

  const presentCategories = useMemo(
    () => (data.categoryDistribution ?? []).map(c => c.category).filter(Boolean).sort(),
    [data],
  );

  // node types not meaningful at cluster level — pass empty set
  const presentNodeTypes = useMemo(() => new Set<string>(), []);

  // ── Filter toggles ────────────────────────────────────────────────────────
  const toggleLegendProtocol = toggleSet(setActiveLegendProtocols);
  const toggleNodeFilter = toggleSet(setActiveNodeFilters);
  const toggleAppFilter = toggleSet(setActiveAppFilters);
  const toggleL7Protocol = toggleSet(setActiveL7Protocols);
  const toggleCategory = toggleSet(setActiveCategories);
  const toggleRiskType = toggleSet(setActiveRiskTypes);
  const toggleCustomSig = toggleSet(setActiveCustomSigs);
  const toggleFileType = toggleSet(setActiveFileTypes);
  const toggleCountry = toggleSet(setActiveCountries);
  const toggleNetLabel = toggleSet(setActiveNetLabels);

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
    setActiveNetLabels([]);
    setHasRisksOnly(false);
  };

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
    (hasRisksOnly ? 1 : 0) +
    activeNetLabels.length;

  // ── Build IntelClusterFilters from active filter state ────────────────────
  const intelFilters = useMemo((): IntelClusterFilters => {
    // Map activeNodeFilters (dt:MOBILE etc.) → deviceTypes param
    const deviceTypes = activeNodeFilters
      .filter(k => k.startsWith('dt:'))
      .map(k => k.slice(3));

    return {
      ip: ipFilter || undefined,
      port: portFilter || undefined,
      protocols: activeLegendProtocols.length ? activeLegendProtocols : undefined,
      l7Protocols: activeL7Protocols.length ? activeL7Protocols : undefined,
      apps: activeAppFilters.length ? activeAppFilters : undefined,
      categories: activeCategories.length ? activeCategories : undefined,
      hasRisks: hasRisksOnly || undefined,
      fileTypes: activeFileTypes.length ? activeFileTypes : undefined,
      riskTypes: activeRiskTypes.length ? activeRiskTypes : undefined,
      customSignatures: activeCustomSigs.length ? activeCustomSigs : undefined,
      deviceTypes: deviceTypes.length ? deviceTypes : undefined,
      countries: activeCountries.length ? activeCountries : undefined,
      networkLabels: activeNetLabels.length ? activeNetLabels : undefined,
    };
  }, [
    ipFilter, portFilter, hasRisksOnly,
    activeLegendProtocols, activeNodeFilters,
    activeAppFilters, activeL7Protocols, activeCategories,
    activeRiskTypes, activeCustomSigs, activeFileTypes, activeCountries, activeNetLabels,
  ]);

  // CSS fullscreen — lets us intercept Escape to close modals before exiting fullscreen
  useEffect(() => {
    if (!isFullscreen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      if (showFilterModal) { setShowFilterModal(false); return; }
      if (selectedCluster) { setSelectedCluster(null); return; }
      setIsFullscreen(false);
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [isFullscreen, showFilterModal, selectedCluster]);

  const [autoSelected, setAutoSelected] = useState(false);

  // Stable serialised key — only changes when filter values actually differ
  const intelFiltersKey = JSON.stringify(intelFilters);

  // Fetch clusters when groupBy or filters change
  useEffect(() => {
    if (!fileId) return;
    let active = true;
    setClusterLoading(true);
    setClusterError(null);
    setClusterData(null);
    intelligenceService
      .getClusters(fileId, groupBy, intelFilters)
      .then(result => {
        if (!active) return;
        setClusterData(result);
        // On first load, auto-switch to subnet24 if all clusters are internal
        if (!autoSelected) {
          setAutoSelected(true);
          const allInternal = result.clusters.length > 0 &&
            result.clusters.every(c => c.label.startsWith('Internal'));
          if (allInternal && groupBy === 'asn') {
            setGroupBy('subnet24');
          }
        }
      })
      .catch(e => {
        if (!active) return;
        setClusterError(e instanceof Error ? e.message : 'Failed to load cluster data');
      })
      .finally(() => {
        if (active) setClusterLoading(false);
      });
    return () => { active = false; };
  }, [fileId, groupBy, intelFiltersKey]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="network-intelligence-page">
      <div className="mb-3">
        <h4 className="mb-1">Network Intelligence</h4>
        <p className="text-muted small mb-0">
          Identify who your network is talking to, where the traffic is flowing, and where risks are concentrated —
          without reviewing individual conversations. Best suited for large captures with many hosts.
        </p>
      </div>

      {/* Summary stats */}
      <SummaryStatsBar data={data} />

      {/* Cluster graph */}
      <Card className={`mb-4${isFullscreen ? ' nd-css-fullscreen' : ''}`} ref={graphCardRef}>
        <Card.Header className="d-flex justify-content-between align-items-center">
          <div>
            <h6 className="mb-0">
              <i className="bi bi-diagram-3 me-2" />
              Network Cluster View
            </h6>
            <small className="text-muted">Click a cluster node to see its member IPs and statistics.</small>
          </div>
          <Button
            variant="link"
            size="sm"
            className="p-0 text-muted"
            onClick={() => setIsFullscreen(f => !f)}
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            <i className={`bi ${isFullscreen ? 'bi-fullscreen-exit' : 'bi-fullscreen'}`} />
          </Button>
        </Card.Header>
        <Card.Body className="intel-cluster-card-body">
          {clusterError && (
            <Alert variant="warning" className="py-2">
              <i className="bi bi-exclamation-triangle me-2" />
              {clusterError}
            </Alert>
          )}
          <ClusterGraph
            data={clusterData}
            loading={clusterLoading}
            groupBy={groupBy}
            onGroupByChange={setGroupBy}
            fileId={fileId}
          />
        </Card.Body>
      </Card>

      {/* Filter modal */}
      <Modal
        show={showFilterModal}
        onHide={() => setShowFilterModal(false)}
        container={graphCardRef.current ?? undefined}
        size="lg"
      >
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
            activeNetLabels={activeNetLabels}
            onNetLabelClick={toggleNetLabel}
            onNetLabelClear={() => setActiveNetLabels([])}
            presentNetLabels={presentNetLabels}
          />
        </Modal.Body>
      </Modal>

    </div>
  );
};
