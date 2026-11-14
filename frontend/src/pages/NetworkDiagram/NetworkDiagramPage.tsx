import { usePermission } from '@/features/me/useMe';
import { networkMapEditsService } from '@/features/network/services/networkMapEdits';
import { useStore } from '@/store';
import { buildGroupTree, layoutGroups, leafGroups } from '@/features/network/services/networkGroups';
import { downloadDrawio, toDrawio } from '@components/network/NetworkGraph/drawioExport';
import { buildNodeLines } from '@components/network/NetworkGraph/nodeLines';
import { usePacketReplay } from '@/features/network/hooks/usePacketReplay';
import { PacketReplayBar } from '@/features/network/components/PacketReplayBar';
import type { AxisMode } from '@/features/network/components/PlayByControl';
import { flightsFor, type ConversationEnds } from '@/features/network/services/packetReplay';
import { getProtocolColor } from '@/features/network/constants';
import { clusterApi } from '@/features/cluster/services/clusterApi';
import { dnsNamesByIp } from '@/features/network/services/networkGroups';
import { networkSegmentService, type NetworkSegment } from '@/features/networkSegments/networkSegmentService';
import { customPrivateRangeService } from '@/features/cluster/services/customPrivateRangeService';
import type { CustomPrivateRange } from '@/features/cluster/types/customPrivateRange.types';
import type { GraphLayoutType } from '@/features/network/types';
import { FullscreenToggle } from '@components/common/FullscreenToggle';
import { useNetworkContext } from '@/features/detectionRules/useNetworkContext';
import { useState, useMemo, useRef, useEffect } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import { Button, Card, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import type { GraphNode } from '@/features/network/types';
import {
  useNetworkData,
  CONVERSATION_LIMIT_ENABLED,
  MAX_DIAGRAM_NODES,
} from '@/features/network/hooks/useNetworkData';
import { buildActiveFilterLabels, toggleSet } from '@/features/network/constants';
import { edgeMatchesLegendKey } from '@/features/network/services/networkService';
import { nodeIdentityKey } from '@/utils/deviceType';
import { formatBytes } from '@/utils/formatters';
import { NetworkGraph } from '@components/network/NetworkGraph';
import { TimeScrubber } from '@/features/network/components/TimeScrubber';
import { activeInWindow, timeBounds, unseenByWindowEnd, type TimeWindow } from '@/features/network/services/timeWindow';
import type { EdgeColorMode, NodeHighlight } from '@components/network/NetworkGraph/NetworkGraph';
import { edgeBytesRange } from '@components/network/NetworkGraph/NetworkGraph';
import { VolumeHeatmap } from '@components/network/VolumeHeatmap';
import type { VolumePair } from '@components/network/VolumeHeatmap';
import { VolumeLegend } from '@components/network/VolumeLegend';
import { useResolvedDark } from '@/utils/useResolvedDark';
import { useEscapeLayer } from '@/utils/useEscapeLayer';
import { NetworkControls } from '@components/network/NetworkControls';
import { EntityDetailModal, graphNodeEntity } from '@components/common/EntityDetailModal';
import { NodeLabelSettingsModal } from '@components/network/NodeLabelSettingsModal';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';
import type { AnalysisOutletContext } from '@/pages/Analysis/AnalysisPage';


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
    activeGhostFilters, setActiveGhostFilters,
  } = networkDiagramFilters;

  // Draft value for the custom node count input — only applied on Enter/blur
  const [customInput, setCustomInput] = useState('');
  const [showSignificanceModal, setShowSignificanceModal] = useState(false);
  const [showFilterModal, setShowFilterModal] = useState(false);
  const [showLabelModal, setShowLabelModal] = useState(false);
  // In a network, its own detection rules' matches show on the edges too (#925 phase 3).
  const [networkContext] = useNetworkContext();
  const { nodes, edges, stats, loading, error, refetch, hiddenNodes, hiddenNodesList, crossEdges, deviceLinks } =
    useNetworkData(fileId, data, nodeLimit, networkContext);

  // The network map layout's grouping: networks from DHCP/VLANs, and what counts as local.
  const [networkSegments, setNetworkSegments] = useState<NetworkSegment[]>([]);
  const [customPrivateRanges, setCustomPrivateRanges] = useState<CustomPrivateRange[]>([]);
  const [dnsNames, setDnsNames] = useState<Map<string, string> | undefined>(undefined);
  useEffect(() => {
    let live = true;
    networkSegmentService
      .get(fileId)
      .then(r => live && setNetworkSegments(r.segments))
      .catch(() => live && setNetworkSegments([]));
    customPrivateRangeService
      .list()
      .then(r => live && setCustomPrivateRanges(r))
      .catch(() => live && setCustomPrivateRanges([]));
    // Names internet hosts were looked up by, from every DNS server's query log.
    clusterApi
      .getDnsServers(fileId)
      .then(servers => Promise.all(servers.map(s => clusterApi.getDnsQueryLog(fileId, s.serverIp))))
      .then(logs => live && setDnsNames(dnsNamesByIp(logs)))
      .catch(() => live && setDnsNames(undefined));
    return () => {
      live = false;
    };
  }, [fileId]);

  // The analyst's edits to the network map (#649): devices moved between groups. Saved per capture.
  const mapPermission = usePermission('NETWORK_MAP');
  const [mapPlacements, setMapPlacements] = useState<Record<string, string>>({});
  const [mapHistory, setMapHistory] = useState<Record<string, string>[]>([]);
  const [mapError, setMapError] = useState<string | null>(null);
  const [confirmMapReset, setConfirmMapReset] = useState(false);
  useEffect(() => {
    let live = true;
    setMapPlacements({});
    setMapHistory([]);
    networkMapEditsService
      .get(fileId)
      .then(e => live && setMapPlacements(e.placements ?? {}))
      .catch(() => live && setMapPlacements({}));
    return () => {
      live = false;
    };
  }, [fileId]);
  const saveMap = (next: Record<string, string>, previous: Record<string, string>) => {
    setMapPlacements(next);
    setMapError(null);
    networkMapEditsService.save(fileId, { placements: next }).catch(() => {
      setMapPlacements(previous);
      setMapError("The network map change couldn't be saved, so it was undone.");
    });
  };
  const moveDevice = (nodeId: string, groupId: string) => {
    // Back into its automatic group: no placement needed.
    const auto = leafGroups(buildGroupTree(filteredNodes, { segments: networkSegments, customRanges: customPrivateRanges, dnsNames }));
    const automatic = [...auto.values()].find(g => g.nodeIds.includes(nodeId))?.id;
    const next = { ...mapPlacements };
    if (groupId === automatic) delete next[nodeId];
    else next[nodeId] = groupId;
    setMapHistory(h => [...h.slice(-49), mapPlacements]);
    saveMap(next, mapPlacements);
  };
  const undoMapEdit = () => {
    const previous = mapHistory[mapHistory.length - 1];
    if (!previous) return;
    setMapHistory(h => h.slice(0, -1));
    saveMap(previous, mapPlacements);
  };
  const resetMap = () => {
    setConfirmMapReset(false);
    const previous = mapPlacements;
    setMapPlacements({});
    setMapHistory([]);
    networkMapEditsService.reset(fileId).catch(() => {
      setMapPlacements(previous);
      setMapError("The network map couldn't be reset.");
    });
  };
  const mapEdited = Object.keys(mapPlacements).length > 0;

  // The network map, as a draw.io diagram: grouped the same way, whatever layout is showing.
  const nodeLabelConfig = useStore(st => st.nodeLabelConfig);
  const downloadMap = () => {
    const layout = layoutGroups(
      buildGroupTree(filteredNodes, { segments: networkSegments, customRanges: customPrivateRanges, dnsNames, placements: mapPlacements }),
    );
    const name = (data?.fileName ?? 'capture').replace(/\.(pcapng|pcap|cap)$/i, '');
    downloadDrawio(toDrawio(layout, filteredNodes, filteredEdges, n => buildNodeLines(n, nodeLabelConfig), `${name} — network map`), `${name}-network-map`);
  };

  const navigate = useNavigate();
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const toggleGhostFilter = toggleSet(setActiveGhostFilters);
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
    setActiveGhostFilters([]);
    setHasRisksOnly(false);
  };

  // The network map is the default here: devices grouped by network, subnet and type.
  const [layoutType, setLayoutType] = useState<GraphLayoutType>('grouped');

  const isDark = useResolvedDark();
  const [edgeColorMode, setEdgeColorMode] = useState<EdgeColorMode>('transport');
  const [showHeatmap, setShowHeatmap] = useState(false);
  const [isHeatmapFullscreen, setIsHeatmapFullscreen] = useState(false);
  const [selectedPair, setSelectedPair] = useState<VolumePair | null>(null);

  const graphCardRef = useRef<HTMLDivElement>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const toggleFullscreen = () => setIsFullscreen(f => !f);

  // Fullscreen is the bottom Escape layer: the filter/label modals (SGDS modals, which stack above
  // the fullscreen card) and the node detail panel (its own layer) each own Escape while open, so
  // leaving fullscreen is what happens once nothing is stacked over it.
  useEscapeLayer(() => setIsFullscreen(false), { enabled: isFullscreen, ref: graphCardRef });

  // ─── "Present" sets: only show options that exist in the data ───────────────

  const presentIdentities = useMemo(() => {
    const ids = new Set<string>();
    nodes.forEach(n => ids.add(nodeIdentityKey(n.data)));
    return ids;
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

  const presentGhostFlags = useMemo(() => {
    const flags = new Set<string>();
    nodes.forEach(n => n.data.ghostFlags?.forEach(f => flags.add(f)));
    return flags;
  }, [nodes]);

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
              if (key.startsWith('id:')) return nodeIdentityKey(n.data) === key.slice(3);
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

    // Ghost filter: hide nodes matching active ghost types and their edges
    const hiddenGhostIds = new Set<string>(
      activeGhostFilters.length > 0
        ? nodes
            .filter(n => n.data.ghostFlags?.some(flag => activeGhostFilters.includes(flag)))
            .map(n => n.id)
        : []
    );
    if (hiddenGhostIds.size > 0) {
      filtered = filtered.filter(e => !hiddenGhostIds.has(e.source) && !hiddenGhostIds.has(e.target));
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
      activeGhostFilters.length > 0 ||
      hasRisksOnly ||
      ipFilter.length > 0 ||
      portFilter.length > 0;

    const ipLower = ipFilter.toLowerCase();
    // Start with ghost-hidden nodes already excluded so IP search can't resurface them.
    let visibleNodes = nodes.filter(n => !hiddenGhostIds.has(n.id));
    if (ipFilter) {
      visibleNodes = visibleNodes.filter(
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
        n => !hiddenGhostIds.has(n.id) && (visibleNodeIds.has(n.id) || (ipFilter && matchedByIp.has(n.id)))
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
    activeGhostFilters,
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
    activeGhostFilters.length +
    (ipFilter ? 1 : 0) +
    (portFilter ? 1 : 0) +
    (hasRisksOnly ? 1 : 0);

  // Volume range of the *current* view. Derived with the same helper the graph
  // paints with, so the legend can never describe a different domain than the
  // edges it explains.
  const edgeRange = useMemo(() => edgeBytesRange(filteredEdges), [filteredEdges]);

  // Time axis: the capture's span, and what was active in the chosen window (null = all of it).
  const [timeWindow, setTimeWindow] = useState<TimeWindow | null>(null);
  // Traffic dots along the edges: on unless the system asks for reduced motion.
  const [animateTraffic, setAnimateTraffic] = useState(
    () => !(typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches),
  );
  const bounds = useMemo(() => timeBounds(edges), [edges]);
  useEffect(() => setTimeWindow(null), [fileId]);
  // Nodes not seen yet by the window's end are hidden when that option is on.
  const [appearWhenSeen, setAppearWhenSeen] = useState(false);
  const [fullscreenHint, setFullscreenHint] = useState(0);
  const [unseenStyle, setUnseenStyle] = useState<'hide' | 'faint'>('hide');
  // Play by a sliding time window, or packet by packet (replay).
  const [axisMode, setAxisMode] = useState<AxisMode>('window');
  useEffect(() => setAxisMode('window'), [fileId]);
  const replay = usePacketReplay(fileId, axisMode === 'packets');
  // In replay, the graph shows the instant of the current moment: the conversations open then.
  const replayT = axisMode === 'packets' ? replay.moment?.t : undefined;
  const axisWindow = useMemo<TimeWindow | null>(
    () => (axisMode === 'packets' ? (replayT != null ? { from: replayT, to: replayT } : null) : timeWindow),
    [axisMode, replayT, timeWindow],
  );
  const windowActive = useMemo(() => {
    if (!axisWindow) return null;
    const active = { ...activeInWindow(filteredEdges, axisWindow), window: axisWindow };
    if (!appearWhenSeen) return active;
    const unseen = unseenByWindowEnd(filteredEdges, axisWindow);
    return unseenStyle === 'faint' ? { ...active, faintNodeIds: unseen } : { ...active, hiddenNodeIds: unseen };
  }, [filteredEdges, axisWindow, appearWhenSeen, unseenStyle]);
  // Each conversation's ends on the graph, so a replayed packet knows which edge to fly along.
  const conversationEnds = useMemo(() => {
    const ipOf = new Map(filteredNodes.map(n => [n.id, n.data.ip]));
    const m = new Map<string, ConversationEnds>();
    for (const e of filteredEdges) {
      m.set(e.data.conversationId, { source: e.source, target: e.target, sourceIp: ipOf.get(e.source) ?? '' });
    }
    return m;
  }, [filteredEdges, filteredNodes]);
  const replayFlights = useMemo(() => {
    const m = replay.moment;
    if (axisMode !== 'packets' || !m) return null;
    const flights = flightsFor(m, conversationEnds).map(f => ({ from: f.from, to: f.to, color: getProtocolColor(f.protocol) }));
    return {
      key: m.packets[0].number,
      flights,
      durationMs: Math.min(900, Math.max(180, 800 / replay.speed)),
      offGraph: m.packets.length - flights.length,
    };
  }, [axisMode, replay.moment, replay.speed, conversationEnds]);
  // Same-device links between nodes both still shown after the filters.
  const shownDeviceLinks = useMemo(() => {
    const ids = new Set(filteredNodes.map(n => n.id));
    return deviceLinks.filter(l => ids.has(l.from) && ids.has(l.to));
  }, [deviceLinks, filteredNodes]);
  const windowedEdges = useMemo(
    () => (windowActive ? filteredEdges.filter(e => windowActive.edgeIds.has(e.id)) : filteredEdges),
    [filteredEdges, windowActive],
  );
  const windowedNodes = useMemo(
    () => (windowActive ? filteredNodes.filter(n => windowActive.nodeIds.has(n.id)) : filteredNodes),
    [filteredNodes, windowActive],
  );

  // Cross-filter: a selected heatmap cell highlights that pair in the diagram.
  // `highlightedNodes` is keyed by node *label*, not id, so translate first.
  const highlightedNodes = useMemo(() => {
    if (!selectedPair) return undefined;
    const labelById = new Map(filteredNodes.map(n => [n.id, n.label]));
    const map = new Map<string, NodeHighlight>();
    const src = labelById.get(selectedPair.source);
    const dst = labelById.get(selectedPair.target);
    if (src) map.set(src, { color: '#0d6efd', label: 'src', description: 'Selected pair — source' });
    if (dst) map.set(dst, { color: '#0d6efd', label: 'dst', description: 'Selected pair — destination' });
    return map.size > 0 ? map : undefined;
  }, [selectedPair, filteredNodes]);

  // Keep the parent's ref up to date with the currently visible graph state so
  // the report button captures exactly what the user sees.
  useEffect(() => {
    if (!networkGraphStateRef) return;
    const labels = buildActiveFilterLabels({
      ipFilter, portFilter, hasRisksOnly,
      activeLegendProtocols, activeNodeFilters, activeAppFilters,
      activeL7Protocols, activeCategories, activeRiskTypes,
      activeCustomSigs, activeFileTypes, activeCountries,
      activeGhostFilters,
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
      <div className="mb-3">
        <h4 className="mb-1">
          <i className="bi bi-diagram-3 me-2"></i>
          Network Topology Diagram
        </h4>
        <p className="text-muted small mb-0">
          Visualise individual hosts and the connections between them. Best for captures with fewer than 50 hosts —
          for larger captures, use the <strong>Network Cluster</strong> tab for a cluster-level overview.
        </p>
      </div>

      {CONVERSATION_LIMIT_ENABLED &&
        (stats.isLimited ? (
          <Alert variant="warning" className="mb-3">
            <i className="bi bi-exclamation-triangle me-2"></i>
            <strong>Performance limit active:</strong> Showing top{' '}
            {stats.displayedConversations?.toLocaleString()} of{' '}
            {stats.totalConversations?.toLocaleString()} conversations by packet count. Set{' '}
            <code>VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT=false</code> to render all.
          </Alert>
        ) : (
          <Alert variant="info" className="mb-3">
            <i className="bi bi-info-circle me-2"></i>
            <strong>Performance limit enabled</strong> — all{' '}
            {stats.totalConversations?.toLocaleString()} conversations are within the 500-connection
            limit and fully rendered.
          </Alert>
        ))}

      {/* Row 1: Network Statistics */}
      <Card className="mb-3">
        <Card.Header>
          <strong>Diagram Overview</strong>
        </Card.Header>
        <Card.Body className="py-2 px-3">
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
        </Card.Body>
      </Card>

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
            <Alert variant="info" className="mb-3">
              <div className="d-flex align-items-start gap-2 flex-wrap">
                <Button
                  variant="link"
                  className="p-0 border-0 mt-1 flex-shrink-0"
                  style={{ lineHeight: 1 }}
                  title="How is significance determined?"
                  onClick={() => setShowSignificanceModal(true)}
                >
                  <i className="bi bi-info-circle"></i>
                </Button>
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
                      <Button
                        key={p}
                        size="sm"
                        variant={nodeLimit === p ? 'info' : 'outline-secondary'}
                        style={{ minWidth: 52 }}
                        onClick={() => setNodeLimit(p)}
                      >
                        Top {p}
                      </Button>
                    ))}
                    <Button
                      size="sm"
                      variant={nodeLimit >= totalNodes ? 'info' : 'outline-secondary'}
                      style={{ minWidth: 52 }}
                      onClick={() => setNodeLimit(totalNodes)}
                    >
                      All {totalNodes}
                    </Button>
                    <span className="text-muted small ms-2 me-1">or</span>
                    <div className="input-group input-group-sm" style={{ width: 120 }}>
                      <Form.Control
                        type="number"
                        size="sm"
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
            </Alert>
          );
        })()}

      {/* Row 2: Graph full width */}
      <div className="row">
        <div className="col-12">
          <Card className={isFullscreen ? 'nd-css-fullscreen' : ''} ref={graphCardRef}>
            <Card.Header className="d-flex justify-content-between align-items-center">
              <strong>Topology Diagram</strong>
              <div className="d-flex align-items-center gap-3 flex-wrap">
                {/* Colour is a single channel — transport, application, and volume are offered as
                    alternatives rather than layered, and the active one is always accompanied by
                    its legend. Transport = base protocol (TCP/UDP/ICMP); Application = deepest
                    identified protocol (HTTPS, DNS, QUIC…). */}
                <div className="d-flex align-items-center gap-2">
                  <Form.Label className="mb-0 text-muted small">Color edges by</Form.Label>
                  <Form.Select
                    size="sm"
                    style={{ width: 130 }}
                    value={edgeColorMode}
                    onChange={e => setEdgeColorMode(e.target.value as EdgeColorMode)}
                  >
                    <option value="transport">Transport</option>
                    <option value="application">Application</option>
                    <option value="volume">Volume</option>
                  </Form.Select>
                </div>
                {edgeColorMode === 'volume' && (
                  <VolumeLegend
                    maxValue={edgeRange.max}
                    minValue={edgeRange.min}
                    dark={isDark}
                    variant="edge"
                    label="Edge volume"
                  />
                )}
                {layoutType === 'grouped' && mapHistory.length > 0 && (
                  <Button variant="link" size="sm" className="p-0 text-muted" onClick={undoMapEdit}>
                    <i className="bi bi-arrow-90deg-left me-1" aria-hidden="true" />
                    Undo move
                  </Button>
                )}
                {layoutType === 'grouped' && mapEdited && mapPermission.allowed && (
                  <Button variant="link" size="sm" className="p-0 text-muted" onClick={() => setConfirmMapReset(true)}>
                    Reset map
                  </Button>
                )}
                <Button
                  variant="link"
                  size="sm"
                  className="p-0 text-muted"
                  onClick={downloadMap}
                  disabled={filteredNodes.length === 0}
                  title="Download the network map as a draw.io diagram"
                  aria-label="Download the network map as a draw.io diagram"
                >
                  <i className="bi bi-download" aria-hidden="true" />
                </Button>
                <Button
                  variant="link"
                  size="sm"
                  className="p-0 text-muted"
                  onClick={() => setShowLabelModal(true)}
                  title="Customize node labels"
                >
                  <i className="bi bi-tags" />
                </Button>
                <FullscreenToggle isFullscreen={isFullscreen} onToggle={toggleFullscreen} hintSignal={fullscreenHint} hintId="fullscreen-hint-diagram" />
              </div>
            </Card.Header>
            {mapError && (
              <Alert variant="danger" className="m-2 mb-0" dismissible onClose={() => setMapError(null)}>
                {mapError}
              </Alert>
            )}
            <Card.Body className="p-0 network-diagram-graph-body">
              <NetworkGraph
                key={layoutType}
                onFitViewRepeated={() => setFullscreenHint(n => n + 1)}
                networkSegments={networkSegments}
                customPrivateRanges={customPrivateRanges}
                dnsNames={dnsNames}
                mapPlacements={mapPlacements}
                onMoveToGroup={mapPermission.allowed ? moveDevice : undefined}
                nodes={filteredNodes}
                edges={filteredEdges}
                hiddenNodesList={hiddenNodesList}
                crossEdges={crossEdges}
                onNodeClick={node => setSelectedNode(node)}
                layoutType={layoutType}
                onLayoutChange={setLayoutType}
                onFilterClick={() => setShowFilterModal(true)}
                activeFilterCount={activeFilterCount}
                edgeColorMode={edgeColorMode}
                highlightedNodes={highlightedNodes}
                activeInWindow={windowActive}
                animateTraffic={animateTraffic && axisMode === 'window'}
                packetFlights={replayFlights}
                bottomBar={
                  bounds && bounds.to > bounds.from && axisMode === 'packets' ? (
                    <PacketReplayBar
                      edges={filteredEdges}
                      bounds={bounds}
                      replay={replay}
                      onModeChange={setAxisMode}
                      offGraph={replayFlights?.offGraph ?? 0}
                    />
                  ) : bounds && bounds.to > bounds.from ? (
                    <TimeScrubber
                      onModeChange={setAxisMode}
                      edges={filteredEdges}
                      bounds={bounds}
                      window={timeWindow}
                      onWindowChange={setTimeWindow}
                      activeCount={windowActive ? windowActive.edgeIds.size : filteredEdges.length}
                      animate={animateTraffic}
                      onAnimateChange={setAnimateTraffic}
                      appearWhenSeen={appearWhenSeen}
                      onAppearWhenSeenChange={setAppearWhenSeen}
                      unseenStyle={unseenStyle}
                      onUnseenStyleChange={setUnseenStyle}
                    />
                  ) : undefined
                }
                deviceLinks={shownDeviceLinks}
              />
            </Card.Body>
          </Card>
        </div>
      </div>

      {/* Row 3: Node-to-node volume matrix.
          The diagram answers "who talks to whom"; this answers "how much", which a
          force-directed layout cannot show. Both read the same filtered edges. */}
      {isHeatmapFullscreen ? (
        <Modal show onHide={() => setIsHeatmapFullscreen(false)} fullscreen>
          <Modal.Header closeButton>
            <Modal.Title>
              <strong>Node-to-Node Volume</strong>
              <span className="text-muted small ms-2">
                Traffic between each pair of displayed hosts
              </span>
            </Modal.Title>
          </Modal.Header>
          <Modal.Body className="tp-heatmap-body">
            <VolumeHeatmap
              nodes={windowedNodes}
              edges={windowedEdges}
              dark={isDark}
              focusedHost={selectedNode?.id ?? null}
              selectedPair={selectedPair}
              onCellClick={setSelectedPair}
              onHostClick={setSelectedNode}
            />
          </Modal.Body>
        </Modal>
      ) : (
        <Card className="mt-3">
          <Card.Header className="d-flex justify-content-between align-items-center">
            <div>
              <strong>Node-to-Node Volume</strong>
              <span className="text-muted small ms-2">
                Traffic between each pair of displayed hosts
              </span>
            </div>
            <div className="d-flex align-items-center gap-3">
              {showHeatmap && (
                <Button
                  variant="link"
                  size="sm"
                  className="p-0 text-muted"
                  onClick={() => setIsHeatmapFullscreen(true)}
                  title="Fullscreen"
                >
                  <i className="bi bi-fullscreen" />
                </Button>
              )}
              <Button
                variant="link"
                size="sm"
                className="p-0 text-muted"
                onClick={() => setShowHeatmap(s => !s)}
                aria-expanded={showHeatmap}
              >
                {showHeatmap ? 'Hide' : 'Show'}
                <i className={`bi ms-1 ${showHeatmap ? 'bi-chevron-up' : 'bi-chevron-down'}`} />
              </Button>
            </div>
          </Card.Header>
          {showHeatmap && (
            <Card.Body className="tp-heatmap-body">
              <VolumeHeatmap
                nodes={windowedNodes}
                edges={windowedEdges}
                dark={isDark}
                focusedHost={selectedNode?.id ?? null}
                selectedPair={selectedPair}
                onCellClick={setSelectedPair}
                onHostClick={setSelectedNode}
              />
            </Card.Body>
          )}
        </Card>
      )}

      {selectedNode && (
        <EntityDetailModal
          {...graphNodeEntity(selectedNode)}
          fileId={fileId}
          graphNode={selectedNode}
          graphEdges={edges}
          onNavigate={navigate}
          onClose={() => setSelectedNode(null)}
        />
      )}

      <Modal show={confirmMapReset} onHide={() => setConfirmMapReset(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Reset the network map?</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          Every device you moved goes back to its automatic group, for everyone who opens this capture.
          This can't be undone.
        </Modal.Body>
        <Modal.Footer>
          <Button variant="outline-secondary" onClick={() => setConfirmMapReset(false)}>
            Cancel
          </Button>
          <Button variant="primary" onClick={resetMap}>
            Reset map
          </Button>
        </Modal.Footer>
      </Modal>

      <NodeLabelSettingsModal
        show={showLabelModal}
        onHide={() => setShowLabelModal(false)}
        container={graphCardRef.current ?? undefined}
      />

      <Modal
        show={showFilterModal}
        onHide={() => setShowFilterModal(false)}
        size="lg"
        container={graphCardRef.current ?? undefined}
      >
        <Modal.Header closeButton>
          <Modal.Title>Filters</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <NetworkControls
            activeLegendProtocols={activeLegendProtocols}
            onLegendProtocolClick={toggleLegendProtocol}
            onLegendProtocolClear={() => setActiveLegendProtocols([])}
            activeNodeFilters={activeNodeFilters}
            onNodeFilterClick={toggleNodeFilter}
            onNodeFilterClear={() => setActiveNodeFilters([])}
            presentIdentities={presentIdentities}
            presentEdgeLegendKeys={presentEdgeLegendKeys}
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
            activeGhostFilters={activeGhostFilters}
            onGhostFilterClick={toggleGhostFilter}
            onGhostFilterClear={() => setActiveGhostFilters([])}
            presentGhostFlags={presentGhostFlags}
            activeFilterCount={activeFilterCount}
            onClearAllFilters={clearAllFilters}
          />
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowFilterModal(false)}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>

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
          <Button variant="secondary" onClick={() => setShowSignificanceModal(false)}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};
