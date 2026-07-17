import type { Conversation, AnalysisSummary, HostClassification, HostIdentity } from '@/types';
import type {
  GraphNode,
  GraphEdge,
  NetworkGraphData,
  NetworkStats,
  NodeMap,
  NodeType,
} from '../types';

/** MAC address regex — identifies nodes that have no IP and are addressed by MAC only */
const MAC_REGEX = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

function isMacAddress(id: string): boolean {
  return MAC_REGEX.test(id);
}

/**
 * Classify a node type from its inbound port frequency map, distinct peer count,
 * and the set of nDPI appName values observed on inbound edges.
 *
 * Classification order (highest priority first):
 *   1. nDPI appName (NDPI_APP_MAP) — accurate even on non-standard ports / encrypted flows
 *   2. Well-known port (PORT_SERVICE_MAP) — fallback when appName is unavailable
 *   3. Router heuristic — many distinct peers
 *   4. Generic client / unknown
 *
 * serverPorts: { "53/UDP": 42, "80/TCP": 1 } — counts of connections received on each port.
 * ndpiApps: set of distinct nDPI appName strings seen on inbound edges.
 */
/**
 * The port a node most often served on — the busiest of its well-known ports. Evidence only: it is
 * shown in the details panel as one input the backend weighed, not used here to decide anything.
 * Deciding what a host *is* moved to the adjudicator (#521); this is a fact, not a judgment.
 */
function dominantServerPort(serverPorts: Record<string, number>): string | null {
  let best: string | null = null;
  let max = 0;
  for (const [portProto, count] of Object.entries(serverPorts)) {
    if (count > max) {
      max = count;
      best = portProto;
    }
  }
  return best;
}

/**
 * Create a new graph node from a network endpoint
 */
function createNode(ip: string, hostname?: string, mac?: string): GraphNode {
  const isL2 = isMacAddress(ip);
  return {
    id: ip,
    label: hostname || ip,
    data: {
      ip,
      mac: isL2 ? ip : mac, // for MAC-identified nodes, the "ip" field IS the MAC
      hostname,
      isL2,
      packetsSent: 0,
      packetsReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      totalBytes: 0,
      role: 'unknown',
      protocols: [],
      connections: 0,
      nodeType: isL2 ? 'l2-device' : 'unknown',
      nodeTypeEvidence: { dominantPort: null, connectionCount: 0, distinctPeers: 0 },
    },
  };
}

/**
 * Update node statistics based on conversation data
 */
function updateNodeStats(
  node: GraphNode,
  conversation: Conversation,
  direction: 'sent' | 'received',
  protocol: string
) {
  if (direction === 'sent') {
    node.data.packetsSent += conversation.packetCount;
    node.data.bytesSent += conversation.totalBytes;
  } else {
    node.data.packetsReceived += conversation.packetCount;
    node.data.bytesReceived += conversation.totalBytes;
  }

  node.data.totalBytes = node.data.bytesSent + node.data.bytesReceived;

  // Add protocol if not already tracked
  if (!node.data.protocols.includes(protocol)) {
    node.data.protocols.push(protocol);
  }

  node.data.connections += 1;
}

/**
 * Create a graph edge from a conversation
 */
function createEdge(conversation: Conversation, srcIp: string, dstIp: string): GraphEdge {
  const protocol = conversation.protocol.name.toUpperCase();
  const rawName = conversation.appName ?? protocol;
  const labelName = rawName.charAt(0).toUpperCase() + rawName.slice(1);

  const flowRisks = conversation.flowRisks ?? [];
  return {
    id: conversation.id,
    source: srcIp,
    target: dstIp,
    label: `${labelName} (${conversation.packetCount})`,
    data: {
      protocol,
      appName: conversation.appName,
      packetCount: conversation.packetCount,
      totalBytes: conversation.totalBytes,
      conversationId: conversation.id,
      bidirectional: conversation.direction === 'bidirectional',
      srcPort: conversation.endpoints[0]?.port,
      dstPort: conversation.endpoints[1]?.port,
      l7Protocol: conversation.tsharkProtocol,
      category: conversation.category,
      flowRisks,
      customSignatures: conversation.customSignatures ?? [],
      suricataAlerts: conversation.suricataAlerts ?? [],
      detectedFileTypes: conversation.detectedFileTypes ?? [],
      srcCountry: conversation.srcGeo?.countryCode,
      dstCountry: conversation.dstGeo?.countryCode,
      hasRisks: flowRisks.length > 0,
    },
  };
}

/**
 * Calculate network statistics from nodes and edges
 */
function calculateNetworkStats(nodeMap: NodeMap, edges: GraphEdge[]): NetworkStats {
  const nodes = Array.from(Object.values(nodeMap));
  const protocolBreakdown: { [protocol: string]: number } = {};

  // Calculate total packets and bytes
  const totalPackets = nodes.reduce((sum, node) => sum + node.data.packetsSent, 0);
  const totalBytes = nodes.reduce((sum, node) => sum + node.data.bytesSent, 0);

  // Calculate protocol breakdown
  edges.forEach(edge => {
    const protocol = edge.data.protocol;
    protocolBreakdown[protocol] = (protocolBreakdown[protocol] || 0) + edge.data.packetCount;
  });

  return {
    totalNodes: nodes.length,
    totalEdges: edges.length,
    totalPackets,
    totalBytes,
    protocolBreakdown,
  };
}

/**
 * Determine final node role based on observed behavior
 */
/**
 * Records what one conversation says about a node's role, using who opened it (#496).
 *
 * <p>This replaces a pair of functions that guessed from port numbers — "< 1024 means server",
 * then ORed 'server' across *both* endpoints, so a host talking from :51000 to a router's :80 was
 * itself marked a server. The guess existed because the real signal was destroyed at parse time;
 * now the backend records who sent SYN without ACK, so we can just read it.
 *
 * <p>Roles accumulate across flows rather than being overwritten: a host that opens some
 * connections and answers others is genuinely 'both', and the last conversation parsed should not
 * decide. A node whose flows carry no initiator (UDP, ARP, a capture that joined mid-stream) keeps
 * whatever it had — unknown is the honest answer, and guessing is what this removes.
 */
function applyRoleFromInitiator(node: GraphNode, conv: Conversation) {
  if (node.data.isL2) return;
  if (!conv.initiatorIp) return; // unknown — say nothing rather than guess

  const isInitiator = conv.initiatorIp === node.data.ip;
  const roleHere: 'client' | 'server' = isInitiator ? 'client' : 'server';

  // 'unknown' is the initial value AND a truthy string, so a bare `!role` check would skip the
  // first assignment and mark every node 'both' on its second flow — which would defeat the whole
  // point of reading the fact. Treat 'unknown' as "not yet set".
  if (!node.data.role || node.data.role === 'unknown') {
    node.data.role = roleHere;
  } else if (node.data.role !== roleHere) {
    node.data.role = 'both';
  }
}

/**
 * Select the most significant nodes to render in the topology diagram.
 *
 * Significance score (0–1):
 *   0.5 × (totalBytes / maxBytes)         — traffic dominance
 *   0.3 × (nodeHasRisk ? 1 : 0)           — connected to a risky edge
 *   0.2 × (connections / maxConnections)  — structural hub-ness
 *
 * Returns the selected nodes and the count of nodes that were hidden.
 */
export function selectSignificantNodes(
  nodes: GraphNode[],
  edges: GraphEdge[],
  limit: number
): {
  significantNodes: GraphNode[];
  hiddenCount: number;
  hiddenNodesList: GraphNode[];
  crossEdges: GraphEdge[];
} {
  if (nodes.length <= limit) {
    return { significantNodes: nodes, hiddenCount: 0, hiddenNodesList: [], crossEdges: [] };
  }

  // Build per-node risk flag from edges — includes nDPI flow risks and custom rule matches
  const nodeHasRisk = new Map<string, boolean>();
  for (const e of edges) {
    if (
      e.data.hasRisks ||
      (e.data.flowRisks?.length ?? 0) > 0 ||
      (e.data.customSignatures?.length ?? 0) > 0
    ) {
      nodeHasRisk.set(e.source, true);
      nodeHasRisk.set(e.target, true);
    }
  }

  // Normalisation denominators (avoid division by zero)
  const maxBytes = nodes.reduce((max, n) => Math.max(max, n.data.totalBytes), 1);
  const maxConns = nodes.reduce((max, n) => Math.max(max, n.data.connections), 1);

  const scored = nodes.map(n => ({
    node: n,
    score:
      0.5 * (n.data.totalBytes / maxBytes) +
      0.3 * (nodeHasRisk.get(n.id) ? 1 : 0) +
      0.2 * (n.data.connections / maxConns),
  }));

  scored.sort((a, b) => b.score - a.score);

  const significantNodes = scored.slice(0, limit).map(s => s.node);
  const sigNodeIds = new Set(significantNodes.map(n => n.id));
  const hiddenNodesList = nodes.filter(n => !sigNodeIds.has(n.id));

  // Cross-edges: exactly one endpoint is hidden (visible ↔ hidden connections)
  const crossEdges = edges.filter(e => sigNodeIds.has(e.source) !== sigNodeIds.has(e.target));

  return { significantNodes, hiddenCount: hiddenNodesList.length, hiddenNodesList, crossEdges };
}

/**
 * Transform conversations into graph nodes and edges
 * @param conversations - Array of conversations to visualize
 * @param analysisSummary - Optional analysis summary used to seed unique hosts and override packet totals
 * @param maxConversations - Maximum number of conversations to render (default: 500)
 * @param hostClassifications - Optional per-IP device classifications from the backend
 * @param maxNodes - Maximum number of nodes to render (default: 50, 0 = no limit)
 */
export function buildNetworkGraph(
  conversations: Conversation[],
  analysisSummary?: AnalysisSummary,
  maxConversations: number = 500,
  hostClassifications?: HostClassification[],
  maxNodes: number = 50,
  hostIdentities?: HostIdentity[]
): NetworkGraphData {
  const nodeMap: NodeMap = {};
  const edges: GraphEdge[] = [];

  // Per-node tracking for node type classification
  // serverPorts[ip]["53/UDP"] = count of connections received on that port
  const serverPorts: Record<string, Record<string, number>> = {};
  // peerSets[ip] = set of all distinct peer IPs
  const peerSets: Record<string, Set<string>> = {};
  // ndpiAppSets[ip] = set of distinct nDPI appName values seen on inbound edges (dst = ip)
  const ndpiAppSets: Record<string, Set<string>> = {};

  // Ghost/phantom node detection tracking
  const ghostAppearsAsSrc = new Set<string>();
  const ghostAppearsAsDst = new Set<string>();
  const ghostBidirectional = new Set<string>(); // IPs involved in any truly bidirectional conv
  const ghostProtoAsSrc: Record<string, Set<string>> = {};
  const ghostProtoAsDst: Record<string, Set<string>> = {};

  // Seed all known hosts from the analysis summary so the node count matches
  // the "Unique Hosts" figure on the overview, even for hosts that fall outside
  // the conversation rendering limit below.
  if (analysisSummary?.uniqueHosts) {
    for (const host of analysisSummary.uniqueHosts) {
      if (host.ip && !nodeMap[host.ip]) {
        nodeMap[host.ip] = createNode(host.ip, host.hostname);
      }
    }
  }

  // Limit conversations to top N by packet count for performance
  const limitedConversations =
    conversations.length > maxConversations
      ? conversations.sort((a, b) => b.packetCount - a.packetCount).slice(0, maxConversations)
      : conversations;

  // Build nodes and edges from conversations
  limitedConversations.forEach(conv => {
    const [src, dst] = conv.endpoints;
    const protocol = conv.protocol.name.toUpperCase();

    // Create or update source node
    if (!nodeMap[src.ip]) {
      nodeMap[src.ip] = createNode(src.ip, src.hostname, src.mac);
    }
    updateNodeStats(nodeMap[src.ip], conv, 'sent', protocol);

    // Create or update destination node
    if (!nodeMap[dst.ip]) {
      nodeMap[dst.ip] = createNode(dst.ip, dst.hostname, dst.mac);
    }
    updateNodeStats(nodeMap[dst.ip], conv, 'received', protocol);

    // Track well-known port usage for both endpoints.
    // A node sending FROM a well-known port (e.g. DNS response from :53) is
    // just as valid a signal as one receiving ON a well-known port.
    for (const [nodeIp, port] of [
      [dst.ip, dst.port],
      [src.ip, src.port],
    ] as [string, number][]) {
      if (port != null && port < 1024) {
        const portKey = `${port}/${protocol}`;
        if (!serverPorts[nodeIp]) serverPorts[nodeIp] = {};
        serverPorts[nodeIp][portKey] = (serverPorts[nodeIp][portKey] || 0) + 1;
      }
    }

    // Track distinct peers for both endpoints
    if (!peerSets[src.ip]) peerSets[src.ip] = new Set();
    peerSets[src.ip].add(dst.ip);
    if (!peerSets[dst.ip]) peerSets[dst.ip] = new Set();
    peerSets[dst.ip].add(src.ip);

    // Accumulate nDPI appName on the destination node (the server side of the flow).
    // Store uppercased to match NDPI_APP_MAP keys.
    if (conv.appName) {
      if (!ndpiAppSets[dst.ip]) ndpiAppSets[dst.ip] = new Set();
      ndpiAppSets[dst.ip].add(conv.appName.toUpperCase());
    }

    // Create edge
    edges.push(createEdge(conv, src.ip, dst.ip));

    // Ghost node detection: track per-conversation roles and directionality.
    // Use both conv.direction and a direct flowRisks check — ARP conversations
    // are never flagged with 'unidirectional_traffic' by the backend even when
    // the ARP target never replied, so we need the fallback.
    ghostAppearsAsSrc.add(src.ip);
    ghostAppearsAsDst.add(dst.ip);
    const convIsUnidirectional =
      conv.direction === 'unidirectional' ||
      (conv.flowRisks ?? []).includes('unidirectional_traffic');
    if (!convIsUnidirectional) {
      ghostBidirectional.add(src.ip);
      ghostBidirectional.add(dst.ip);
    }
    if (!ghostProtoAsSrc[src.ip]) ghostProtoAsSrc[src.ip] = new Set();
    ghostProtoAsSrc[src.ip].add(protocol);
    if (!ghostProtoAsDst[dst.ip]) ghostProtoAsDst[dst.ip] = new Set();
    ghostProtoAsDst[dst.ip].add(protocol);
  });

  // Roles are derived over EVERY conversation, not just the displayed subset. role comes from who
  // opened the connection (a MEASURED fact, #496), so it must be independent of the packet-count
  // cap that decides what fits on screen — otherwise Present is still adjudicating on a truncated
  // view, which is exactly what #521 removed everywhere else. A node whose only flows were capped
  // out has no entry in nodeMap and is skipped: it is not on the diagram to label.
  conversations.forEach(conv => {
    const [s0, d0] = conv.endpoints;
    if (nodeMap[s0.ip]) applyRoleFromInitiator(nodeMap[s0.ip], conv);
    if (nodeMap[d0.ip]) applyRoleFromInitiator(nodeMap[d0.ip], conv);
  });

  // Node type comes from the backend's adjudicated host identity (see applyIdentities below).
  // It used to be judged here — nDPI app, then well-known port, then peer fan-out — which made
  // this a Scan-stage classifier running in the browser over a *truncated* node set, so a host
  // could classify differently depending on what else fit on screen (#521). The evidence it used
  // is the same evidence the backend already weighs, with a confidence and a contested outcome
  // this code could not express.
  //
  // serverPorts / peerSets / ndpiAppSets are still accumulated: they populate nodeTypeEvidence,
  // which the details panel shows as *why*, and they are facts, not judgments.
  Object.keys(nodeMap).forEach(ip => {
    const d = nodeMap[ip].data;
    if (d.isL2) return; // L2-only nodes keep their pre-assigned type
    const domPort = dominantServerPort(serverPorts[ip] ?? {});
    d.nodeTypeEvidence = {
      dominantPort: domPort,
      connectionCount: domPort ? (serverPorts[ip]?.[domPort] ?? 0) : 0,
      distinctPeers: peerSets[ip]?.size ?? 0,
      ndpiApps: Array.from(ndpiAppSets[ip] ?? new Set<string>()),
    };
  });

  // Compute ghost/phantom node flags for each node in the map
  Object.keys(nodeMap).forEach(ip => {
    const node = nodeMap[ip];
    const ghostFlags: string[] = [];

    const asSrc = ghostAppearsAsSrc.has(ip);
    const asDst = ghostAppearsAsDst.has(ip);
    const bidir = ghostBidirectional.has(ip);
    const dstProtos = ghostProtoAsDst[ip];
    const srcProtos = ghostProtoAsSrc[ip];

    // No response: only appears as dst in unidirectional conversations (any protocol)
    if (!asSrc && asDst && !bidir) {
      ghostFlags.push('no-response');
    }

    // ARP no-reply: only appears as dst in ARP — skip bidir check because the
    // backend never emits 'unidirectional_traffic' for ARP; dst-only is sufficient
    if (!asSrc && asDst && dstProtos?.size === 1 && dstProtos.has('ARP')) {
      ghostFlags.push('arp-no-reply');
    }

    // ICMP unreachable: subset of no-response, only ICMP protocol as dst
    if (
      !asSrc && asDst && !bidir &&
      dstProtos?.size === 1 && (dstProtos.has('ICMP') || dstProtos.has('ICMPV6'))
    ) {
      ghostFlags.push('icmp-unreachable');
    }

    // TTL exceeded: only appears as src in unidirectional ICMP (traceroute intermediate hops)
    if (
      asSrc && !asDst && !bidir &&
      srcProtos?.size === 1 && (srcProtos.has('ICMP') || srcProtos.has('ICMPV6'))
    ) {
      ghostFlags.push('ttl-exceeded');
    }

    if (ghostFlags.length > 0) {
      node.data.ghostFlags = ghostFlags;
    }
  });

  // Adjudicated identities (#512 slice 5b): the display authority where present. A HUMAN basis
  // replaces machine-derived labels outright; contested identities are rendered as contests
  // rather than asserted winners. Files analysed before the adjudicator have no identities and
  // fall back to raw classification display unchanged.
  const identityMap = hostIdentities
    ? new Map(hostIdentities.map(i => [i.ip, i]))
    : undefined;

  // Apply backend device classifications (deviceType, confidence, manufacturer)
  if (hostClassifications) {
    const classMap = new Map(hostClassifications.map(c => [c.ip, c]));
    Object.keys(nodeMap).forEach(ip => {
      const c = classMap.get(ip);
      if (c) {
        nodeMap[ip].data.deviceType = c.deviceType;
        nodeMap[ip].data.serviceRoles = c.serviceRoles;
        nodeMap[ip].data.deviceConfidence = c.confidence;
        nodeMap[ip].data.manufacturer = c.manufacturer;
        nodeMap[ip].data.ttl = c.ttl;
        if (c.mac && !nodeMap[ip].data.mac) nodeMap[ip].data.mac = c.mac;
        // The classifier's hostname identifies the host itself (DHCP/mDNS/NBNS/reverse
        // DNS) and is more authoritative than the SNI-derived conversation hostname.
        if (c.hostname) {
          nodeMap[ip].data.hostname = c.hostname;
          nodeMap[ip].data.hostnameSource = c.hostnameSource;
          if (nodeMap[ip].label === ip) nodeMap[ip].label = c.hostname;
        }
      }
    });
  }


/**
 * Projects the backend's adjudicated identity label onto a {@link NodeType} for rendering (#499).
 *
 * <p>These are two vocabularies for the same question — the adjudicator says `WEB_SERVER`, the
 * graph's config keys on `web-server` — and having them diverge is #499's "two taxonomies, both
 * containing Web Server, disagreeing on colour". The fix is not a third taxonomy: it is to make one
 * a projection of the other, so the adjudicator decides and the graph only renders.
 *
 * Unmapped or absent labels fall through to `unknown`, which is the honest answer for a host the
 * adjudicator did not classify (or a file analysed before the adjudicator existed).
 */
const IDENTITY_LABEL_TO_NODE_TYPE: Record<string, NodeType> = {
  WEB_SERVER: 'web-server',
  API_SERVER: 'web-server',
  DNS_SERVER: 'dns-server',
  ROUTER: 'router',
  SERVER: 'database-server',
  IOT: 'client',
  MOBILE: 'client',
  LAPTOP_DESKTOP: 'client',
};

function nodeTypeFromIdentityLabel(label: string | undefined): NodeType {
  if (!label) return 'unknown';
  return IDENTITY_LABEL_TO_NODE_TYPE[label] ?? 'unknown';
}

  if (identityMap) {
    Object.keys(nodeMap).forEach(ip => {
      const identity = identityMap.get(ip);
      if (!identity) return;
      const d = nodeMap[ip].data;
      d.identityLabel = identity.primaryLabel;
      d.identityBasis = identity.basis;
      d.identityConfidence = identity.confidence;
      d.identityContested = identity.contested;
      d.identityCandidates = identity.candidates ?? undefined;
      // The adjudicated identity IS what this host is — so it drives the rendered nodeType, rather
      // than the browser judging it a second time from ports and nDPI apps (#521). Present renders
      // the conclusion; it does not reach its own.
      d.nodeType = nodeTypeFromIdentityLabel(identity.primaryLabel);
      // A human-confirmed label outranks every machine-derived display value.
      if (identity.basis === 'HUMAN') d.deviceType = undefined;
    });
  }

  // Apply significance-based node cap: keep the top-N most significant nodes
  // and drop edges where either endpoint was hidden.
  const allNodes = Array.from(Object.values(nodeMap));
  const allEdges = edges;

  const { significantNodes, hiddenCount, hiddenNodesList, crossEdges } =
    maxNodes > 0
      ? selectSignificantNodes(allNodes, allEdges, maxNodes)
      : { significantNodes: allNodes, hiddenCount: 0, hiddenNodesList: [], crossEdges: [] };

  const sigNodeIds = new Set(significantNodes.map(n => n.id));
  const significantEdges = allEdges.filter(
    e => sigNodeIds.has(e.source) && sigNodeIds.has(e.target)
  );

  // Calculate statistics, then override packet/byte totals with the authoritative
  // figures from the analysis summary when available. The per-conversation sum
  // misses non-flow traffic (ARP, ICMP, malformed frames, etc.).
  const stats = calculateNetworkStats(nodeMap, significantEdges);
  if (analysisSummary?.totalPackets != null) {
    stats.totalPackets = analysisSummary.totalPackets;
  }

  return {
    nodes: significantNodes,
    edges: significantEdges,
    stats,
    isLimited: conversations.length > maxConversations,
    totalConversations: conversations.length,
    displayedConversations: limitedConversations.length,
    hiddenNodes: hiddenCount,
    hiddenNodesList,
    crossEdges,
  };
}

/** Returns true if an edge's protocol/app matches a legend key (e.g. HTTPS, ICMP, STP). */
export function edgeMatchesLegendKey(proto: string, app: string, key: string): boolean {
  if (key === 'HTTPS')
    return proto === 'HTTPS' || app.includes('TLS') || app.includes('SSL') || app.includes('HTTPS');
  if (key === 'ICMP') return proto === 'ICMP' || proto === 'ICMPV6';
  if (key === 'STP') return proto === 'STP' || proto === 'RSTP';
  return proto === key || app.includes(key);
}

/**
 * Apply the standard set of client-side network-diagram filters to a graph.
 * Used in both NetworkDiagramPage (live UI) and AnalysisPage (PDF fallback).
 * Centralised here so both sites stay in sync automatically.
 */
export function applyNetworkFilters(
  allNodes: GraphNode[],
  allEdges: GraphEdge[],
  filters: {
    hasRisksOnly: boolean;
    activeLegendProtocols: string[];
    activeAppFilters: string[];
    activeL7Protocols: string[];
    activeCategories: string[];
    activeRiskTypes: string[];
    activeCustomSigs: string[];
    activeFileTypes: string[];
    activeCountries: string[];
    activeNodeFilters: string[];
    portFilter: string;
    ipFilter: string;
    /** Ghost node flags to hide (e.g. 'no-response', 'arp-no-reply', 'ttl-exceeded', 'icmp-unreachable'). */
    activeGhostFilters?: string[];
  }
): { filteredNodes: GraphNode[]; filteredEdges: GraphEdge[] } {
  const {
    hasRisksOnly,
    activeLegendProtocols,
    activeAppFilters,
    activeL7Protocols,
    activeCategories,
    activeRiskTypes,
    activeCustomSigs,
    activeFileTypes,
    activeCountries,
    activeNodeFilters,
    portFilter,
    ipFilter,
    activeGhostFilters = [],
  } = filters;

  let fe = allEdges;

  if (hasRisksOnly) fe = fe.filter(e => e.data.hasRisks);

  if (activeLegendProtocols.length > 0)
    fe = fe.filter(e => {
      const p = e.data.protocol.toUpperCase();
      const a = (e.data.appName ?? '').toUpperCase();
      return activeLegendProtocols.some(k => edgeMatchesLegendKey(p, a, k));
    });

  if (activeAppFilters.length > 0)
    fe = fe.filter(e => activeAppFilters.includes(e.data.appName ?? ''));

  if (activeL7Protocols.length > 0)
    fe = fe.filter(e => activeL7Protocols.includes(e.data.l7Protocol ?? ''));

  if (activeCategories.length > 0)
    fe = fe.filter(e => activeCategories.includes(e.data.category ?? ''));

  if (activeRiskTypes.length > 0)
    fe = fe.filter(e => activeRiskTypes.some(r => e.data.flowRisks?.includes(r)));

  if (activeCustomSigs.length > 0)
    fe = fe.filter(e => activeCustomSigs.some(s => e.data.customSignatures?.includes(s)));

  if (activeFileTypes.length > 0)
    fe = fe.filter(e => activeFileTypes.some(f => e.data.detectedFileTypes?.includes(f)));

  if (activeCountries.length > 0)
    fe = fe.filter(
      e =>
        activeCountries.includes(e.data.srcCountry ?? '') ||
        activeCountries.includes(e.data.dstCountry ?? '')
    );

  if (activeNodeFilters.length > 0) {
    const matchIds = new Set(
      allNodes
        .filter(n =>
          activeNodeFilters.some(k => {
            if (k.startsWith('nt:')) return n.data.nodeType === k.slice(3);
            if (k.startsWith('dt:')) return n.data.deviceType === k.slice(3);
            return false;
          })
        )
        .map(n => n.id)
    );
    fe = fe.filter(e => matchIds.has(e.source) || matchIds.has(e.target));
  }

  if (portFilter) {
    const portNum = parseInt(portFilter, 10);
    if (!isNaN(portNum))
      fe = fe.filter(e => e.data.srcPort === portNum || e.data.dstPort === portNum);
  }

  // Ghost filter: hide nodes matching the active ghost types and their edges
  if (activeGhostFilters.length > 0) {
    const ghostIds = new Set(
      allNodes
        .filter(n => n.data.ghostFlags?.some(flag => activeGhostFilters.includes(flag)))
        .map(n => n.id)
    );
    fe = fe.filter(e => !ghostIds.has(e.source) && !ghostIds.has(e.target));
  }

  const visibleIds = new Set<string>();
  fe.forEach(e => { visibleIds.add(e.source); visibleIds.add(e.target); });
  let fn = allNodes.filter(n => visibleIds.has(n.id));

  if (ipFilter) {
    const ipLower = ipFilter.toLowerCase();
    const ipMatchIds = new Set(
      allNodes
        .filter(
          n =>
            n.data.ip.toLowerCase().includes(ipLower) ||
            (n.data.hostname ?? '').toLowerCase().includes(ipLower)
        )
        .map(n => n.id)
    );
    fe = fe.filter(e => ipMatchIds.has(e.source) || ipMatchIds.has(e.target));
    const ipVisibleIds = new Set<string>();
    fe.forEach(e => { ipVisibleIds.add(e.source); ipVisibleIds.add(e.target); });
    fn = allNodes.filter(n => ipVisibleIds.has(n.id) || ipMatchIds.has(n.id));
  }

  return { filteredNodes: fn, filteredEdges: fe };
}

export const networkService = {
  buildNetworkGraph,
  applyNetworkFilters,
  edgeMatchesLegendKey,
};
