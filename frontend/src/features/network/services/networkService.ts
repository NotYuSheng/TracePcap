import type { Conversation, AnalysisSummary, HostClassification } from '@/types';
import type {
  GraphNode,
  GraphEdge,
  NetworkGraphData,
  NetworkStats,
  NodeMap,
  NodeType,
} from '../types';

/**
 * Determine node role based on port number
 * Ports < 1024 are typically server ports (well-known ports)
 * Ports >= 1024 are typically client ports (ephemeral ports)
 */
function determineRole(port: number): 'client' | 'server' {
  return port < 1024 ? 'server' : 'client';
}

/**
 * Maps well-known port/protocol combinations to node types.
 * Key format: "<port>/<PROTOCOL>"
 */
const PORT_SERVICE_MAP: Record<string, NodeType> = {
  '53/UDP': 'dns-server',
  '53/TCP': 'dns-server',
  '80/TCP': 'web-server',
  '443/TCP': 'web-server',
  '8080/TCP': 'web-server',
  '8443/TCP': 'web-server',
  '22/TCP': 'ssh-server',
  '21/TCP': 'ftp-server',
  '20/TCP': 'ftp-server',
  '25/TCP': 'mail-server',
  '587/TCP': 'mail-server',
  '465/TCP': 'mail-server',
  '110/TCP': 'mail-server',
  '143/TCP': 'mail-server',
  '993/TCP': 'mail-server',
  '995/TCP': 'mail-server',
  '67/UDP': 'dhcp-server',
  '68/UDP': 'dhcp-server',
  '123/UDP': 'ntp-server',
  '3306/TCP': 'database-server',
  '5432/TCP': 'database-server',
  '1433/TCP': 'database-server',
  '1521/TCP': 'database-server',
  '27017/TCP': 'database-server',
  '6379/TCP': 'database-server',
  '9200/TCP': 'database-server',
};

/** Minimum distinct peers before a non-server node is classified as a router/gateway */
const ROUTER_PEER_THRESHOLD = 10;

/** MAC address regex — identifies nodes that have no IP and are addressed by MAC only */
const MAC_REGEX = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

function isMacAddress(id: string): boolean {
  return MAC_REGEX.test(id);
}

/**
 * Classify a node type from its inbound port frequency map and distinct peer count.
 * serverPorts: { "53/UDP": 42, "80/TCP": 1 } — counts of connections received on each port.
 */
function classifyNodeType(
  node: GraphNode,
  serverPorts: Record<string, number>,
  distinctPeers: number
): void {
  // L2-only nodes (identified by MAC address) keep their pre-assigned type
  if (node.data.isL2) return;
  // Find the port/protocol with the most inbound connections
  let dominantPort: string | null = null;
  let maxCount = 0;

  for (const [portProto, count] of Object.entries(serverPorts)) {
    if (count > maxCount) {
      maxCount = count;
      dominantPort = portProto;
    }
  }

  if (dominantPort && PORT_SERVICE_MAP[dominantPort]) {
    node.data.nodeType = PORT_SERVICE_MAP[dominantPort];
  } else if (distinctPeers >= ROUTER_PEER_THRESHOLD && node.data.role !== 'server') {
    node.data.nodeType = 'router';
  } else if (node.data.role === 'client' || node.data.role === 'unknown') {
    node.data.nodeType = 'client';
  } else {
    node.data.nodeType = 'unknown';
  }

  node.data.nodeTypeEvidence = { dominantPort, connectionCount: maxCount, distinctPeers };
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
function finalizeNodeRole(node: GraphNode, srcPort: number, dstPort: number) {
  if (node.data.isL2) return;
  const srcRole = determineRole(srcPort);
  const dstRole = determineRole(dstPort);

  if (node.data.packetsSent > 0 && node.data.packetsReceived > 0) {
    // Node both sends and receives - could be 'both'
    // If it acts as server more often (lower ports), mark as server
    if (srcRole === 'server' || dstRole === 'server') {
      node.data.role = 'server';
    } else {
      node.data.role = 'client';
    }
  } else if (node.data.packetsSent > 0) {
    node.data.role = srcRole;
  } else if (node.data.packetsReceived > 0) {
    node.data.role = dstRole;
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
 * @param analysisSummary - Optional analysis summary for anomaly detection
 * @param maxConversations - Maximum number of conversations to render (default: 500)
 * @param hostClassifications - Optional per-IP device classifications from the backend
 * @param maxNodes - Maximum number of nodes to render (default: 50, 0 = no limit)
 */
export function buildNetworkGraph(
  conversations: Conversation[],
  analysisSummary?: AnalysisSummary,
  maxConversations: number = 500,
  hostClassifications?: HostClassification[],
  maxNodes: number = 50
): NetworkGraphData {
  const nodeMap: NodeMap = {};
  const edges: GraphEdge[] = [];

  // Per-node tracking for node type classification
  // serverPorts[ip]["53/UDP"] = count of connections received on that port
  const serverPorts: Record<string, Record<string, number>> = {};
  // peerSets[ip] = set of all distinct peer IPs
  const peerSets: Record<string, Set<string>> = {};

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
    finalizeNodeRole(nodeMap[src.ip], src.port, dst.port);

    // Create or update destination node
    if (!nodeMap[dst.ip]) {
      nodeMap[dst.ip] = createNode(dst.ip, dst.hostname, dst.mac);
    }
    updateNodeStats(nodeMap[dst.ip], conv, 'received', protocol);
    finalizeNodeRole(nodeMap[dst.ip], src.port, dst.port);

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

    // Create edge
    edges.push(createEdge(conv, src.ip, dst.ip));
  });

  // Classify node types based on accumulated port/peer data
  Object.keys(nodeMap).forEach(ip => {
    classifyNodeType(nodeMap[ip], serverPorts[ip] || {}, peerSets[ip]?.size || 0);
  });

  // Apply backend device classifications (deviceType, confidence, manufacturer)
  if (hostClassifications) {
    const classMap = new Map(hostClassifications.map(c => [c.ip, c]));
    Object.keys(nodeMap).forEach(ip => {
      const c = classMap.get(ip);
      if (c) {
        nodeMap[ip].data.deviceType = c.deviceType;
        nodeMap[ip].data.deviceConfidence = c.confidence;
        nodeMap[ip].data.manufacturer = c.manufacturer;
        nodeMap[ip].data.ttl = c.ttl;
        if (c.mac && !nodeMap[ip].data.mac) nodeMap[ip].data.mac = c.mac;
      }
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
    fn = allNodes.filter(n => {
      const inEdge = fe.some(e => e.source === n.id || e.target === n.id);
      return inEdge || ipMatchIds.has(n.id);
    });
  }

  return { filteredNodes: fn, filteredEdges: fe };
}

export const networkService = {
  buildNetworkGraph,
  applyNetworkFilters,
  edgeMatchesLegendKey,
};
