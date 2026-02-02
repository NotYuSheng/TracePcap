import type { Conversation, AnalysisSummary } from '@/types';
import type { GraphNode, GraphEdge, NetworkGraphData, NetworkStats, NodeMap } from '../types';

/**
 * Determine node role based on port number
 * Ports < 1024 are typically server ports (well-known ports)
 * Ports >= 1024 are typically client ports (ephemeral ports)
 */
function determineRole(port: number): 'client' | 'server' {
  return port < 1024 ? 'server' : 'client';
}

/**
 * Create a new graph node from a network endpoint
 */
function createNode(ip: string, hostname?: string, mac?: string): GraphNode {
  return {
    id: ip,
    label: hostname || ip,
    data: {
      ip,
      mac,
      hostname,
      packetsSent: 0,
      packetsReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      totalBytes: 0,
      role: 'unknown',
      protocols: [],
      connections: 0,
      isAnomaly: false,
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

  return {
    id: conversation.id,
    source: srcIp,
    target: dstIp,
    label: `${protocol} (${conversation.packetCount})`,
    data: {
      protocol,
      packetCount: conversation.packetCount,
      totalBytes: conversation.totalBytes,
      conversationId: conversation.id,
      bidirectional: conversation.direction === 'bidirectional',
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
 * Mark nodes involved in anomalies
 */
function markAnomalies(nodeMap: NodeMap, analysisSummary?: AnalysisSummary) {
  if (!analysisSummary?.fiveWs?.why?.anomalies) {
    return;
  }

  const anomalies = analysisSummary.fiveWs.why.anomalies;

  // Extract IPs from suspicious activity
  const suspiciousActivity = analysisSummary.fiveWs.why.suspiciousActivity || [];
  const suspiciousIps = new Set<string>();

  suspiciousActivity.forEach(activity => {
    if (activity.source?.ip) {
      suspiciousIps.add(activity.source.ip);
    }
    if (activity.destination?.ip) {
      suspiciousIps.add(activity.destination.ip);
    }
  });

  // Mark nodes as anomalies
  suspiciousIps.forEach(ip => {
    if (nodeMap[ip]) {
      nodeMap[ip].data.isAnomaly = true;
    }
  });

  // Also check if anomaly descriptions mention IPs
  anomalies.forEach(anomaly => {
    if (anomaly.severity === 'high' || anomaly.severity === 'critical') {
      // Try to extract IP addresses from description
      const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
      const matches = anomaly.description.match(ipRegex);
      if (matches) {
        matches.forEach(ip => {
          if (nodeMap[ip]) {
            nodeMap[ip].data.isAnomaly = true;
          }
        });
      }
    }
  });
}

/**
 * Transform conversations into graph nodes and edges
 * @param conversations - Array of conversations to visualize
 * @param analysisSummary - Optional analysis summary for anomaly detection
 * @param maxConversations - Maximum number of conversations to render (default: 500)
 */
export function buildNetworkGraph(
  conversations: Conversation[],
  analysisSummary?: AnalysisSummary,
  maxConversations: number = 500
): NetworkGraphData {
  const nodeMap: NodeMap = {};
  const edges: GraphEdge[] = [];

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

    // Create edge
    edges.push(createEdge(conv, src.ip, dst.ip));
  });

  // Mark anomalies if analysis data is available
  if (analysisSummary) {
    markAnomalies(nodeMap, analysisSummary);
  }

  // Calculate statistics
  const stats = calculateNetworkStats(nodeMap, edges);

  return {
    nodes: Array.from(Object.values(nodeMap)),
    edges,
    stats,
    isLimited: conversations.length > maxConversations,
    totalConversations: conversations.length,
    displayedConversations: limitedConversations.length,
  };
}

export const networkService = {
  buildNetworkGraph,
};
