// Network Graph Types
import type { DeviceType } from '@/types';

export type NodeType =
  | 'dns-server'
  | 'web-server'
  | 'ssh-server'
  | 'ftp-server'
  | 'mail-server'
  | 'dhcp-server'
  | 'ntp-server'
  | 'database-server'
  | 'router'
  | 'client'
  | 'l2-device'
  | 'unknown';

export interface NodeTypeEvidence {
  dominantPort: string | null;
  connectionCount: number;
  distinctPeers: number;
  /** nDPI appName values that drove the classification (primary signal). */
  ndpiApps?: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  data: NodeData;
}

export interface NodeData {
  ip: string;
  mac?: string;
  /** True when this node is identified by a MAC address (pure L2 device with no IP). */
  isL2?: boolean;
  hostname?: string;
  /** How `hostname` was discovered: reverse_dns | mdns | nbns | dhcp | manual. */
  hostnameSource?: string;
  packetsSent: number;
  packetsReceived: number;
  bytesSent: number;
  bytesReceived: number;
  totalBytes: number;
  role: 'client' | 'server' | 'both' | 'unknown';
  protocols: string[];
  connections: number;
  nodeType: NodeType;
  nodeTypeEvidence: NodeTypeEvidence;
  /** Device type from backend classification (e.g. ROUTER, MOBILE, SERVER). */
  deviceType?: DeviceType;
  /** Confidence score 0–100 from the classifier. */
  deviceConfidence?: number;
  /** Manufacturer from OUI lookup. */
  manufacturer?: string;
  /** TTL observed for this host. */
  ttl?: number;
  /** Which file(s) this node appears in — set only in compare mode. */
  sources?: string[];
  /**
   * Ghost/phantom node flags — set when a node shows signs of being an
   * unreachable or scan-artefact host. Possible values:
   *   'no-response'      — only ever appeared as dst in unidirectional conversations
   *   'arp-no-reply'     — subset of no-response, only ARP protocol
   *   'icmp-unreachable' — subset of no-response, only ICMP protocol
   *   'ttl-exceeded'     — only appeared as src of unidirectional ICMP (traceroute hop)
   */
  ghostFlags?: string[];
  // ── Cluster fields — only set on synthetic cluster nodes ─────────────────
  /** True when this node represents a collapsed /24 subnet cluster. */
  isCluster?: boolean;
  /** Cluster identifier, e.g. "cluster:192.168.1.0/24". */
  clusterId?: string;
  /** Number of real nodes inside this cluster. */
  memberCount?: number;
  /** IDs of the real nodes inside this cluster. */
  memberIds?: string[];
  /** Breakdown of roles among cluster members. */
  roleBreakdown?: { client: number; server: number; both: number; unknown: number };
  /** Top protocols seen on edges between cluster members. */
  dominantProtocols?: string[];
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  data: EdgeData;
}

export interface EdgeData {
  protocol: string;
  appName?: string;
  packetCount: number;
  totalBytes: number;
  conversationId: string;
  bidirectional: boolean;
  // Extra conversation fields for filtering
  srcPort?: number;
  dstPort?: number;
  l7Protocol?: string;
  category?: string;
  flowRisks?: string[];
  customSignatures?: string[];
  detectedFileTypes?: string[];
  srcCountry?: string;
  dstCountry?: string;
  hasRisks?: boolean;
  /** Which file(s) this edge appears in — set only in compare mode. */
  sources?: string[];
}

export interface NetworkGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: NetworkStats;
  isLimited?: boolean;
  totalConversations?: number;
  displayedConversations?: number;
  /** Number of nodes hidden by the significance filter (0 when all nodes are shown). */
  hiddenNodes?: number;
  /** The actual hidden node objects (not rendered due to significance cap). */
  hiddenNodesList?: GraphNode[];
  /** Edges where exactly one endpoint is a hidden node (cross-boundary edges). */
  crossEdges?: GraphEdge[];
}

export interface NetworkStats {
  totalNodes: number;
  totalEdges: number;
  totalPackets: number;
  totalBytes: number;
  protocolBreakdown: { [protocol: string]: number };
  isLimited?: boolean;
  totalConversations?: number;
  displayedConversations?: number;
}

export interface NodeMap {
  [ip: string]: GraphNode;
}
