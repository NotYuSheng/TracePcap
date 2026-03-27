// Network Graph Types

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
  | 'unknown';

export interface NodeTypeEvidence {
  dominantPort: string | null;
  connectionCount: number;
  distinctPeers: number;
}

export interface GraphNode {
  id: string;
  label: string;
  data: NodeData;
}

export interface NodeData {
  ip: string;
  mac?: string;
  hostname?: string;
  packetsSent: number;
  packetsReceived: number;
  bytesSent: number;
  bytesReceived: number;
  totalBytes: number;
  role: 'client' | 'server' | 'both' | 'unknown';
  protocols: string[];
  connections: number;
  isAnomaly: boolean;
  nodeType: NodeType;
  nodeTypeEvidence: NodeTypeEvidence;
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
}

export interface NetworkGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: NetworkStats;
  isLimited?: boolean;
  totalConversations?: number;
  displayedConversations?: number;
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
