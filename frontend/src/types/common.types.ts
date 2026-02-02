// Packet and Network Types
export interface Packet {
  id: string;
  timestamp: number;
  source: NetworkEndpoint;
  destination: NetworkEndpoint;
  protocol: Protocol;
  size: number;
  payload: string;
  flags?: string[];
}

export interface NetworkEndpoint {
  ip: string;
  port: number;
  mac?: string;
  hostname?: string;
}

export interface Protocol {
  layer: 'link' | 'network' | 'transport' | 'application';
  name: string;
  version?: string;
}

// Conversation Types
export interface Conversation {
  id: string;
  endpoints: [NetworkEndpoint, NetworkEndpoint];
  protocol: Protocol;
  startTime: number;
  endTime: number;
  packetCount: number;
  totalBytes: number;
  packets: Packet[];
  direction: 'bidirectional' | 'unidirectional';
}

// Analysis Types
export interface AnalysisSummary {
  fileId: string;
  fileName: string;
  fileSize: number;
  uploadTime: number;
  totalPackets: number;
  timeRange: [number, number];
  protocolDistribution: ProtocolStats[];
  topConversations: Conversation[];
  uniqueHosts: NetworkEndpoint[];
  fiveWs?: FiveWsAnalysis;
}

// Alias for backward compatibility
export type AnalysisData = AnalysisSummary;

export interface ProtocolStats {
  protocol: string;
  count: number;
  percentage: number;
  bytes: number;
}

// Five W's Analysis
export interface FiveWsAnalysis {
  who: WhoAnalysis;
  what: WhatAnalysis;
  when: WhenAnalysis;
  where: WhereAnalysis;
  why: WhyAnalysis;
}

export interface WhoAnalysis {
  hosts: HostInfo[];
  topTalkers: NetworkEndpoint[];
  roles: { [ip: string]: 'client' | 'server' | 'both' };
}

export interface HostInfo {
  endpoint: NetworkEndpoint;
  packetsSent: number;
  packetsReceived: number;
  bytesSent: number;
  bytesReceived: number;
  role: 'client' | 'server' | 'both';
}

export interface WhatAnalysis {
  protocols: ProtocolStats[];
  services: ServiceInfo[];
  dataTransferred: number;
}

export interface ServiceInfo {
  name: string;
  port: number;
  protocol: string;
  packetCount: number;
  bytes: number;
}

export interface WhenAnalysis {
  startTime: number;
  endTime: number;
  duration: number;
  peakActivity: TimeWindow[];
}

export interface TimeWindow {
  start: number;
  end: number;
  packetCount: number;
  bytes: number;
}

export interface WhereAnalysis {
  internalNetworks: string[];
  externalNetworks: string[];
  geolocation: { [ip: string]: GeoInfo };
}

export interface GeoInfo {
  country?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
}

export interface WhyAnalysis {
  purposes: string[];
  anomalies: Anomaly[];
  suspiciousActivity: SuspiciousActivity[];
}

export interface Anomaly {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  timestamp: number;
  relatedPackets: string[];
  recommendations?: string[];
}

export interface SuspiciousActivity {
  id: string;
  type: string;
  description: string;
  timestamp: number;
  source: NetworkEndpoint;
  destination?: NetworkEndpoint;
  confidence: number;
}

// Kill Chain Types
export interface KillChainPhase {
  phase:
    | 'reconnaissance'
    | 'weaponization'
    | 'delivery'
    | 'exploitation'
    | 'installation'
    | 'command-control'
    | 'actions';
  indicators: string[];
  confidence: number;
  relatedPackets: string[];
  timestamp: number;
}

// Story Types
export interface Story {
  id: string;
  fileId: string;
  generatedAt: number;
  narrative: NarrativeSection[];
  highlights: Highlight[];
  timeline: StoryTimelineEvent[];
}

export interface NarrativeSection {
  title: string;
  content: string;
  type: 'summary' | 'detail' | 'anomaly' | 'conclusion';
  relatedData: {
    packets?: string[];
    conversations?: string[];
    hosts?: string[];
  };
}

export interface Highlight {
  id: string;
  type: 'anomaly' | 'insight' | 'warning' | 'info';
  title: string;
  description: string;
  timestamp?: number;
}

export interface StoryTimelineEvent {
  timestamp: number;
  title: string;
  description: string;
  type: 'normal' | 'suspicious' | 'critical';
  relatedData: {
    packets?: string[];
    conversations?: string[];
  };
}

// Timeline Types
export interface TimelineDataPoint {
  timestamp: number;
  packetCount: number;
  bytes: number;
  protocols: { [protocol: string]: number };
}

// Session Types
export interface Session {
  id: string;
  conversations: Conversation[];
  startTime: number;
  endTime: number;
  totalPackets: number;
  totalBytes: number;
  purpose?: string;
}

// Filter Generator Types
export interface FilterGenerationRequest {
  fileId: string;
  naturalLanguageQuery: string;
}

export interface FilterGenerationResponse {
  filter: string;
  explanation: string;
  confidence: number;
  suggestions?: string[];
}

export interface FilterExecutionRequest {
  fileId: string;
  filter: string;
}

export interface FilterExecutionResponse {
  packets: Packet[];
  totalMatches: number;
  executionTime: number;
  page?: number;
  pageSize?: number;
  totalPages?: number;
}
