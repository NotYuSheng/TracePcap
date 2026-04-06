// Packet and Network Types
export interface Packet {
  id: string;
  timestamp: number;
  source: NetworkEndpoint;
  destination: NetworkEndpoint;
  protocol: Protocol;
  size: number;
  info?: string;
  payload: string;
  detectedFileType?: string;
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

export interface DetectedApplication {
  name: string;
  packetCount: number;
  bytes: number;
}

export interface CategoryStat {
  category: string;
  count: number;
  percentage: number;
  bytes: number;
}

export interface ConversationGeoInfo {
  country: string;
  countryCode: string;
  asn?: string;
  org?: string;
}

// Conversation Types
export interface Conversation {
  id: string;
  endpoints: [NetworkEndpoint, NetworkEndpoint];
  protocol: Protocol;
  appName?: string;
  tsharkProtocol?: string;
  category?: string;
  hostname?: string;
  ja3Client?: string;
  ja3Server?: string;
  tlsIssuer?: string;
  tlsSubject?: string;
  tlsNotBefore?: number;
  tlsNotAfter?: number;
  flowRisks: string[];
  customSignatures: string[];
  httpUserAgents: string[];
  detectedFileTypes: string[];
  startTime: number;
  endTime: number;
  packetCount: number;
  totalBytes: number;
  packets: Packet[];
  direction: 'bidirectional' | 'unidirectional';
  srcGeo?: ConversationGeoInfo;
  dstGeo?: ConversationGeoInfo;
}

// Analysis Types
export interface AnalysisSummary {
  fileId: string;
  fileName: string;
  fileSize: number;
  uploadTime: number;
  totalPackets: number;
  totalConversations: number;
  timeRange: [number, number];
  protocolDistribution: ProtocolStats[];
  topConversations: Conversation[];
  uniqueHosts: NetworkEndpoint[];
  detectedApplications?: DetectedApplication[];
  detectedApplicationsTruncated?: boolean;
  detectedL7Protocols?: string[];
  categoryDistribution?: CategoryStat[];
  fiveWs?: FiveWsAnalysis;
  securityAlertCount?: number;
  triggeredCustomRules?: string[];
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

// Story Aggregate Types
export interface StoryAggregates {
  coverage: StoryCoverage;
  topExternalAsns: AsnEntry[];
  protocolRiskMatrix: ProtocolRiskEntry[];
  tlsAnomalySummary: TlsAnomalySummary;
  unknownAppPct: number;
  beaconCandidates: BeaconCandidate[];
}

export interface StoryCoverage {
  totalConversations: number;
  shownConversations: number;
  totalPackets: number;
  shownPackets: number;
  bytesCoveragePct: number;
}

export interface AsnEntry {
  asn: string | null;
  org: string;
  country: string | null;
  bytes: number;
  pct: number;
  flowCount: number;
}

export interface ProtocolRiskEntry {
  protocol: string;
  total: number;
  atRisk: number;
}

export interface TlsAnomalySummary {
  selfSigned: number;
  expired: number;
  unknownCa: number;
  total: number;
}

export interface BeaconCandidate {
  srcIp: string;
  dstIp: string | null;
  dstPort: number | null;
  protocol: string;
  appName: string | null;
  flowCount: number;
  avgIntervalMs: number;
  cv: number;
}

export type FindingType =
  | 'NDPI_RISK'
  | 'BEACON'
  | 'TLS_ANOMALY'
  | 'VOLUME'
  | 'FAN_OUT'
  | 'LONG_SESSION'
  | 'UNKNOWN_APP'
  | 'PORT_PROTOCOL_MISMATCH';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Finding {
  type: FindingType;
  severity: FindingSeverity;
  title: string;
  summary: string;
  metrics: Record<string, number | string | null>;
  affectedIps: string[];
}

export interface InvestigationQuery {
  id: string;
  label: string;
  srcIp?: string | null;
  dstIp?: string | null;
  dstPort?: number | null;
  protocol?: string | null;
  appName?: string | null;
  category?: string | null;
  hasRisks?: boolean | null;
  hasTlsAnomaly?: boolean | null;
  riskType?: string | null;
  minBytes?: number | null;
  maxBytes?: number | null;
  minFlows?: number | null;
}

export interface Hypothesis {
  id: string;
  queryRef: string;
  hypothesis: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface ConversationEvidence {
  srcIp: string;
  srcPort?: number;
  dstIp: string;
  dstPort?: number;
  protocol: string;
  appName?: string | null;
  category?: string | null;
  hostname?: string | null;
  totalBytes?: number | null;
  packetCount?: number | null;
  startTime?: string | null;
  endTime?: string | null;
  flowRisks?: string[];
  tlsIssuer?: string | null;
  tlsSubject?: string | null;
  ja3Client?: string | null;
}

export interface InvestigationStep {
  query: InvestigationQuery;
  hypothesis?: Hypothesis | null;
  conversations: ConversationEvidence[];
  conversationCount: number;
}

// Story Types
export interface Story {
  id: string;
  fileId: string;
  generatedAt: number;
  narrative: NarrativeSection[];
  highlights: Highlight[];
  timeline: StoryTimelineEvent[];
  suggestedQuestions?: string[];
  aggregates?: StoryAggregates;
  findings?: Finding[];
  investigationSteps?: InvestigationStep[];
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

// Device Classification Types
export type DeviceType =
  | 'ROUTER'
  | 'MOBILE'
  | 'LAPTOP_DESKTOP'
  | 'SERVER'
  | 'IOT'
  | 'UNKNOWN'
  | string; // custom override values from YAML

export interface HostClassification {
  ip: string;
  mac?: string;
  manufacturer?: string;
  ttl?: number;
  deviceType: DeviceType;
  confidence: number;
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
