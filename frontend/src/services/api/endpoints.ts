export const API_ENDPOINTS = {
  // Files (Upload/Download/List)
  UPLOAD_PCAP: '/files',
  FILES_LIST: '/files',
  FILE_METADATA: (fileId: string) => `/files/${fileId}`,
  FILE_DELETE: (fileId: string) => `/files/${fileId}`,
  FILE_DOWNLOAD: (fileId: string) => `/files/${fileId}/download`,
  FILES_MERGE: '/files/merge',

  // Analysis (Not yet implemented in backend)
  ANALYSIS_SUMMARY: (fileId: string) => `/analysis/${fileId}/summary`,
  PROTOCOL_STATS: (fileId: string) => `/analysis/${fileId}/protocols`,
  FIVE_WS: (fileId: string) => `/analysis/${fileId}/five-ws`,
  KILL_CHAIN: (fileId: string) => `/analysis/${fileId}/kill-chain`,

  // Host Classifications
  HOST_CLASSIFICATIONS: (fileId: string) => `/files/${fileId}/host-classifications`,

  // Conversations
  CONVERSATIONS: (fileId: string) => `/conversations/${fileId}`,
  CONVERSATION_DETAIL: (conversationId: string) => `/conversations/detail/${conversationId}`,
  SECURITY_ALERTS: (fileId: string) => `/files/${fileId}/security-alerts`,
  RISK_TYPES: (fileId: string) => `/conversations/${fileId}/risk-types`,

  // Timeline (Not yet implemented in backend)
  TIMELINE_DATA: (fileId: string) => `/timeline/${fileId}`,
  TIMELINE_RANGE: (fileId: string, start: number, end: number) =>
    `/timeline/${fileId}?start=${start}&end=${end}`,

  // Story
  STORIES: '/stories',
  GET_STORY: (storyId: string) => `/stories/${storyId}`,
  GET_STORY_BY_FILE: (fileId: string) => `/stories?fileId=${fileId}`,
  ASK_STORY: (storyId: string) => `/stories/${storyId}/questions`,

  // Filter Generator
  GENERATE_FILTER: (fileId: string) => `/filter/${fileId}/generate`,
  EXECUTE_FILTER: (fileId: string) => `/filter/${fileId}/execute`,

  // Extracted Files
  EXTRACTED_FILES: (fileId: string) => `/files/${fileId}/extractions`,
  EXTRACTED_FILES_WARNINGS: (fileId: string) => `/files/${fileId}/extractions/warnings`,
  EXTRACTED_FILE_DOWNLOAD: (fileId: string, extractionId: string) =>
    `/files/${fileId}/extractions/${extractionId}/download`,

  // Network Intelligence
  NETWORK_INTELLIGENCE_CLUSTERS: (fileId: string, groupBy: string) =>
    `/intelligence/${fileId}/clusters?groupBy=${groupBy}`,
  NETWORK_INTELLIGENCE_TOP_HOSTS: (fileId: string, sortBy: string, limit: number) =>
    `/intelligence/${fileId}/top-hosts?sortBy=${sortBy}&limit=${limit}`,
  NETWORK_INTELLIGENCE_DNS_SERVERS: (fileId: string) =>
    `/intelligence/${fileId}/dns-servers`,
  NETWORK_INTELLIGENCE_DNS_LOG: (fileId: string, serverIp: string) =>
    `/intelligence/${fileId}/dns/${encodeURIComponent(serverIp)}`,
  NETWORK_INTELLIGENCE_WEB_SERVERS: (fileId: string) =>
    `/intelligence/${fileId}/web-servers`,
  NETWORK_INTELLIGENCE_WEB_DETAIL: (fileId: string, serverIp: string) =>
    `/intelligence/${fileId}/web/${encodeURIComponent(serverIp)}`,
  NETWORK_INTELLIGENCE_PACKET_LOCATION: (fileId: string, packetNumber: number) =>
    `/intelligence/${fileId}/packet-location/${packetNumber}`,

  // Conversation Tracer
  TRACER_STEPS: (conversationId: string) => `/tracer/${conversationId}/steps`,
  TRACER_PEERS: (conversationId: string) => `/tracer/${conversationId}/peers`,
  TRACER_EXPLAIN: (conversationId: string) => `/tracer/${conversationId}/explanations`,

  // IP Org Rules (Network Labels)
  IP_ORG_RULES: '/ip-org-rules',
  IP_ORG_RULE_DELETE: (id: number) => `/ip-org-rules/${id}`,

  // System
  SYSTEM_TIME: '/system/time',

  // Report
  REPORT_DOWNLOAD: (fileId: string) => `/files/${fileId}/report`,
  COMPARE_REPORT_DOWNLOAD: '/files/compare/report',

  // Entity Notes
  ENTITY_NOTE: (entityType: string, entityKey: string) =>
    `/entity-notes?entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}`,
  ENTITY_NOTE_UPSERT: '/entity-notes',
  ENTITY_NOTE_HISTORY: (entityType: string, entityKey: string) =>
    `/entity-notes/history?entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}`,
} as const;

export const MONITOR_ENDPOINTS = {
  NETWORKS: '/monitor/networks',
  NETWORK: (id: string) => `/monitor/networks/${id}`,
  SNAPSHOTS: (networkId: string) => `/monitor/networks/${networkId}/snapshots`,
  SNAPSHOT: (networkId: string, snapshotId: string) =>
    `/monitor/networks/${networkId}/snapshots/${snapshotId}`,
  SNAPSHOT_BASELINE: (networkId: string, snapshotId: string) =>
    `/monitor/networks/${networkId}/snapshots/${snapshotId}/baseline`,
  CHANGES: (networkId: string) => `/monitor/networks/${networkId}/changes`,
  CHANGE: (networkId: string, eventId: string) => `/monitor/networks/${networkId}/changes/${eventId}`,
  BASELINE_DEFINITIONS: (networkId: string) =>
    `/monitor/networks/${networkId}/baseline/definitions`,
  EXTERNAL_EVENTS: (networkId: string) => `/monitor/networks/${networkId}/external-events`,
  EXTERNAL_EVENT: (networkId: string, eventId: string) =>
    `/monitor/networks/${networkId}/external-events/${eventId}`,
  ANNOTATIONS: (networkId: string) => `/monitor/networks/${networkId}/annotations`,
  ANNOTATION: (networkId: string, annotationId: string) =>
    `/monitor/networks/${networkId}/annotations/${annotationId}`,
  INSIGHTS_LATEST: (networkId: string) => `/monitor/networks/${networkId}/insights/latest`,
  INSIGHTS_GENERATE: (networkId: string) => `/monitor/networks/${networkId}/insights`,
  SNAPSHOT_PATCH: (networkId: string, snapshotId: string) =>
    `/monitor/networks/${networkId}/snapshots/${snapshotId}`,
  SNAPSHOT_INSIGHT_LATEST: (networkId: string, snapshotId: string) =>
    `/monitor/networks/${networkId}/snapshots/${snapshotId}/insights/latest`,
  SNAPSHOT_INSIGHT_GENERATE: (networkId: string, snapshotId: string) =>
    `/monitor/networks/${networkId}/snapshots/${snapshotId}/insights`,
};

export const SUBNET_ENDPOINTS = {
  SUBNETS: '/subnets',
  SUBNET_DELETE: (id: number) => `/subnets/${id}`,
  SUBNET_DETECT: (fileId: string) => `/subnets/detect?fileId=${fileId}`,
  SUBNET_DETECT_NETWORK: (networkId: string) => `/subnets/detect/network?networkId=${networkId}`,
  SUBNET_SAVE_DETECTED: '/subnets/detected',
};

export const INSIGHTS_ENDPOINTS = {
  NODE_ROLE: (entityType: string, entityKey: string) =>
    `/node-roles?entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}`,
  NODE_ROLE_UPSERT: '/node-roles',
  NODE_ROLE_DELETE: (entityType: string, entityKey: string) =>
    `/node-roles?entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}`,
  NODE_ROLE_SUGGEST: (entityType: string, entityKey: string, fileId: string) =>
    `/node-roles/suggest?entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}&fileId=${fileId}`,
};
