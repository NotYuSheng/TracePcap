export const API_ENDPOINTS = {
  // Files (Upload/Download/List)
  UPLOAD_PCAP: '/files',
  FILES_LIST: '/files',
  FILE_METADATA: (fileId: string) => `/files/${fileId}`,
  FILE_REANALYSES: (fileId: string) => `/files/${fileId}/reanalyses`,
  FILE_VERSIONS: (fileId: string) => `/files/${fileId}/versions`,
  FILE_DELETE: (fileId: string) => `/files/${fileId}`,
  FILE_DOWNLOAD: (fileId: string) => `/files/${fileId}/download`,
  FILES_MERGE: '/files/merge',

  // Analysis
  ANALYSIS_SUMMARY: (fileId: string) => `/analysis/${fileId}/summary`,
  ANALYSIS_PROGRESS: (fileId: string) => `/analysis/${fileId}/progress`,
  PROTOCOL_STATS: (fileId: string) => `/analysis/${fileId}/protocols`,
  // No /five-ws or /kill-chain endpoint exists. The five-Ws data ships as the `fiveWs` field of
  // the analysis summary above; there is no kill-chain equivalent.

  // Host Classifications
  HOST_CLASSIFICATIONS: (fileId: string) => `/files/${fileId}/host-classifications`,
  WINDOWS_LOGONS: (fileId: string, ip: string) =>
    `/files/${fileId}/hosts/${encodeURIComponent(ip)}/windows-logons`,
  /** Which devices held an address when, and the analyst's split/merge decisions (#918). */
  HOST_OCCUPANCIES: (fileId: string, ip: string) =>
    `/files/${fileId}/hosts/${encodeURIComponent(ip)}/occupancies`,
  HOST_OCCUPANCY_DECISIONS: (fileId: string, ip: string) =>
    `/files/${fileId}/hosts/${encodeURIComponent(ip)}/occupancy-decisions`,
  HOST_OCCUPANCY_DECISION: (fileId: string, ip: string, decisionId: number) =>
    `/files/${fileId}/hosts/${encodeURIComponent(ip)}/occupancy-decisions/${decisionId}`,
  /** Deterministic answers to the standard investigation questions (#813). */
  ANSWERS: (fileId: string) => `/files/${fileId}/answers`,
  /** Goal-driven autonomous investigation report — producers plus pivots (#819). */
  INVESTIGATION: (fileId: string) => `/files/${fileId}/investigation`,
  HOST_IDENTITIES: (fileId: string) => `/files/${fileId}/host-identities`,
  /** Full explainable classification (verdict + evidence axes) for one host. */
  HOST_IDENTITY_EVIDENCE: (fileId: string, ip: string) =>
    `/files/${fileId}/hosts/${encodeURIComponent(ip)}/identity`,

  // Adjudication overrides + evidence (generic: any question, keyed by Adjudicator.question())
  ADJUDICATION_OVERRIDE: (fileId: string, question: string, entityKey: string) =>
    `/files/${fileId}/adjudications/${question}/${encodeURIComponent(entityKey)}/override`,
  ADJUDICATION_EVIDENCE: (fileId: string, question: string, entityKey: string) =>
    `/files/${fileId}/adjudications/${question}/${encodeURIComponent(entityKey)}/evidence`,
  ADJUDICATION_EVIDENCE_ITEM: (fileId: string, question: string, entityKey: string, evidenceId: number) =>
    `/files/${fileId}/adjudications/${question}/${encodeURIComponent(entityKey)}/evidence/${evidenceId}`,

  // Conversations
  CONVERSATIONS: (fileId: string) => `/conversations/${fileId}`,
  ENTITY_STATS: (fileId: string) => `/conversations/${fileId}/entity-stats`,
  CONVERSATION_DETAIL: (conversationId: string) => `/conversations/detail/${conversationId}`,
  CONVERSATIONS_EXPORT: (fileId: string) => `/conversations/${fileId}/export`,
  CONVERSATIONS_PCAP_EXPORT: (fileId: string) => `/conversations/${fileId}/export-pcap`,
  CONVERSATION_PCAP_EXPORT: (conversationId: string) =>
    `/conversations/detail/${conversationId}/export-pcap`,
  SECURITY_ALERTS: (fileId: string) => `/files/${fileId}/security-alerts`,
  RISK_TYPES: (fileId: string) => `/conversations/${fileId}/risk-types`,
  DISTINCT_IPS: (fileId: string) => `/conversations/${fileId}/distinct-ips`,
  DISTINCT_APPS: (fileId: string) => `/conversations/${fileId}/distinct-apps`,
  DISTINCT_PROTOCOLS: (fileId: string) => `/conversations/${fileId}/distinct-protocols`,

  // Timeline
  TIMELINE_DATA: (fileId: string) => `/timeline/${fileId}`,
  /** `start`/`end` are ISO-8601 timestamps — TimelineController parses them with LocalDateTime. */
  TIMELINE_RANGE: (fileId: string, start: string, end: string) =>
    `/timeline/${fileId}/range?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`,

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
  EXTRACTED_FILE_PREVIEW: (fileId: string, extractionId: string) =>
    `/files/${fileId}/extractions/${extractionId}/preview`,

  // Network Cluster
  NETWORK_INTELLIGENCE_CLUSTERS: (fileId: string, groupBy: string) =>
    `/clusters/${fileId}/graph?groupBy=${groupBy}`,
  NETWORK_INTELLIGENCE_TOP_HOSTS: (fileId: string, sortBy: string, limit: number) =>
    `/clusters/${fileId}/top-hosts?sortBy=${sortBy}&limit=${limit}`,
  NETWORK_INTELLIGENCE_DNS_SERVERS: (fileId: string) =>
    `/clusters/${fileId}/dns-servers`,
  NETWORK_INTELLIGENCE_DNS_LOG: (fileId: string, serverIp: string) =>
    `/clusters/${fileId}/dns/${encodeURIComponent(serverIp)}`,
  NETWORK_INTELLIGENCE_WEB_SERVERS: (fileId: string) =>
    `/clusters/${fileId}/web-servers`,
  NETWORK_INTELLIGENCE_WEB_DETAIL: (fileId: string, serverIp: string) =>
    `/clusters/${fileId}/web/${encodeURIComponent(serverIp)}`,
  NETWORK_INTELLIGENCE_PACKET_LOCATION: (fileId: string, packetNumber: number) =>
    `/clusters/${fileId}/packet-location/${packetNumber}`,

  // Conversation Tracer
  TRACER_STEPS: (conversationId: string) => `/tracer/${conversationId}/steps`,
  TRACER_PEERS: (conversationId: string) => `/tracer/${conversationId}/peers`,
  TRACER_EXPLAIN: (conversationId: string) => `/tracer/${conversationId}/explanations`,

  // IP Org Rules (Network Labels)
  IP_ORG_RULES: '/ip-org-rules',
  IP_ORG_RULE_DELETE: (id: number) => `/ip-org-rules/${id}`,

  // Custom private ranges
  CUSTOM_PRIVATE_RANGES: '/custom-private-ranges',
  CUSTOM_PRIVATE_RANGE_DELETE: (id: number) => `/custom-private-ranges/${id}`,

  // System
  SYSTEM_TIME: '/system/time',
  SYSTEM_LIMITS: '/system/limits',
  SYSTEM_SETTINGS: '/system/settings',
  SYSTEM_SETTING: (key: string) => `/system/settings/${key}`,
  PREFERENCES: '/preferences',
  ME: '/me',
  PERMISSIONS: '/permissions',
  PERMISSION: (action: string) => `/permissions/${action}`,
  AUDIT_LOG: '/audit-log',
  DETECTION_RULES: '/detection-rules',
  DETECTION_RULE: (id: string) => `/detection-rules/${id}`,
  DETECTION_RULES_EXPORT: '/detection-rules/export',
  DETECTION_RULES_IMPORT: '/detection-rules/import',
  DETECTION_RULES_STATUS: '/detection-rules/status',
  CAPTURE_DETECTION_RULES: (fileId: string) => `/files/${fileId}/detection-rules`,
  NETWORK_DETECTION_RULES: (networkId: string) => `/monitor/networks/${networkId}/detection-rules`,
  FILE_NETWORKS: (fileId: string) => `/files/${fileId}/networks`,
  NETWORK_RULE_SUPPRESSIONS: (networkId: string) => `/monitor/networks/${networkId}/detection-rules/suppressions`,
  NETWORK_RULE_SUPPRESSION: (networkId: string, ruleId: string) =>
    `/monitor/networks/${networkId}/detection-rules/suppressions/${ruleId}`,
  DETECTION_RULE_PREVIEWS: '/detection-rules/previews',
  DETECTION_RULE_PROMOTIONS: (id: string) => `/detection-rules/${id}/promotions`,
  FILE_RULE_STATUS: (fileId: string) => `/files/${fileId}/rule-status`,
  RULE_REAPPLY_JOBS: '/rule-reapply-jobs',
  RULE_REAPPLY_JOB: (id: string) => `/rule-reapply-jobs/${id}`,

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
  NETWORK_SETTINGS: (id: string) => `/monitor/networks/${id}/settings`,
  SNAPSHOTS: (networkId: string) => `/monitor/networks/${networkId}/snapshots`,
  SNAPSHOT: (networkId: string, snapshotId: string) =>
    `/monitor/networks/${networkId}/snapshots/${snapshotId}`,
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
  SUBNET_SUGGEST_LABEL: (id: number, networkId?: string, fileId?: string) => {
    const p = new URLSearchParams();
    if (networkId) p.set('networkId', networkId);
    if (fileId) p.set('fileId', fileId);
    const q = p.toString();
    return `/subnets/${id}/suggest-label${q ? `?${q}` : ''}`;
  },
  SUBNET_HISTORY: (id: number, networkId: string) =>
    `/subnets/${id}/history?networkId=${networkId}`,
  SUBNET_DISMISS_STALENESS: (id: number, networkId?: string) =>
    `/subnets/${id}/dismiss-staleness${networkId ? `?networkId=${networkId}` : ''}`,
  SUBNET_OVERLAPS: (networkId: string) => `/subnets/overlaps?networkId=${networkId}`,
};

export const INSIGHTS_ENDPOINTS = {
  NODE_ROLE: (fileId: string, entityType: string, entityKey: string) =>
    `/node-roles?fileId=${fileId}&entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}`,
  /** All confirmed roles in a file — bulk read for graph-wide node labels. */
  NODE_ROLES_BY_FILE: (fileId: string) => `/files/${fileId}/node-roles`,
  NODE_ROLE_UPSERT: '/node-roles',
  NODE_ROLE_DELETE: (fileId: string, entityType: string, entityKey: string) =>
    `/node-roles?fileId=${fileId}&entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}`,
  NODE_ROLE_SUGGEST: (entityType: string, entityKey: string, fileId: string) =>
    `/node-roles/suggest?entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}&fileId=${fileId}`,
  NODE_ROLE_SUGGEST_PREVIEW: (entityType: string, entityKey: string, fileId: string) =>
    `/node-roles/suggest-preview?entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}&fileId=${fileId}`,
  NODE_ROLE_DISMISS_STALENESS: (fileId: string, entityType: string, entityKey: string) =>
    `/node-roles/dismiss-staleness?fileId=${fileId}&entityType=${encodeURIComponent(entityType)}&entityKey=${encodeURIComponent(entityKey)}`,
};
