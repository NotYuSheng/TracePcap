export const API_ENDPOINTS = {
  // Files (Upload/Download/List)
  UPLOAD_PCAP: '/files',
  FILES_LIST: '/files',
  FILE_METADATA: (fileId: string) => `/files/${fileId}`,
  FILE_DOWNLOAD: (fileId: string) => `/files/${fileId}/download`,

  // Analysis (Not yet implemented in backend)
  ANALYSIS_SUMMARY: (fileId: string) => `/analysis/${fileId}/summary`,
  PROTOCOL_STATS: (fileId: string) => `/analysis/${fileId}/protocols`,
  FIVE_WS: (fileId: string) => `/analysis/${fileId}/five-ws`,
  KILL_CHAIN: (fileId: string) => `/analysis/${fileId}/kill-chain`,

  // Conversations (Not yet implemented in backend)
  CONVERSATIONS: (fileId: string) => `/conversations/${fileId}`,
  CONVERSATION_DETAIL: (conversationId: string) => `/conversations/detail/${conversationId}`,

  // Timeline (Not yet implemented in backend)
  TIMELINE_DATA: (fileId: string) => `/timeline/${fileId}`,
  TIMELINE_RANGE: (fileId: string, start: number, end: number) =>
    `/timeline/${fileId}?start=${start}&end=${end}`,

  // Story (Not yet implemented in backend)
  GENERATE_STORY: (fileId: string) => `/story/generate/${fileId}`,
  GET_STORY: (storyId: string) => `/story/${storyId}`,

  // Filter Generator (Not yet implemented in backend)
  GENERATE_FILTER: (fileId: string) => `/filter/generate/${fileId}`,
  EXECUTE_FILTER: (fileId: string) => `/filter/execute/${fileId}`,
} as const
