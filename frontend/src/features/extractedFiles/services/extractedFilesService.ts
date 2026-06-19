import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

export interface ExtractedFile {
  id: string;
  conversationId: string | null;
  filename: string | null;
  mimeType: string | null;
  fileSize: number | null;
  sha256: string | null;
  extractionMethod: string | null;
  skippedReason: string | null;
  createdAt: string;
}

export interface SkippedFile {
  id: string;
  conversationId: string | null;
  filename: string | null;
  fileSize: number | null;
}

export interface ExtractionWarnings {
  matchLimitConversationIds: string[];
  conversationLimitSkippedCount: number;
  conversationLimitSkippedIds: string[];
  sizeLimitFiles: SkippedFile[];
  maxMatchesPerStream: number;
  maxStreamConversations: number;
  maxFileSizeMb: number;
}

export async function getExtractedFiles(fileId: string): Promise<ExtractedFile[]> {
  const response = await apiClient.get<ExtractedFile[]>(API_ENDPOINTS.EXTRACTED_FILES(fileId));
  return response.data;
}

export async function getExtractionWarnings(fileId: string): Promise<ExtractionWarnings> {
  const response = await apiClient.get<ExtractionWarnings>(
    API_ENDPOINTS.EXTRACTED_FILES_WARNINGS(fileId)
  );
  return response.data;
}

export async function getExtractionsByConversation(
  fileId: string,
  conversationId: string
): Promise<ExtractedFile[]> {
  const response = await apiClient.get<ExtractedFile[]>(
    `${API_ENDPOINTS.EXTRACTED_FILES(fileId)}?conversationId=${conversationId}`
  );
  return response.data;
}

export function getDownloadUrl(fileId: string, extractionId: string): string {
  return `/api${API_ENDPOINTS.EXTRACTED_FILE_DOWNLOAD(fileId, extractionId)}`;
}

export function getPreviewUrl(fileId: string, extractionId: string): string {
  return `/api/files/${fileId}/extractions/${extractionId}/preview`;
}
