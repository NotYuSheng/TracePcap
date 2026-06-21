import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** A file extracted from a PCAP, or one detected but skipped (when `skippedReason` is set). */
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

/** A file that was detected but not stored because it exceeded the per-file size limit. */
export interface SkippedFile {
  id: string;
  conversationId: string | null;
  filename: string | null;
  fileSize: number | null;
}

/**
 * Which extraction limits were hit for a capture (so results may be incomplete), plus the limit
 * values in effect. Empty lists / zero counts mean the corresponding limit was not reached.
 */
export interface ExtractionWarnings {
  matchLimitConversationIds: string[];
  conversationLimitSkippedCount: number;
  conversationLimitSkippedIds: string[];
  sizeLimitFiles: SkippedFile[];
  maxMatchesPerStream: number;
  maxStreamConversations: number;
  maxFileSizeMb: number;
}

/** Fetches all files extracted from the given PCAP. */
export async function getExtractedFiles(fileId: string): Promise<ExtractedFile[]> {
  const response = await apiClient.get<ExtractedFile[]>(API_ENDPOINTS.EXTRACTED_FILES(fileId));
  return response.data;
}

/** Fetches which extraction limits (if any) were hit while processing the given PCAP. */
export async function getExtractionWarnings(fileId: string): Promise<ExtractionWarnings> {
  const response = await apiClient.get<ExtractionWarnings>(
    API_ENDPOINTS.EXTRACTED_FILES_WARNINGS(fileId)
  );
  return response.data;
}

/** Fetches the files extracted from a single conversation within a PCAP. */
export async function getExtractionsByConversation(
  fileId: string,
  conversationId: string
): Promise<ExtractedFile[]> {
  const response = await apiClient.get<ExtractedFile[]>(
    `${API_ENDPOINTS.EXTRACTED_FILES(fileId)}?conversationId=${conversationId}`
  );
  return response.data;
}

/** Builds the download URL for an extracted file (triggers an attachment download). */
export function getDownloadUrl(fileId: string, extractionId: string): string {
  return `/api${API_ENDPOINTS.EXTRACTED_FILE_DOWNLOAD(fileId, extractionId)}`;
}

/** Builds the inline-preview URL for an extracted file (browser-renderable types only). */
export function getPreviewUrl(fileId: string, extractionId: string): string {
  return `/api/v1/files/${fileId}/extractions/${extractionId}/preview`;
}
