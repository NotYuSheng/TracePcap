import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { UploadResponse, UploadProgress } from '../types/upload.types';

export const uploadService = {
  /**
   * Upload a PCAP file to the server
   */
  uploadPcap: async (
    file: File,
    onProgress?: (progress: number) => void
  ): Promise<UploadResponse> => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await apiClient.post<UploadResponse>(API_ENDPOINTS.UPLOAD_PCAP, formData, {
      onUploadProgress: progressEvent => {
        if (progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress?.(progress);
        }
      },
    });

    return response.data;
  },

  /**
   * Get the status of an ongoing upload
   */
  getUploadStatus: async (uploadId: string): Promise<UploadProgress> => {
    const response = await apiClient.get<UploadResponse>(API_ENDPOINTS.FILE_METADATA(uploadId));

    return {
      uploadId: response.data.fileId,
      status: response.data.status as any,
      progress:
        response.data.status === 'completed' ? 100 : response.data.status === 'processing' ? 50 : 0,
      message: `File ${response.data.status}`,
    };
  },
};
