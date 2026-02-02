import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { UploadResponse, UploadProgress } from '../types/upload.types';

const USE_MOCK = import.meta.env.VITE_USE_MOCK_DATA === 'true';

// Mock upload simulation
const mockUpload = async (
  file: File,
  onProgress?: (progress: number) => void
): Promise<UploadResponse> => {
  // Simulate upload progress
  const steps = 10;
  for (let i = 0; i <= steps; i++) {
    await new Promise(resolve => setTimeout(resolve, 100));
    onProgress?.(Math.round((i / steps) * 100));
  }

  // Generate a unique file ID
  const fileId = `mock-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

  return {
    fileId,
    fileName: file.name,
    fileSize: file.size,
    status: 'completed',
    uploadedAt: Date.now(),
  };
};

export const uploadService = {
  /**
   * Upload a PCAP file to the server
   * @param file - The PCAP file to upload
   * @param onProgress - Optional callback for upload progress updates
   * @returns Upload response with file ID and status
   */
  uploadPcap: async (
    file: File,
    onProgress?: (progress: number) => void
  ): Promise<UploadResponse> => {
    if (USE_MOCK) {
      return mockUpload(file, onProgress);
    }

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
   * @param uploadId - The upload ID to check
   * @returns Upload progress information
   */
  getUploadStatus: async (uploadId: string): Promise<UploadProgress> => {
    if (USE_MOCK) {
      return {
        uploadId,
        status: 'completed',
        progress: 100,
        message: 'Analysis complete',
      };
    }

    // Use FILE_METADATA endpoint to get file status
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
