import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useStore } from '@/store';
import { uploadService } from '../services/uploadService';
import type { UploadError, UploadResponse } from '../types/upload.types';

export const useFileUpload = () => {
  const [isUploading, setIsUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<UploadError | null>(null);
  const addRecentFile = useStore(state => state.addRecentFile);
  const navigate = useNavigate();

  const uploadFile = useCallback(
    async (file: File): Promise<UploadResponse | null> => {
      setIsUploading(true);
      setError(null);
      setProgress(0);

      try {
        const result = await uploadService.uploadPcap(file, setProgress);

        // Add to recent files
        addRecentFile({
          id: result.fileId,
          name: file.name,
          size: file.size,
          uploadedAt: Date.now(),
        });

        // Navigate to analysis page on success
        if (result.status === 'completed' || result.status === 'processing') {
          setTimeout(() => {
            navigate(`/analysis/${result.fileId}`);
          }, 500);
        }

        return result;
      } catch (err) {
        const uploadError: UploadError = {
          code: 'UPLOAD_ERROR',
          message: err instanceof Error ? err.message : 'Upload failed',
          details: err,
        };
        setError(uploadError);
        return null;
      } finally {
        setIsUploading(false);
      }
    },
    [addRecentFile, navigate]
  );

  const resetUpload = useCallback(() => {
    setProgress(0);
    setError(null);
    setIsUploading(false);
  }, []);

  return {
    uploadFile,
    isUploading,
    progress,
    error,
    resetUpload,
  };
};
