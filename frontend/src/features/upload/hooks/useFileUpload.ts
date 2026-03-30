import { useState, useCallback } from 'react';
import { useStore } from '@/store';
import { uploadService } from '../services/uploadService';
import type { FileUploadState } from '../types/upload.types';

const CONCURRENCY_LIMIT = 3;

export const useFileUpload = () => {
  const [fileStates, setFileStates] = useState<FileUploadState[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const addRecentFile = useStore(state => state.addRecentFile);

  const updateFileState = (index: number, update: Partial<FileUploadState>) => {
    setFileStates(prev => prev.map((s, i) => (i === index ? { ...s, ...update } : s)));
  };

  const uploadFiles = useCallback(
    async (files: File[]) => {
      const initial: FileUploadState[] = files.map(file => ({
        file,
        progress: 0,
        status: 'pending',
      }));
      setFileStates(initial);
      setIsUploading(true);

      let queueIndex = 0;

      const uploadOne = async (file: File, index: number) => {
        updateFileState(index, { status: 'uploading' });
        try {
          const result = await uploadService.uploadPcap(file, progress => {
            updateFileState(index, { progress });
          });

          addRecentFile({
            id: result.fileId,
            name: file.name,
            size: file.size,
            uploadedAt: Date.now(),
          });

          updateFileState(index, { status: 'done', progress: 100, fileId: result.fileId });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Upload failed';
          updateFileState(index, { status: 'error', error: message });
        }
      };

      const runNext = async (): Promise<void> => {
        if (queueIndex >= files.length) return;
        const index = queueIndex++;
        await uploadOne(files[index], index);
        await runNext();
      };

      const workers = Array.from({ length: Math.min(CONCURRENCY_LIMIT, files.length) }, runNext);
      await Promise.all(workers);

      setIsUploading(false);
    },
    [addRecentFile]
  );

  const resetUpload = useCallback(() => {
    setFileStates([]);
    setIsUploading(false);
  }, []);

  return {
    uploadFiles,
    fileStates,
    isUploading,
    resetUpload,
  };
};
