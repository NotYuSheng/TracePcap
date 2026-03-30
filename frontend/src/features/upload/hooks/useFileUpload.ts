import { useState, useCallback } from 'react';
import { useStore } from '@/store';
import { uploadService } from '../services/uploadService';

export interface UploadEntry {
  id: string;       // local key
  fileId?: string;  // backend ID, set on success
  fileName: string;
  progress: number;
  isUploading: boolean;
  error?: string;
}

export const useFileUpload = () => {
  const [uploads, setUploads] = useState<UploadEntry[]>([]);
  const addRecentFile = useStore(state => state.addRecentFile);

  const update = (id: string, patch: Partial<UploadEntry>) =>
    setUploads(prev => prev.map(u => (u.id === id ? { ...u, ...patch } : u)));

  const uploadFiles = useCallback(
    async (files: File[]) => {
      const entries: UploadEntry[] = files.map((f, i) => ({
        id: `${Date.now()}-${i}`,
        fileName: f.name,
        progress: 0,
        isUploading: true,
      }));

      setUploads(prev => [...prev, ...entries]);

      // Upload sequentially so the backend isn't flooded
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const entryId = entries[i].id;
        try {
          const result = await uploadService.uploadPcap(file, progress => {
            update(entryId, { progress });
          });

          addRecentFile({
            id: result.fileId,
            name: file.name,
            size: file.size,
            uploadedAt: Date.now(),
          });

          update(entryId, { isUploading: false, progress: 100, fileId: result.fileId });
        } catch (err) {
          update(entryId, {
            isUploading: false,
            error: err instanceof Error ? err.message : 'Upload failed',
          });
        }
      }
    },
    [addRecentFile]
  );

  const clearUploads = useCallback(() => setUploads([]), []);

  // True if any file is currently being uploaded
  const isUploading = uploads.some(u => u.isUploading);

  return { uploadFiles, uploads, clearUploads, isUploading };
};
