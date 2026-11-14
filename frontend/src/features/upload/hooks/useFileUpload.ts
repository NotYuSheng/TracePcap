import { useState, useCallback } from 'react';
import { uploadService, type AnalysisOptions } from '../services/uploadService';

export interface UploadEntry {
  id: string; // local key
  fileId?: string; // backend ID, set on success
  fileName: string;
  /** Bytes, for "9.2 of 14.45 MB". */
  size?: number;
  progress: number;
  isUploading: boolean;
  error?: string;
  isDuplicate?: boolean;
  duplicateOfFileId?: string;
}

export const useFileUpload = () => {
  const [uploads, setUploads] = useState<UploadEntry[]>([]);

  const update = (id: string, patch: Partial<UploadEntry>) =>
    setUploads(prev => prev.map(u => (u.id === id ? { ...u, ...patch } : u)));

  const uploadFiles = useCallback(
    async (
      files: File[],
      options: AnalysisOptions = {
        enableNdpi: true,
        enableSuricata: true,
        enableFileExtraction: true,
      }
    ) => {
      const entries: UploadEntry[] = files.map((f, i) => ({
        id: `${Date.now()}-${i}`,
        fileName: f.name,
        size: f.size,
        progress: 0,
        isUploading: true,
      }));

      setUploads(prev => [...prev, ...entries]);

      // Upload sequentially so the backend isn't flooded
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const entryId = entries[i].id;
        try {
          const result = await uploadService.uploadPcap(
            file,
            progress => {
              update(entryId, { progress });
            },
            options
          );

          update(entryId, { isUploading: false, progress: 100, fileId: result.fileId });
        } catch (err: any) {
          const data = err?.response?.data;
          if (err?.response?.status === 409 && data?.existingFileId) {
            update(entryId, {
              isUploading: false,
              progress: 100,
              isDuplicate: true,
              duplicateOfFileId: data.existingFileId,
            });
          } else {
            const message = data?.message || (err instanceof Error ? err.message : 'Upload failed');
            update(entryId, { isUploading: false, error: message });
          }
        }
      }
    },
    []
  );

  const clearUploads = useCallback(() => setUploads([]), []);
  /** Drop the rows that are done with: uploaded (analysis carries on) or failed. */
  const clearFinished = useCallback(() => setUploads(prev => prev.filter(u => u.isUploading)), []);

  // True if any file is currently being uploaded
  const isUploading = uploads.some(u => u.isUploading);

  return { uploadFiles, uploads, clearUploads, clearFinished, isUploading };
};
