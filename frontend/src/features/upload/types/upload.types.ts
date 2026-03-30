// Upload Response Types (matches backend FileUploadResponse)
export interface UploadResponse {
  fileId: string;
  fileName: string;
  fileSize: number;
  status: string; // 'processing' | 'completed' | 'failed' | 'uploading'
  uploadedAt: number[] | number; // Backend returns LocalDateTime as array [year, month, day, hour, min, sec, nano]
  storageLocation?: string;
}

export interface UploadProgress {
  uploadId: string;
  status: 'uploading' | 'processing' | 'analyzing' | 'completed' | 'failed';
  progress: number;
  message?: string;
}

// Upload Error Types
export interface UploadError {
  code: string;
  message: string;
  details?: unknown;
}

// File Validation Types
export interface FileValidationResult {
  valid: boolean;
  error?: string;
}

// Upload State Types
export interface UploadState {
  isUploading: boolean;
  progress: number;
  uploadId?: string;
  fileId?: string;
  error?: UploadError;
}
