// API Response Types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
  message?: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: unknown;
}

// Upload Types
export interface UploadResponse {
  fileId: string;
  fileName: string;
  fileSize: number;
  status: 'processing' | 'completed' | 'failed';
  uploadedAt: number;
}

export interface UploadProgress {
  uploadId: string;
  status: 'uploading' | 'processing' | 'analyzing' | 'completed' | 'failed';
  progress: number;
  message?: string;
}

// Pagination Types
export interface PaginatedResponse<T> {
  data: T[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface PaginationParams {
  page?: number;
  pageSize?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

// Filter Types
export interface FilterParams {
  protocols?: string[];
  timeRange?: {
    start: number;
    end: number;
  };
  sources?: string[];
  destinations?: string[];
  minPacketSize?: number;
  maxPacketSize?: number;
}
