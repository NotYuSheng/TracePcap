import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type {
  FilterGenerationRequest,
  FilterGenerationResponse,
  FilterExecutionRequest,
  FilterExecutionResponse,
} from '@/types';

export const filterService = {
  /**
   * Generate a pcap filter from natural language query
   */
  generateFilter: async (fileId: string, query: string): Promise<FilterGenerationResponse> => {
    const request: FilterGenerationRequest = {
      fileId,
      naturalLanguageQuery: query,
    };
    const response = await apiClient.post<FilterGenerationResponse>(
      API_ENDPOINTS.GENERATE_FILTER(fileId),
      request
    );
    return response.data;
  },

  /**
   * Execute a pcap filter and get matching packets with pagination
   */
  executeFilter: async (
    fileId: string,
    filter: string,
    page: number = 1,
    pageSize: number = 25
  ): Promise<FilterExecutionResponse> => {
    const request: FilterExecutionRequest = {
      fileId,
      filter,
    };
    const response = await apiClient.post<FilterExecutionResponse>(
      API_ENDPOINTS.EXECUTE_FILTER(fileId),
      request,
      { params: { page, pageSize } }
    );
    return response.data;
  },
};
