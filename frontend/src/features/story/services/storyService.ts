import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { Story } from '@/types';

export const storyService = {
  /**
   * Generate a story/narrative for a PCAP file
   */
  generateStory: async (fileId: string, additionalContext?: string, timeoutMs?: number): Promise<Story> => {
    const body = additionalContext?.trim() ? { additionalContext: additionalContext.trim() } : undefined;
    const response = await apiClient.post<Story>(API_ENDPOINTS.GENERATE_STORY(fileId), body, {
      ...(timeoutMs !== undefined && { timeout: timeoutMs }),
    });
    return response.data;
  },

  /**
   * Get an existing story by ID
   */
  getStory: async (storyId: string): Promise<Story> => {
    const response = await apiClient.get<Story>(API_ENDPOINTS.GET_STORY(storyId));
    return response.data;
  },

  /**
   * Get the latest story for a file, returns null if none exists
   */
  askQuestion: async (
    storyId: string,
    question: string,
    history: { role: 'user' | 'assistant'; text: string }[]
  ): Promise<{ answer: string; followUpQuestions: string[] }> => {
    const response = await apiClient.post<{ answer: string; followUpQuestions: string[] }>(
      API_ENDPOINTS.ASK_STORY(storyId),
      { question, history }
    );
    return response.data;
  },

  getStoryByFileId: async (fileId: string): Promise<Story | null> => {
    const response = await apiClient.get<Story>(API_ENDPOINTS.GET_STORY_BY_FILE(fileId), {
      validateStatus: (status) => status === 200 || status === 204,
    });
    return response.status === 204 ? null : response.data;
  },
};
