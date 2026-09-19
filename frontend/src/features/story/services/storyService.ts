import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { Answer, Story } from '@/types';

export const storyService = {
  /**
   * Deterministic answers to the standard investigation questions for a file (#813) — victim, C2,
   * malware, signed-in user. The same conclusions that feed the narrative, surfaced directly.
   */
  getAnswers: async (fileId: string): Promise<Answer[]> => {
    const response = await apiClient.get<Answer[]>(API_ENDPOINTS.ANSWERS(fileId));
    return response.data;
  },

  /**
   * Generate a story/narrative for a PCAP file
   */
  generateStory: async (
    fileId: string,
    additionalContext?: string,
    timeoutMs?: number,
    customPrompt?: string,
    maxFindings?: number,
    maxRiskMatrix?: number
  ): Promise<Story> => {
    const body: Record<string, string | number> = { fileId };
    if (additionalContext?.trim()) body.additionalContext = additionalContext.trim();
    if (customPrompt?.trim()) body.customPrompt = customPrompt.trim();
    if (maxFindings !== undefined) body.maxFindings = maxFindings;
    if (maxRiskMatrix !== undefined) body.maxRiskMatrix = maxRiskMatrix;
    const response = await apiClient.post<Story>(API_ENDPOINTS.STORIES, body, {
      ...(timeoutMs !== undefined && { timeout: timeoutMs + 10000 }),
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
      validateStatus: status => status === 200 || status === 204,
    });
    return response.status === 204 ? null : response.data;
  },
};
