import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { Story } from '@/types';
import { mockStory, generateMockStory } from '@/mocks/mockStoryData';

const USE_MOCK = import.meta.env.VITE_USE_MOCK_DATA === 'true';

export const storyService = {
  /**
   * Generate a story/narrative for a PCAP file
   * @param fileId - The file ID to generate story for
   * @returns Generated story with narrative sections
   */
  generateStory: async (fileId: string): Promise<Story> => {
    if (USE_MOCK) {
      // Simulate AI processing time
      await new Promise(resolve => setTimeout(resolve, 2000));
      return generateMockStory(fileId);
    }

    const response = await apiClient.post<Story>(API_ENDPOINTS.GENERATE_STORY(fileId));
    return response.data;
  },

  /**
   * Get an existing story by ID
   * @param storyId - The story ID
   * @returns The story
   */
  getStory: async (storyId: string): Promise<Story> => {
    if (USE_MOCK) {
      await new Promise(resolve => setTimeout(resolve, 400));
      return mockStory;
    }

    const response = await apiClient.get<Story>(API_ENDPOINTS.GET_STORY(storyId));
    return response.data;
  },
};
