import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { Answer, InvestigationReport, Story } from '@/types';

/** Goal → the standard-question key the panel already has a label and icon for. */
const GOAL_QUESTION: Record<string, string> = {
  VICTIM: 'victim',
  USER: 'signed-in-user',
  MALWARE: 'malware',
  C2: 'c2',
};

/** What the Investigation Summary renders: the conclusions, and the goals still unknown. */
export interface InvestigationSummary {
  answers: Answer[];
  /** Goals no technique could close on this capture, e.g. ['C2', 'MALWARE']. */
  unknowns: string[];
}

/** Flattens a report into panel answers: each answered goal, then any non-goal answers. */
export function investigationToSummary(report: InvestigationReport): InvestigationSummary {
  const goalAnswers: Answer[] = report.goals
    .filter((g) => g.answered && g.headline)
    .map((g) => ({
      question: GOAL_QUESTION[g.goal] ?? g.goal.toLowerCase(),
      headline: g.headline as string,
      grade: g.grade ?? 'INFERRED',
      subjects: g.subjects,
      basis: g.basis,
      attributes: {},
    }));
  return { answers: [...goalAnswers, ...report.additional], unknowns: report.unknowns };
}

export const storyService = {
  /**
   * Deterministic answers to the standard investigation questions for a file (#813) — victim, C2,
   * malware, signed-in user. Producer-only and cheap; the pivots' conclusions are NOT here, so
   * surfaces that present the investigation read {@link storyService.getInvestigation} instead.
   */
  getAnswers: async (fileId: string): Promise<Answer[]> => {
    const response = await apiClient.get<Answer[]>(API_ENDPOINTS.ANSWERS(fileId));
    return response.data;
  },

  /**
   * The autonomous investigation for a file (#819): the standard answers plus what following leads
   * uncovered (a beacon classified as a C2 with no IDS rule), and the goals still unknown. This is
   * what the Investigation Summary should show — it is the same board the narrative is built from.
   */
  getInvestigation: async (fileId: string): Promise<InvestigationSummary> => {
    const response = await apiClient.get<InvestigationReport>(API_ENDPOINTS.INVESTIGATION(fileId));
    return investigationToSummary(response.data);
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
