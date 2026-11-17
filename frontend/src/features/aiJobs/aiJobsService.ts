import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS, MONITOR_ENDPOINTS } from '@/services/api/endpoints';
import type { AiJob } from './aiJobs.types';

/** Fired whenever this tab starts or cancels a job, so the header's chip looks again at once. */
export const AI_JOBS_CHANGED = 'tracepcap:ai-jobs-changed';
const changed = () => window.dispatchEvent(new Event(AI_JOBS_CHANGED));

export interface StoryJobOptions {
  additionalContext?: string;
  customPrompt?: string;
  maxFindings?: number;
  maxRiskMatrix?: number;
  networkId?: string;
}

export const aiJobsService = {
  list: async (filter: { kind?: string; subjectId?: string } = {}): Promise<AiJob[]> => {
    const r = await apiClient.get<AiJob[]>(API_ENDPOINTS.AI_JOBS, { params: filter });
    return r.data;
  },

  get: async (jobId: string): Promise<AiJob> => (await apiClient.get<AiJob>(API_ENDPOINTS.AI_JOB(jobId))).data,

  cancel: async (jobId: string): Promise<AiJob> => {
    const r = await apiClient.post<AiJob>(API_ENDPOINTS.AI_JOB_CANCEL(jobId));
    changed();
    return r.data;
  },

  startStory: async (fileId: string, options: StoryJobOptions): Promise<AiJob> => {
    const body: StoryJobOptions = {};
    if (options.additionalContext?.trim()) body.additionalContext = options.additionalContext.trim();
    if (options.customPrompt?.trim()) body.customPrompt = options.customPrompt.trim();
    if (options.maxFindings !== undefined) body.maxFindings = options.maxFindings;
    if (options.maxRiskMatrix !== undefined) body.maxRiskMatrix = options.maxRiskMatrix;
    if (options.networkId) body.networkId = options.networkId;
    const r = await apiClient.post<AiJob>(API_ENDPOINTS.STORY_JOBS(fileId), body);
    changed();
    return r.data;
  },

  startInsights: async (networkId: string, options: { audience?: string; focus?: string }): Promise<AiJob> => {
    const r = await apiClient.post<AiJob>(MONITOR_ENDPOINTS.INSIGHT_JOBS(networkId), options);
    changed();
    return r.data;
  },
};
