import { apiClient } from '@/services/api/client';

/** One tool the capture chat can use (#1161). */
export interface ChatTool {
  name: string;
  label: string;
  summary: string;
  example: string;
}

export interface ChatTools {
  tools: ChatTool[];
  /** "on", "off", or for the auto setting "supported", "unsupported" or "unknown". */
  toolCalling: string;
}

export interface ChatStep {
  tool: string;
  label: string;
  /** The arguments as the model sent them (JSON). */
  arguments: string | null;
  status: 'RUNNING' | 'DONE' | 'FAILED';
  summary: string | null;
  ms: number | null;
}

export interface CheckedFilter {
  expression: string;
  matches: number | null;
}

export interface ChatTurn {
  id: string;
  status: 'RUNNING' | 'DONE' | 'FAILED';
  steps: ChatStep[];
  answer: string | null;
  followUpQuestions: string[];
  filters: CheckedFilter[];
  toolsOffered: boolean;
  /** Set when the LLM server answered with another model than the configured one. */
  modelNote?: string | null;
  error: string | null;
  errorCode: string | null;
  elapsedMs: number;
}

export interface ChatHistoryEntry {
  role: 'user' | 'assistant';
  text: string;
}

export const chatService = {
  tools: async (): Promise<ChatTools> => (await apiClient.get<ChatTools>('/chat-tools')).data,

  ask: async (
    fileId: string,
    question: string,
    history: ChatHistoryEntry[],
    networkId?: string | null
  ): Promise<ChatTurn> =>
    (
      await apiClient.post<ChatTurn>(`/files/${fileId}/chat-turns`, {
        question,
        history,
        networkId: networkId ?? null,
      })
    ).data,

  turn: async (fileId: string, turnId: string): Promise<ChatTurn> =>
    (await apiClient.get<ChatTurn>(`/files/${fileId}/chat-turns/${turnId}`)).data,
};

/** "Check a filter" with its arguments, for a step line: `{"filter":"udp.port == 53"}` → `udp.port == 53`. */
export function stepArgs(step: ChatStep): string {
  if (!step.arguments) return '';
  try {
    const parsed = JSON.parse(step.arguments) as Record<string, unknown>;
    return Object.entries(parsed)
      .filter(([, v]) => v !== null && v !== undefined && v !== '')
      .map(([k, v]) => (Object.keys(parsed).length === 1 ? String(v) : `${k}: ${String(v)}`))
      .join(' · ');
  } catch {
    return step.arguments;
  }
}

/** What the tools list says about the configured LLM. */
export function toolCallingNote(status: string): string {
  switch (status) {
    case 'on':
    case 'supported':
      return 'This LLM takes tools.';
    case 'off':
      return 'Tools are switched off (LLM_TOOL_CALLING=off): answers come from the findings and the story only.';
    case 'unsupported':
      return "This LLM's server didn't accept tools, so answers come from the findings and the story only.";
    default:
      return 'Tools are tried on the first question; if the LLM server refuses them, answers come from the findings and the story only.';
  }
}
