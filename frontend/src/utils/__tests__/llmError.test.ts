import { describe, expect, it } from 'vitest';
import { isLlmUnreachable } from '../llmError';

describe('isLlmUnreachable', () => {
  it('treats the backend unreachable code as unreachable', () => {
    expect(isLlmUnreachable(502, 'LLM_UNREACHABLE')).toBe(true);
  });

  it('treats a 502 with no code as unreachable', () => {
    expect(isLlmUnreachable(502, undefined)).toBe(true);
  });

  it.each(['OUTPUT_TRUNCATED', 'LLM_TIMEOUT', 'LLM_BAD_RESPONSE'])(
    'keeps a 502 with %s distinct, so its own message reaches the user',
    errorCode => {
      expect(isLlmUnreachable(502, errorCode)).toBe(false);
    }
  );

  it('ignores other failures', () => {
    expect(isLlmUnreachable(500, undefined)).toBe(false);
    expect(isLlmUnreachable(undefined, undefined)).toBe(false);
  });
});
