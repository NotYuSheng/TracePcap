import { describe, expect, it } from 'vitest';
import { isBackendUnreachable } from '../llmError';

describe('isBackendUnreachable', () => {
  it('treats a 502 with no code as the backend being down', () => {
    expect(isBackendUnreachable(502, undefined)).toBe(true);
  });

  it.each(['LLM_UNREACHABLE', 'OUTPUT_TRUNCATED', 'LLM_TIMEOUT', 'LLM_BAD_RESPONSE'])(
    'leaves a 502 with %s to the LLM error handling',
    errorCode => {
      expect(isBackendUnreachable(502, errorCode)).toBe(false);
    }
  );

  it('ignores other failures', () => {
    expect(isBackendUnreachable(500, undefined)).toBe(false);
    expect(isBackendUnreachable(undefined, undefined)).toBe(false);
  });
});
