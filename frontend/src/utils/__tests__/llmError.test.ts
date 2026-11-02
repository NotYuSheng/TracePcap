import { describe, expect, it } from 'vitest';
import { describeLlmError } from '../llmError';

const options = {
  subject: 'Story generation',
  timeoutMs: 900_000,
  timeoutHint: 'reduce the capture size',
  fallback: 'Failed to generate story',
};

const httpError = (status: number, data: Record<string, unknown> = {}) =>
  Object.assign(new Error(`Request failed with status code ${status}`), {
    response: { status, data },
  });

describe('describeLlmError', () => {
  it('blames the backend for a 502 that never reached its error handler', () => {
    expect(describeLlmError(httpError(502), options)).toContain('The backend is not responding');
  });

  it('blames the LLM server only when the backend says it is unreachable', () => {
    const err = httpError(502, { errorCode: 'LLM_UNREACHABLE', message: 'raw detail' });
    expect(describeLlmError(err, options)).toContain('The LLM server is not responding');
  });

  it('shows the server message for an LLM failure with a reason of its own', () => {
    const err = httpError(502, { errorCode: 'OUTPUT_TRUNCATED', message: 'Raise LLM_MAX_TOKENS.' });
    expect(describeLlmError(err, options)).toBe('Raise LLM_MAX_TOKENS.');
  });

  it('shows the server message for a failure that is not a 502', () => {
    expect(describeLlmError(httpError(500, { message: 'Nope' }), options)).toBe('Nope');
  });

  it.each([
    ['the backend', httpError(502, { errorCode: 'LLM_TIMEOUT' })],
    ['the client', Object.assign(new Error('timeout'), { code: 'ECONNABORTED' })],
  ])('explains a timeout from %s using the caller wording', (_, err) => {
    expect(describeLlmError(err, options)).toBe(
      'Story generation timed out after 15 minutes. ' +
        'The LLM is responding but took too long — try again or reduce the capture size.'
    );
  });

  it('counts short timeouts in seconds', () => {
    const err = httpError(502, { errorCode: 'LLM_TIMEOUT' });
    expect(describeLlmError(err, { ...options, timeoutMs: 1000 })).toContain('after 1 second.');
  });

  it('falls back to the error message, then the caller fallback', () => {
    expect(describeLlmError(new Error('Network Error'), options)).toBe('Network Error');
    expect(describeLlmError(undefined, options)).toBe('Failed to generate story');
  });
});
