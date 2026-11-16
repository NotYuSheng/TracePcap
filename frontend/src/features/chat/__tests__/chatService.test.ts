/** The capture chat's step lines and tools note (#1161). */
import { describe, expect, it } from 'vitest';
import { stepArgs, toolCallingNote, type ChatStep } from '../chatService';

const step = (args: string | null): ChatStep => ({
  tool: 't', label: 'T', arguments: args, status: 'DONE', summary: null, ms: 1,
});

describe('stepArgs', () => {
  it('shows a single argument bare, several as name: value, and skips empty ones', () => {
    expect(stepArgs(step('{"filter":"udp.port == 53"}'))).toBe('udp.port == 53');
    expect(stepArgs(step('{"ip":"10.0.0.5","port":53,"app":""}'))).toBe('ip: 10.0.0.5 · port: 53');
    expect(stepArgs(step('not json'))).toBe('not json');
    expect(stepArgs(step(null))).toBe('');
  });
});

describe('toolCallingNote', () => {
  it('says whether this LLM takes tools', () => {
    expect(toolCallingNote('supported')).toMatch(/takes tools/);
    expect(toolCallingNote('unsupported')).toMatch(/didn't accept tools/);
    expect(toolCallingNote('off')).toMatch(/switched off/);
    expect(toolCallingNote('unknown')).toMatch(/first question/);
  });
});
