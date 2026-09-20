import { describe, expect, it } from 'vitest';
import type { InvestigationReport } from '@/types';
import { investigationToSummary } from './storyService';

const goal = (
  g: string,
  answered: boolean,
  headline: string | null = null,
  grade: string | null = null
) => ({ goal: g, answered, headline, grade, confidence: answered ? 55 : 0, basis: [], subjects: [] });

describe('investigationToSummary', () => {
  it('maps answered goals onto the standard-question keys the panel labels', () => {
    const report: InvestigationReport = {
      goals: [
        goal('VICTIM', true, '172.16.1.66 — contacted a known malware C2', 'INFERRED'),
        goal('USER', true, 'ccollier signed in on 172.16.1.66', 'MEASURED'),
        goal('MALWARE', true, 'STRRAT — malware family identified', 'INFERRED'),
        goal('C2', true, '141.98.10.79 — C2 for STRRAT', 'INFERRED'),
      ],
      additional: [],
      unknowns: [],
      coverage: ['beacon', 'stream-classifier'],
    };

    const { answers, unknowns } = investigationToSummary(report);

    expect(answers.map(a => a.question)).toEqual(['victim', 'signed-in-user', 'malware', 'c2']);
    expect(answers.find(a => a.question === 'signed-in-user')?.grade).toBe('MEASURED');
    expect(unknowns).toEqual([]);
  });

  it('omits open goals from the answers and reports them as unknowns', () => {
    const report: InvestigationReport = {
      goals: [
        goal('USER', true, 'ccollier signed in on 172.16.1.66', 'MEASURED'),
        goal('C2', false),
      ],
      additional: [],
      unknowns: ['C2'],
      coverage: [],
    };

    const { answers, unknowns } = investigationToSummary(report);

    expect(answers).toHaveLength(1);
    expect(answers[0].question).toBe('signed-in-user');
    expect(unknowns).toEqual(['C2']);
  });

  it('keeps non-goal answers (e.g. a bulk transfer) after the goal answers', () => {
    const transfer = {
      question: 'data-transfer',
      headline: '172.16.1.66 sent 8.0 MB to X',
      grade: 'INFERRED',
      subjects: [],
      basis: [],
      attributes: {},
    };
    const report: InvestigationReport = {
      goals: [goal('C2', true, '141.98.10.79 — C2', 'INFERRED')],
      additional: [transfer],
      unknowns: [],
      coverage: [],
    };

    expect(investigationToSummary(report).answers.map(a => a.question)).toEqual(['c2', 'data-transfer']);
  });
});
