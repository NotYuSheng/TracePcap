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

  it('omits open goals from the answers and reports them as unknowns once there is an incident', () => {
    const report: InvestigationReport = {
      goals: [
        goal('C2', true, '141.98.10.79 — C2', 'INFERRED'),
        goal('MALWARE', false),
      ],
      additional: [],
      unknowns: ['MALWARE'],
      coverage: [],
    };

    const { answers, unknowns } = investigationToSummary(report);

    expect(answers).toHaveLength(1);
    expect(answers[0].question).toBe('c2');
    expect(unknowns).toEqual(['MALWARE']);
  });

  it('does not list unknowns when the only answer is context, not an incident', () => {
    // A benign capture that merely shows who is signed in: "victim, malware, C2 not established"
    // would read like a failure when there was never a lead to follow.
    const report: InvestigationReport = {
      goals: [
        goal('USER', true, 'ccollier signed in on 172.16.1.66', 'MEASURED'),
        goal('VICTIM', false),
        goal('MALWARE', false),
        goal('C2', false),
      ],
      additional: [],
      unknowns: ['VICTIM', 'MALWARE', 'C2'],
      coverage: [],
    };

    const { answers, unknowns } = investigationToSummary(report);

    expect(answers.map(a => a.question)).toEqual(['signed-in-user']);
    expect(unknowns).toEqual([]);
  });

  it('keeps a second answer for a goal (e.g. another C2) rather than dropping it', () => {
    const second = {
      question: 'c2',
      headline: '203.0.113.7 — C2 for OTHER',
      grade: 'INFERRED',
      subjects: [],
      basis: [],
      attributes: {},
    };
    const report: InvestigationReport = {
      goals: [goal('C2', true, '141.98.10.79 — C2 for STRRAT', 'INFERRED')],
      additional: [second],
      unknowns: [],
      coverage: [],
    };

    expect(investigationToSummary(report).answers.map(a => a.headline)).toEqual([
      '141.98.10.79 — C2 for STRRAT',
      '203.0.113.7 — C2 for OTHER',
    ]);
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
