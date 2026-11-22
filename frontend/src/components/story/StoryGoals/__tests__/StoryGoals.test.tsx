import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { GoalOutcome } from '@/types';
import { StoryGoals } from '../StoryGoals';

const goal = (g: string, answered: boolean, headline: string | null = null): GoalOutcome => ({
  goal: g,
  answered,
  headline,
  grade: answered ? 'MEASURED' : null,
  confidence: answered ? 90 : 0,
  basis: answered ? ['Suricata alert ET MALWARE'] : [],
  subjects: [],
});

describe('StoryGoals', () => {
  it('shows an answered goal with its headline, grade and confidence', () => {
    render(
      <StoryGoals
        goals={[goal('VICTIM', true, '10.0.0.5 was compromised'), goal('C2', false)]}
        additional={[]}
        loading={false}
      />
    );
    const victim = screen.getByTestId('story-goal-VICTIM');
    expect(within(victim).getByText('Answered')).toBeInTheDocument();
    expect(within(victim).getByText('10.0.0.5 was compromised')).toBeInTheDocument();
    expect(within(victim).getByText(/measured · 90% confidence · 1 reason/)).toBeInTheDocument();
  });

  it('calls an open goal "not established" once an incident was found', () => {
    render(<StoryGoals goals={[goal('VICTIM', true, 'x'), goal('C2', false)]} additional={[]} loading={false} />);
    expect(within(screen.getByTestId('story-goal-C2')).getByText('Not established')).toBeInTheDocument();
  });

  it('says "no lead" on a capture with no incident, rather than reading as a failure', () => {
    render(<StoryGoals goals={[goal('USER', true, 'alice'), goal('C2', false)]} additional={[]} loading={false} />);
    const c2 = screen.getByTestId('story-goal-C2');
    expect(within(c2).getByText('No lead')).toBeInTheDocument();
    expect(within(c2).getByText('Nothing in this capture pointed here.')).toBeInTheDocument();
  });

  it('lists answers that are not a standing goal', () => {
    render(
      <StoryGoals
        goals={[]}
        additional={[{ question: 'bulk', headline: '2 GB sent to 203.0.113.9', grade: 'MEASURED', subjects: [], basis: [], attributes: {} }]}
        loading={false}
      />
    );
    expect(screen.getByText('2 GB sent to 203.0.113.9')).toBeInTheDocument();
  });
});
