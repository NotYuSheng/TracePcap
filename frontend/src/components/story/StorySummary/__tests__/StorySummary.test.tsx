import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { CategoryStatus, GoalOutcome } from '@/types';
import { StorySummary } from '../StorySummary';
import { summarySentence, worthALookNext } from '@/features/insights/categoryStatus';

const cat = (
  key: string,
  status: CategoryStatus['status'],
  extra: Partial<CategoryStatus> = {}
): CategoryStatus => ({
  key,
  axis: 'ACTIVITY',
  label: key.replace(/-/g, ' '),
  attackId: null,
  status,
  unchecked: false,
  reason: null,
  leads: [],
  ...extra,
});

const dns = { label: 'DNS', shows: 'every name a host looked up', query: 'l7Protocols=DNS' };

const CATS: CategoryStatus[] = [
  cat('vantage-point', 'OPEN', { axis: 'CONTEXT', unchecked: true, reason: 'no check covers this yet' }),
  cat('reconnaissance', 'OPEN', { unchecked: true, reason: 'no check covers this yet' }),
  cat('command-and-control', 'OPEN', { leads: [dns] }),
  cat('defense-evasion', 'OPEN', { unchecked: true, leads: [dns] }),
  cat('discovery', 'OPEN', { unchecked: true, reason: 'no check covers this yet' }),
  cat('credential-access', 'RULED_OUT'),
  cat('lateral-movement', 'NOT_OBSERVABLE', { reason: 'no SMB or DCE-RPC in this capture' }),
];

const goal = (g: string, headline: string): GoalOutcome => ({
  goal: g,
  answered: true,
  headline,
  grade: 'MEASURED',
  confidence: 90,
  basis: [],
  subjects: [],
});

const renderIt = (props: Partial<Parameters<typeof StorySummary>[0]> = {}) =>
  render(
    <MemoryRouter>
      <StorySummary fileId="f1" goals={[]} additional={[]} categories={CATS} loading={false} {...props} />
    </MemoryRouter>
  );

describe('summarySentence', () => {
  it('says nothing is concluded when no category is answered', () => {
    expect(summarySentence({ ANSWERED: 0, RULED_OUT: 4, OPEN: 12, NOT_OBSERVABLE: 5 })).toBe(
      "Nothing is concluded yet. 12 are still open, 4 were ruled out and 5 can't be seen in this capture."
    );
  });

  it('leads with the answered count and drops empty parts', () => {
    expect(summarySentence({ ANSWERED: 1, RULED_OUT: 0, OPEN: 1, NOT_OBSERVABLE: 0 })).toBe(
      '1 category is answered. 1 is still open.'
    );
  });
});

describe('worthALookNext', () => {
  it('lists open categories with traffic to look at first, and leaves out capture context', () => {
    expect(worthALookNext(CATS).map(c => c.key)).toEqual([
      'command-and-control', 'defense-evasion', 'reconnaissance', 'discovery',
    ]);
  });
});

describe('StorySummary', () => {
  it('counts categories by status, leaving capture context out of the bar', () => {
    renderIt();
    expect(screen.getByTestId('story-summary-sentence')).toHaveTextContent(
      "Nothing is concluded yet. 4 are still open, 1 was ruled out and 1 can't be seen in this capture."
    );
    expect(screen.getByRole('img')).toHaveAttribute(
      'aria-label', '0 answered, 1 ruled out, 4 open, 1 not observable'
    );
  });

  it('links an open category to its conversations, and folds the rest behind "more open"', async () => {
    renderIt();
    const c2 = screen.getByTestId('story-next-command-and-control');
    expect(within(c2).getByRole('link', { name: 'DNS' })).toHaveAttribute(
      'href', '/analysis/f1/conversations?l7Protocols=DNS'
    );
    expect(screen.queryByTestId('story-next-discovery')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'and 1 more open' }));
    expect(screen.getByTestId('story-next-discovery')).toHaveTextContent('no check covers this yet');
  });

  it('folds away what the capture can\'t show, with why', async () => {
    renderIt();
    expect(screen.queryByText('no SMB or DCE-RPC in this capture', { exact: false })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Not observable/ }));
    expect(screen.getByText(/no SMB or DCE-RPC in this capture/)).toBeInTheDocument();
  });

  it('lists the answers it reached, each opening how it got there', async () => {
    const victim = {
      ...goal('VICTIM', '10.0.0.5 was compromised'),
      derivation: [{ found: '10.0.0.5 talked to a known C2.', rule: null, grade: 'INFERRED', conversations: [] }],
    };
    renderIt({ goals: [victim] });
    expect(screen.getByText('10.0.0.5 was compromised')).toBeInTheDocument();
    expect(screen.getByText(/measured · 90% confidence/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /How we got here/ }));
    expect(await screen.findByText('10.0.0.5 talked to a known C2.')).toBeInTheDocument();
  });

  it('still shows the answers from a backend that reports no categories', () => {
    renderIt({ categories: null, goals: [goal('C2', '203.0.113.9 is a C2')] });
    expect(screen.queryByTestId('story-summary-sentence')).not.toBeInTheDocument();
    expect(screen.getByText('203.0.113.9 is a C2')).toBeInTheDocument();
  });
});
