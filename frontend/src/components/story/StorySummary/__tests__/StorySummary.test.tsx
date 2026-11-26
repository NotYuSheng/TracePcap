import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { CaptureContext, CategoryStatus, GoalOutcome } from '@/types';
import { adjudicationService } from '@/features/insights/services/adjudicationService';
import { contextParts } from '@/features/insights/captureContext';

vi.mock('@/features/insights/services/adjudicationService', () => ({
  adjudicationService: {
    getOverride: vi.fn().mockResolvedValue(null),
    listEvidence: vi.fn().mockResolvedValue([]),
    setOverride: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock('@/features/me/useMe', () => ({
  usePermission: () => ({ allowed: true, reason: null, permission: null }),
}));
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

  it('renders nothing when there are neither categories nor answers', () => {
    const { container } = renderIt({ categories: null });
    expect(container).toBeEmptyDOMElement();
  });

  it('still shows the answers from a backend that reports no categories', () => {
    renderIt({ categories: null, goals: [goal('C2', '203.0.113.9 is a C2')] });
    expect(screen.queryByTestId('story-summary-sentence')).not.toBeInTheDocument();
    expect(screen.getByText('203.0.113.9 is a C2')).toBeInTheDocument();
  });
});

const CONTEXT: CaptureContext = {
  vantage: {
    key: 'sensor',
    label: 'On a honeypot or sensor',
    host: '192.168.100.28',
    basis: 'MACHINE',
    confidence: 75,
    contested: false,
    candidates: [
      { label: 'On a honeypot or sensor', score: 75, reasons: ['18 hosts opened 44 conversations to it on 18 ports'] },
      { label: 'On an exposed server', score: 35, reasons: [] },
    ],
    reason: '18 hosts opened 44 conversations to it on 18 ports',
    overriddenBy: null,
    question: 'vantage-point',
    entityKey: 'capture',
    options: ['Inside the LAN', 'On the internet uplink', 'On one host', 'On an exposed server', 'On a honeypot or sensor'],
  },
  completeness: { label: 'Complete: no gaps', level: 'complete', notes: [] },
  timeSpan: { start: null, end: null, durationMs: 86_000_000, label: '24 h, 2002-11-29 14:26 to 2002-11-30 14:19 UTC' },
};

describe('contextParts', () => {
  it('reads the context as one line, the vantage first', () => {
    expect(contextParts(CONTEXT)).toEqual({
      vantage: 'On a honeypot or sensor (192.168.100.28)',
      grade: 'inferred',
      rest: ['complete', '24 h'],
    });
  });

  it('says when the vantage is undetermined, or an analyst set it', () => {
    const none = { ...CONTEXT, vantage: { ...CONTEXT.vantage, key: null, label: null, host: null } };
    expect(contextParts(none).vantage).toBe('Vantage point not determined');
    expect(contextParts(none).grade).toBeNull();
    const human = { ...CONTEXT, vantage: { ...CONTEXT.vantage, basis: 'HUMAN' as const } };
    expect(contextParts(human).grade).toBe('set by an analyst');
  });
});

describe('StorySummary capture context', () => {
  it('frames the summary with where the capture was taken', () => {
    renderIt({ context: CONTEXT });
    expect(screen.getByTestId('story-summary-context')).toHaveTextContent(
      'On a honeypot or sensor (192.168.100.28) · inferred · complete · 24 h'
    );
  });

  it('opens the vote with its reasons, and lets an analyst override it', async () => {
    const onContextChanged = vi.fn();
    renderIt({ context: CONTEXT, onContextChanged });
    await userEvent.click(screen.getByRole('button', { name: 'Why · change' }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText(/18 hosts opened 44 conversations/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: /I disagree/ }));
    await userEvent.selectOptions(within(dialog).getAllByRole('combobox')[0], 'Inside the LAN');
    await userEvent.click(within(dialog).getByRole('button', { name: /^Save/ }));
    expect(adjudicationService.setOverride).toHaveBeenCalledWith(
      'f1', 'vantage-point', 'capture', 'Inside the LAN', undefined
    );
    expect(onContextChanged).toHaveBeenCalled();
  });

  it('shows no context line from a backend that has none', () => {
    renderIt();
    expect(screen.queryByTestId('story-summary-context')).not.toBeInTheDocument();
  });
});
