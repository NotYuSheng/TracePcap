import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { StoryAggregates } from '@/types';
import { AggregatesPanel } from '../AggregatesPanel';

const aggregates = (protocolCount: number) =>
  ({
    coverage: { totalConversations: 10, totalPackets: 100 },
    topExternalAsns: [],
    protocolRiskMatrix: Array.from({ length: protocolCount }, (_, i) => ({
      protocol: `PROTO-${i + 1}`,
      total: 1,
      atRisk: 0,
    })),
    tlsAnomalySummary: { total: 0, selfSigned: 0, expired: 0, unknownCa: 0 },
    unknownAppPct: 0,
    beaconCandidates: [],
  }) as unknown as StoryAggregates;

describe('AggregatesPanel protocol risk table', () => {
  it('shows one page of a long protocol list', () => {
    render(<AggregatesPanel aggregates={aggregates(391)} />);

    expect(screen.getByText('PROTO-10')).toBeInTheDocument();
    expect(screen.queryByText('PROTO-11')).not.toBeInTheDocument();
    expect(screen.getByText('Showing 1 to 10 of 391 items')).toBeInTheDocument();
  });

  it('moves to the next page', async () => {
    render(<AggregatesPanel aggregates={aggregates(391)} />);

    await userEvent.click(screen.getByRole('button', { name: '2' }));

    expect(screen.getByText('PROTO-11')).toBeInTheDocument();
    expect(screen.queryByText('PROTO-10')).not.toBeInTheDocument();
  });

  it('shows no pager or search when the list fits on one page', () => {
    render(<AggregatesPanel aggregates={aggregates(10)} />);

    expect(screen.getByText('PROTO-10')).toBeInTheDocument();
    expect(screen.queryByText(/Showing/)).not.toBeInTheDocument();
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
  });

  it('searches every page, ignoring case', async () => {
    render(<AggregatesPanel aggregates={aggregates(391)} />);

    await userEvent.type(screen.getByRole('searchbox'), 'proto-391');

    expect(screen.getByText('PROTO-391')).toBeInTheDocument();
    expect(screen.queryByText('PROTO-1')).not.toBeInTheDocument();
  });

  it('goes back to the first page when the search changes', async () => {
    render(<AggregatesPanel aggregates={aggregates(391)} />);
    await userEvent.click(screen.getByRole('button', { name: '2' }));

    await userEvent.type(screen.getByRole('searchbox'), 'PROTO-3');

    expect(screen.getByText(/^Showing 1 to 10 of \d+ items$/)).toBeInTheDocument();
  });

  it('says so when nothing matches', async () => {
    render(<AggregatesPanel aggregates={aggregates(391)} />);

    await userEvent.type(screen.getByRole('searchbox'), 'nothing');

    expect(screen.getByText('No protocols match your search.')).toBeInTheDocument();
  });
});
