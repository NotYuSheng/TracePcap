import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import type { ProtocolStats } from '@/types';
import { ProtocolBreakdownChart } from '../ProtocolBreakdownChart';

const stats = (count: number): ProtocolStats[] =>
  Array.from({ length: count }, (_, i) => ({
    protocol: `PROTO-${i + 1}`,
    count: count - i,
    percentage: 1,
    bytes: 100,
  }));

describe('ProtocolBreakdownChart table', () => {
  it('shows one page of a long protocol list', () => {
    render(<ProtocolBreakdownChart protocolStats={stats(391)} />);

    expect(screen.getByRole('cell', { name: 'PROTO-10' })).toBeInTheDocument();
    expect(screen.queryByRole('cell', { name: 'PROTO-11' })).not.toBeInTheDocument();
    expect(screen.getByText('Showing 1 to 10 of 391 items')).toBeInTheDocument();
  });

  it('reaches the rarer protocols on later pages', async () => {
    render(<ProtocolBreakdownChart protocolStats={stats(391)} />);

    await userEvent.click(screen.getByRole('button', { name: '2' }));

    expect(screen.getByRole('cell', { name: 'PROTO-11' })).toBeInTheDocument();
  });

  it('shows no pager or search when the list fits on one page', () => {
    render(<ProtocolBreakdownChart protocolStats={stats(10)} />);

    expect(screen.queryByText(/Showing/)).not.toBeInTheDocument();
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
  });

  it('searches every page, ignoring case', async () => {
    render(<ProtocolBreakdownChart protocolStats={stats(391)} />);

    await userEvent.type(screen.getByRole('searchbox'), 'proto-391');

    expect(screen.getByRole('cell', { name: 'PROTO-391' })).toBeInTheDocument();
    expect(screen.queryByRole('cell', { name: 'PROTO-1' })).not.toBeInTheDocument();
  });

  it('goes back to the first page when the search changes', async () => {
    render(<ProtocolBreakdownChart protocolStats={stats(391)} />);
    await userEvent.click(screen.getByRole('button', { name: '2' }));

    await userEvent.type(screen.getByRole('searchbox'), 'PROTO-3');

    expect(screen.getByText(/^Showing 1 to 10 of \d+ items$/)).toBeInTheDocument();
  });

  it('shows every row on request, and can go back to pages', async () => {
    render(<ProtocolBreakdownChart protocolStats={stats(391)} />);

    await userEvent.click(screen.getByRole('button', { name: 'Show all 391' }));

    expect(screen.getByRole('cell', { name: 'PROTO-391' })).toBeInTheDocument();
    expect(screen.queryByText(/Showing/)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Show fewer' }));

    expect(screen.queryByRole('cell', { name: 'PROTO-391' })).not.toBeInTheDocument();
    expect(screen.getByText('Showing 1 to 10 of 391 items')).toBeInTheDocument();
  });

  it('says so when nothing matches', async () => {
    render(<ProtocolBreakdownChart protocolStats={stats(391)} />);

    await userEvent.type(screen.getByRole('searchbox'), 'nothing');

    expect(screen.getByText('No protocols match your search.')).toBeInTheDocument();
  });
});
