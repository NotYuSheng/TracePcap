import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { NetworkTimeline } from '../NetworkTimeline';

vi.mock('../CapturePane', () => ({
  CapturePane: ({ snapshot, onStep }: { snapshot: NetworkSnapshot; onStep: (d: -1 | 1) => void }) => (
    <div>
      <span data-testid="picked">{snapshot.fileName}</span>
      <button type="button" onClick={() => onStep(-1)}>
        earlier
      </button>
    </div>
  ),
}));

const snap = (i: number): NetworkSnapshot => ({
  id: `s${i}`,
  networkId: 'n',
  fileId: `f${i}`,
  fileName: `week${String(i).padStart(2, '0')}.pcap`,
  snapshotOrder: i,
  startTime: new Date(Date.UTC(2024, 0, 1 + i * 7)).toISOString(),
  endTime: null,
  packetCount: 100,
  totalBytes: 1000,
  changeCount: 0,
  criticalCount: 0,
  securitySignalCount: 0,
  context: null,
  notes: null,
  hasInsights: false,
  addedAt: '2024-01-01T00:00:00',
  subnetOverrides: [],
});

function renderTimeline(count: number) {
  render(
    <MemoryRouter>
      <NetworkTimeline
        networkId="n"
        snapshots={Array.from({ length: count }, (_, i) => snap(i))}
        changeEvents={[]}
        externalEvents={[]}
        annotations={[]}
        onPatchChange={vi.fn()}
        onSnapshotUpdated={vi.fn()}
        onAddNote={vi.fn()}
        onAddEvent={vi.fn()}
        onManage={vi.fn()}
      />
    </MemoryRouter>
  );
}

describe('NetworkTimeline list', () => {
  it('has no pages or search with a few entries', () => {
    renderTimeline(8);
    expect(screen.queryByRole('searchbox', { name: 'Search the timeline' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /on the map$/ })).toHaveLength(8);
  });

  it('pages a long timeline, newest first, and searches across all of it', async () => {
    renderTimeline(25);
    expect(screen.getAllByRole('button', { name: /on the map$/ })).toHaveLength(20);
    expect(screen.queryByRole('button', { name: 'Show week00.pcap on the map' })).not.toBeInTheDocument();
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search the timeline' }), 'week00');
    expect(screen.getAllByRole('button', { name: /on the map$/ })).toHaveLength(1);
  });

  it('turns to the page holding the capture you step to', async () => {
    renderTimeline(25);
    // The newest is picked; step back 20 times to week04, the first entry of page 2.
    for (let i = 0; i < 20; i++) await userEvent.click(screen.getByRole('button', { name: 'earlier' }));
    expect(screen.getByTestId('picked')).toHaveTextContent('week04.pcap');
    expect(screen.getByRole('button', { name: 'Show week04.pcap on the map' })).toBeInTheDocument();
  });
});
