import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { ChangeEvent } from '@/features/monitor/types/monitor.types';
import { ChangeList } from '../ChangeList';

const ev = (i: number, extra: Partial<ChangeEvent> = {}): ChangeEvent => ({
  id: `e${i}`,
  networkId: 'n',
  fromSnapshotId: 's1',
  toSnapshotId: 's2',
  changeType: 'MAC_ADDED',
  entityType: 'DEVICE',
  entityKey: `02:00:00:00:01:${i.toString(16).padStart(2, '0')}`,
  oldValue: null,
  newValue: { ip: `10.0.4.${i}`, deviceType: 'IOT' },
  severity: 'WARNING',
  detectedAt: '2026-11-15T12:00:00',
  reviewed: false,
  notes: null,
  ...extra,
});

const many = [
  ...Array.from({ length: 20 }, (_, i) => ev(i + 1)),
  ev(99, { changeType: 'GATEWAY_CHANGE', entityKey: '10.0.1.1', severity: 'CRITICAL', newValue: { ip: '10.0.1.254' } }),
];

describe('ChangeList', () => {
  it('summarises by kind, most first, and shows one page at a time', () => {
    render(<ChangeList events={many} snapshots={[]} onPatch={vi.fn()} pageSize={8} />);
    expect(screen.getByText('20 new devices · 1 gateway change')).toBeInTheDocument();
    expect(screen.getAllByText(/^New device:|^Gateway changed:/)).toHaveLength(8);
    // Most severe first: the gateway change leads the first page.
    expect(screen.getAllByText(/^New device:|^Gateway changed:/)[0]).toHaveTextContent('Gateway changed');
  });

  it('searches across every page', async () => {
    render(<ChangeList events={many} snapshots={[]} onPatch={vi.fn()} pageSize={8} />);
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search changes' }), '10.0.4.17');
    expect(screen.getAllByText(/^New device:/)).toHaveLength(1);
    expect(screen.getByText(/10\.0\.4\.17$/)).toBeInTheDocument();
  });

  it('has no search or pages for a short list', () => {
    render(<ChangeList events={many.slice(0, 3)} snapshots={[]} onPatch={vi.fn()} pageSize={8} />);
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
  });

  it('filters by severity, kind and reviewed state', async () => {
    const events = [...many, ev(50, { reviewed: true })];
    render(<ChangeList events={events} snapshots={[]} onPatch={vi.fn()} pageSize={50} />);
    await userEvent.click(screen.getByRole('button', { name: /Critical/ }));
    expect(screen.getAllByText(/^New device:|^Gateway changed:/)).toHaveLength(1);
    await userEvent.click(screen.getByRole('button', { name: /^All/ }));
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Kind of change' }), 'new device');
    expect(screen.getAllByText(/^New device:/)).toHaveLength(21);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Reviewed' }), 'REVIEWED');
    expect(screen.getAllByText(/^New device:/)).toHaveLength(1);
  });
});
