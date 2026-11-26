import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { ConversationFilterPanel } from '../ConversationFilterPanel';
import type { ConversationFacetCounts, ConversationFilters } from '@/features/conversation/types';

const filters: ConversationFilters = {
  ip: '', port: '', payloadContains: '', protocols: [], l7Protocols: [], apps: [], categories: [],
  hasRisks: false, fileTypes: [], riskTypes: [], customSignatures: [], suricataAlerts: [],
  deviceTypes: [], countries: [], sortBy: '', sortDir: 'asc', page: 1, pageSize: 25,
};

const empty = (): ConversationFacetCounts => ({
  protocols: {}, l7Protocols: {}, apps: {}, categories: {}, fileTypes: {}, riskTypes: {},
  customSignatures: {}, suricataAlerts: {}, countries: {}, deviceTypes: {},
});

function renderPanel(facetCounts: ConversationFacetCounts, f: ConversationFilters = filters) {
  const onFiltersChange = vi.fn();
  render(
    <MemoryRouter>
      <ConversationFilterPanel
        filters={f}
        onFiltersChange={onFiltersChange}
        onClearAll={() => {}}
        protocols={[]}
        l7Protocols={[]}
        apps={[]}
        categories={[]}
        fileTypes={[]}
        riskTypes={[]}
        customSignatureOptions={[]}
        suricataAlertOptions={[]}
        countryOptions={[]}
        activeFilterCount={0}
        facetCounts={facetCounts}
        defaultOpen
      />
    </MemoryRouter>
  );
  return onFiltersChange;
}

describe('Connection outcome filter (#1233)', () => {
  it('shows a pill per outcome the capture has, with its count, and toggles it', async () => {
    const onFiltersChange = renderPanel({
      ...empty(),
      outcomes: { ANSWERED: 99, NO_ANSWER: 9, REJECTED: 5, UNKNOWN: 97 },
    });

    expect(await screen.findByText('Connection outcome')).toBeInTheDocument();
    const noAnswer = screen.getByRole('button', { name: /^No answer/ });
    expect(noAnswer).toHaveTextContent('9');
    expect(screen.getByRole('button', { name: /^Refused/ })).toHaveTextContent('5');

    await userEvent.click(noAnswer);
    expect(onFiltersChange).toHaveBeenCalledWith({ outcomes: ['NO_ANSWER'] });
  });

  it('removes an active outcome when clicked again', async () => {
    const onFiltersChange = renderPanel(
      { ...empty(), outcomes: { ANSWERED: 3, NO_ANSWER: 2 } },
      { ...filters, outcomes: ['NO_ANSWER', 'ANSWERED'] }
    );
    await userEvent.click(await screen.findByRole('button', { name: /^No answer/ }));
    expect(onFiltersChange).toHaveBeenCalledWith({ outcomes: ['ANSWERED'] });
  });

  it('stays hidden for a capture analysed before outcomes existed', async () => {
    renderPanel({ ...empty(), outcomes: { UNKNOWN: 210 } });
    await screen.findByRole('dialog').catch(() => null);
    expect(screen.queryByText('Connection outcome')).not.toBeInTheDocument();
  });
});
