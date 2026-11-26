import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { WorthALookCard } from '../WorthALookCard';
import { worthALookGroups } from '@/features/insights/categoryStatus';
import type { CategoryStatus } from '@/types';

const cat = (over: Partial<CategoryStatus> & Pick<CategoryStatus, 'key' | 'label'>): CategoryStatus => ({
  axis: 'ACTIVITY',
  attackId: null,
  status: 'OPEN',
  unchecked: false,
  reason: null,
  leads: [],
  ...over,
});

const C2_LEADS = [
  { label: 'DNS', shows: 'every name a host looked up', query: 'l7Protocols=DNS' },
  { label: 'TLS', shows: 'server names and certificates', query: 'l7Protocols=TLS' },
];

describe('WorthALookCard (#1292)', () => {
  it('lists the categories with traffic here, says their status, and links each protocol', () => {
    render(
      <MemoryRouter>
        <WorthALookCard
          fileId="f1"
          categories={[
            cat({
              key: 'signed-in-user', label: "Who's signed in", axis: 'ENTITY', status: 'ANSWERED',
              leads: [{ label: 'LDAP', shows: 'directory lookups', query: 'apps=LDAP' }],
            }),
            cat({
              key: 'lateral-movement', label: 'Lateral Movement',
              leads: [{ label: 'DCE-RPC', shows: 'remote calls', query: 'apps=DCERPC' }],
            }),
            cat({ key: 'remote-access-server', label: 'Remote-access server', axis: 'ENTITY' }),
          ]}
        />
      </MemoryRouter>,
    );
    const who = screen.getByTestId('worth-signed-in-user');
    expect(who).toHaveTextContent("Who's signed in");
    expect(who).toHaveTextContent('Answered');
    expect(within(who).getByRole('link', { name: 'LDAP' }).getAttribute('href')).toBe('/analysis/f1/conversations?apps=LDAP');
    expect(screen.getByTestId('worth-lateral-movement')).toHaveTextContent('Open');
    // No traffic for it in this capture: not listed.
    expect(screen.queryByTestId('worth-remote-access-server')).not.toBeInTheDocument();
  });

  it('renders nothing until the investigation is in', () => {
    const { container } = render(
      <MemoryRouter>
        <WorthALookCard fileId="f1" categories={null} />
      </MemoryRouter>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when no category has traffic here', () => {
    const { container } = render(
      <MemoryRouter>
        <WorthALookCard fileId="f1" categories={[cat({ key: 'impact', label: 'Impact' })]} />
      </MemoryRouter>,
    );
    expect(container).toBeEmptyDOMElement();
  });
});

describe('worthALookGroups', () => {
  it('merges categories pointing at the same traffic, keeping the most settled status', () => {
    const groups = worthALookGroups([
      cat({ key: 'c2-server', label: 'C2 server', axis: 'ENTITY', status: 'OPEN', leads: C2_LEADS }),
      cat({ key: 'command-and-control', label: 'Command and Control', status: 'ANSWERED', leads: C2_LEADS }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].label).toBe('C2 server · Command and Control');
    expect(groups[0].status).toBe('ANSWERED');
  });

  it('leaves out capture context', () => {
    expect(worthALookGroups([cat({ key: 'vantage-point', label: 'Vantage point', axis: 'CONTEXT', leads: C2_LEADS })])).toEqual([]);
  });
});
