import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { WorthALookCard } from '../WorthALookCard';

describe('WorthALookCard (#1292)', () => {
  it('groups the capture’s protocols by question, says which are answered, and links each', () => {
    render(
      <MemoryRouter>
        <WorthALookCard
          fileId="f1"
          l7Protocols={['KERBEROS', 'SMB2', 'DCERPC', 'DNS']}
          apps={['Kerberos', 'LDAP', 'SMBv23', 'DCERPC', 'DNS']}
          answeredQuestions={['signed-in-user']}
        />
      </MemoryRouter>,
    );
    const who = screen.getByTestId('worth-who');
    expect(who).toHaveTextContent('Who is signed in');
    expect(who).toHaveTextContent('Answered');
    expect(within(who).getByRole('link', { name: 'LDAP' }).getAttribute('href')).toBe('/analysis/f1/conversations?apps=LDAP');
    const lateral = screen.getByTestId('worth-lateral');
    expect(lateral).toHaveTextContent('Open');
    expect(within(lateral).getByRole('link', { name: 'DCE-RPC' })).toBeInTheDocument();
    expect(screen.queryByTestId('worth-remote')).not.toBeInTheDocument();
  });

  it('renders nothing when none of the protocols speak to a question', () => {
    const { container } = render(
      <MemoryRouter>
        <WorthALookCard fileId="f1" l7Protocols={['NTP']} apps={[]} answeredQuestions={[]} />
      </MemoryRouter>,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
