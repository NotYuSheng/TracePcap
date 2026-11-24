import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { ConfirmedFindingsPanel } from '../ConfirmedFindingsPanel';
import type { Answer } from '@/types';

const c2 = (basis: string[]): Answer =>
  ({
    question: 'c2',
    headline: '72.5.43.29 (RO) — C2 for WarmCookie',
    grade: 'INFERRED',
    subjects: [],
    basis,
    attributes: {},
  }) as unknown as Answer;

describe('Investigation Summary evidence', () => {
  it('shows the first few lines and folds the rest behind "and N more"', async () => {
    const lines = Array.from({ length: 7 }, (_, i) => `ET MALWARE rule ${i}`);
    render(<ConfirmedFindingsPanel answers={[c2(lines)]} />);
    expect(screen.getByText('ET MALWARE rule 3')).toBeInTheDocument();
    expect(screen.queryByText('ET MALWARE rule 4')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'and 3 more' }));
    expect(screen.getByText('ET MALWARE rule 6')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Show fewer' })).toHaveAttribute('aria-expanded', 'true');
  });

  it('has no toggle when the evidence is short', () => {
    render(<ConfirmedFindingsPanel answers={[c2(['one', 'two'])]} />);
    expect(screen.queryByRole('button', { name: /more/ })).not.toBeInTheDocument();
  });
});

const answer = (question: string, attributes: Record<string, unknown>): Answer =>
  ({ question, headline: 'h', grade: 'INFERRED', subjects: [], basis: [], attributes }) as unknown as Answer;

describe('How a C2 was concluded (#1264)', () => {
  it('marks a reputation-corroborated C2 as suspected, with its reason behind the info button', async () => {
    render(
      <ConfirmedFindingsPanel
        answers={[answer('c2', { address: '45.1.2.3', conclusion: 'suspected-c2', conclusionReason: 'ET DROP listed; 4 rounds' })]}
      />,
    );
    expect(screen.getByText('Suspected')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'About Suspected C2' }));
    expect(await screen.findByText('ET DROP listed; 4 rounds')).toBeInTheDocument();
  });

  it('marks an install-chain C2', () => {
    render(<ConfirmedFindingsPanel answers={[answer('c2', { address: '45.1.2.3', conclusion: 'install-chain' })]} />);
    expect(screen.getByText('Install chain')).toBeInTheDocument();
  });

  it('adds no chip when a malware rule named the server', () => {
    render(<ConfirmedFindingsPanel answers={[answer('c2', { address: '45.1.2.3', conclusion: 'rule' })]} />);
    expect(screen.queryByTestId('conclusion-chip')).not.toBeInTheDocument();
  });
});

describe('Answer links to conversations (#1264)', () => {
  it('links a C2 and a remote-access answer to the conversations with their server', () => {
    render(
      <MemoryRouter>
        <ConfirmedFindingsPanel
          fileId="f1"
          answers={[answer('c2', { address: '45.1.2.3' }), answer('remote-access', { host: '10.0.0.5', external: '194.180.191.64' })]}
        />
      </MemoryRouter>,
    );
    const links = screen.getAllByRole('link', { name: /Conversations/ });
    expect(links.map((l) => l.getAttribute('href'))).toEqual([
      '/analysis/f1/conversations?ip=45.1.2.3',
      '/analysis/f1/conversations?ip=194.180.191.64',
    ]);
  });

  it('labels a lateral-movement answer and links it to the host acted on (#1266)', () => {
    render(
      <MemoryRouter>
        <ConfirmedFindingsPanel
          fileId="f1"
          answers={[answer('lateral-movement', { client: '172.16.66.1', server: '172.16.66.36' })]}
        />
      </MemoryRouter>,
    );
    expect(screen.getByText('Lateral movement')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Conversations/ }).getAttribute('href')).toBe(
      '/analysis/f1/conversations?ip=172.16.66.36',
    );
  });

  it('labels a Kerberos-attack answer and links it to the host that made the requests (#1267)', () => {
    render(
      <MemoryRouter>
        <ConfirmedFindingsPanel
          fileId="f1"
          answers={[answer('kerberos-attack', { client: '172.16.66.1', kdc: '172.16.66.36' })]}
        />
      </MemoryRouter>,
    );
    expect(screen.getByText('Kerberos attack')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Conversations/ }).getAttribute('href')).toBe(
      '/analysis/f1/conversations?ip=172.16.66.1',
    );
  });

  it('has no link for an answer about a host only, or without a capture', () => {
    render(<ConfirmedFindingsPanel answers={[answer('c2', { address: '45.1.2.3' })]} />);
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
});

describe('How we got here (#1293)', () => {
  const c2: Answer = {
    ...answer('c2', { address: '141.98.10.79' }),
    headline: '141.98.10.79 (LT · UAB Host Baltic) — C2 for STRRAT',
    derivation: [
      {
        found: 'Suricata rule "ET MALWARE STRRAT CnC Checkin" fired on 172.16.1.66 → 141.98.10.79.',
        rule: "A Suricata malware rule that names a server makes it that malware family's command-and-control server.",
        grade: 'INFERRED',
        conversations: ['conv-1'],
      },
      { found: 'First contacted at 2024-07-30 02:54:23 UTC.', rule: null, grade: 'MEASURED', conversations: [] },
    ],
  };

  it('walks the steps: what was found, the rule, and a link to the conversation', async () => {
    render(
      <MemoryRouter>
        <ConfirmedFindingsPanel fileId="f1" answers={[c2]} />
      </MemoryRouter>,
    );
    await userEvent.click(screen.getByRole('button', { name: /How we got here/ }));

    const steps = await screen.findAllByTestId('derivation-step');
    expect(steps).toHaveLength(2);
    expect(steps[0]).toHaveTextContent('ET MALWARE STRRAT CnC Checkin');
    expect(steps[0]).toHaveTextContent("Rule: A Suricata malware rule that names a server");
    // A context step has no rule.
    expect(steps[1]).not.toHaveTextContent('Rule:');
    expect(screen.getByRole('link', { name: /Conversation 1/ }).getAttribute('href')).toBe(
      '/analysis/f1/conversations?highlight=conv-1',
    );
  });

  it('offers no walkthrough for an answer without steps', () => {
    render(
      <MemoryRouter>
        <ConfirmedFindingsPanel fileId="f1" answers={[answer('c2', { address: '45.1.2.3' })]} />
      </MemoryRouter>,
    );
    expect(screen.queryByRole('button', { name: /How we got here/ })).not.toBeInTheDocument();
  });
});
