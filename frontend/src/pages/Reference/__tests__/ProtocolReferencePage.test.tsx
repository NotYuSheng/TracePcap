import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { server } from '@/test/msw';
import { ProtocolReferencePage } from '../ProtocolReferencePage';
import { findNdpiProtocol, loadNdpiProtocols, protocolKey } from '@/features/ndpiReference/ndpiReference';

// Shaped like a real install's usage: the analysis's own spellings, not the reference's.
const USAGE = [
  { appName: 'TLS', captures: 14, conversations: 992 },
  { appName: 'SMTP', captures: 6, conversations: 10 },
  { appName: 'Telnet', captures: 5, conversations: 6 },
];

function renderAt(url: string) {
  server.use(
    http.get('*/protocol-usage', () => HttpResponse.json(USAGE)),
    http.get('*/protocol-usage/:app/captures', ({ params }) =>
      HttpResponse.json(
        params.app === 'SMTP'
          ? [{ fileId: '00000000-0000-0000-0000-000000000001', fileName: 'week4_ftp_exfil_gateway_change.pcap', conversations: 3 }]
          : []
      )
    )
  );
  return render(
    <MemoryRouter initialEntries={[url]}>
      <Routes>
        <Route path="/reference/protocols" element={<ProtocolReferencePage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('Protocol reference', () => {
  it('has all 473 protocols, and matches the analysis spellings to them', async () => {
    const all = await loadNdpiProtocols();
    expect(all).toHaveLength(473);
    expect(findNdpiProtocol(all, 'tls')?.name).toBe('TLS');
    expect(findNdpiProtocol(all, 'TLS.Discord')?.name).toBe('DISCORD');
    // The analysis and the reference spell these differently.
    expect(findNdpiProtocol(all, 'SMTP')?.name).toBe('MAIL_SMTP');
    expect(findNdpiProtocol(all, 'Outlook')?.name).toBe('MS_OUTLOOK');
    expect(findNdpiProtocol(all, 'AppleiCloud')?.name).toBe('APPLE_ICLOUD');
    expect(findNdpiProtocol(all, 'Teams')?.name).toBe('MSTEAMS');
    expect(protocolKey('MAIL_SMTP')).toBe(protocolKey('SMTP'));
  });

  it('browses a category as cards, marking the ones seen in your captures', async () => {
    renderAt('/reference/protocols');
    await screen.findByRole('button', { name: /File Transfer Protocol – Control/ });

    await userEvent.click(screen.getByRole('button', { name: /^Remote access/ }));
    expect(screen.getByRole('heading', { name: 'Remote access' })).toBeInTheDocument();
    const telnet = screen.getByRole('button', { name: /Telnet Remote Terminal/ });
    expect(within(telnet).getByTestId('protocol-seen')).toHaveTextContent('Seen in 5 captures');
    expect(screen.getByRole('button', { name: /Secure Shell/ })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Transport Layer Security/ })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /^Seen in your captures/ }));
    expect(screen.getAllByTestId('protocol-seen')).toHaveLength(3);
  });

  it('searches every protocol, and the drawer shows where you saw it', async () => {
    renderAt('/reference/protocols');
    await screen.findByRole('button', { name: /File Transfer Protocol – Control/ });

    await userEvent.type(screen.getByLabelText('Search protocols'), 'smtp');
    await userEvent.click(screen.getByRole('button', { name: /^Simple Mail Transfer Protocol/ }));

    const detail = await screen.findByTestId('protocol-detail');
    expect(within(detail).getByRole('link', { name: 'RFC 5321' })).toHaveAttribute('href', expect.stringContaining('rfc5321'));
    const where = await within(detail).findByTestId('protocol-captures');
    expect(within(where).getByRole('link', { name: /week4_ftp_exfil_gateway_change\.pcap/ })).toHaveAttribute(
      'href',
      '/analysis/00000000-0000-0000-0000-000000000001/conversations?apps=SMTP'
    );
  });

  it('opens straight to a protocol from a link', async () => {
    renderAt('/reference/protocols?protocol=TLS');
    expect(await screen.findByRole('heading', { name: 'Transport Layer Security' })).toBeInTheDocument();
    expect(screen.getByTestId('protocol-detail')).toHaveTextContent('TLS · nDPI ID 91');
  });
});
