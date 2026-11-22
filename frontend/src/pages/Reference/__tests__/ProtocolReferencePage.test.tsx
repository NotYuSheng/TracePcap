import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { ProtocolReferencePage } from '../ProtocolReferencePage';
import { findNdpiProtocol, loadNdpiProtocols } from '@/features/ndpiReference/ndpiReference';

function renderAt(url: string) {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <Routes>
        <Route path="/reference/protocols" element={<ProtocolReferencePage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('Protocol reference', () => {
  it('has all 473 protocols, and finds nDPI layered names by their parts', async () => {
    const all = await loadNdpiProtocols();
    expect(all).toHaveLength(473);
    expect(findNdpiProtocol(all, 'tls')?.name).toBe('TLS');
    expect(findNdpiProtocol(all, 'TLS.Discord')?.name).toBe('DISCORD');
  });

  it('searches, filters by category, and opens an entry in the drawer', async () => {
    renderAt('/reference/protocols');
    await screen.findByRole('button', { name: /FTP_CONTROL/ });

    await userEvent.type(screen.getByLabelText('Search protocols'), 'smtp');
    const table = screen.getByRole('table');
    expect(within(table).getByRole('button', { name: /^MAIL_SMTP\s*Simple/ })).toBeInTheDocument();
    expect(within(table).queryByRole('button', { name: /FTP_CONTROL/ })).not.toBeInTheDocument();

    await userEvent.click(within(table).getByRole('button', { name: /^MAIL_SMTP\s*Simple/ }));
    const detail = await screen.findByTestId('protocol-detail');
    expect(detail).toHaveTextContent('Simple Mail Transfer Protocol');
    expect(within(detail).getByRole('link', { name: 'RFC 5321' })).toHaveAttribute('href', expect.stringContaining('rfc5321'));
  });

  it('opens straight to a protocol from a link', async () => {
    renderAt('/reference/protocols?protocol=TLS');
    expect(await screen.findByTestId('protocol-detail')).toHaveTextContent(/Transport Layer Security/i);
  });
});
