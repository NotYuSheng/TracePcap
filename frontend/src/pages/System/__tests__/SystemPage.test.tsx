import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { server } from '@/test/msw';
import { PermissionsPanel } from '../PermissionsPanel';
import { AuditLogPanel } from '../AuditLogPanel';
import { SystemPage } from '../SystemPage';

function me(admin: boolean, level: 'ANALYST' | 'ADMIN' = 'ANALYST') {
  return {
    username: admin ? 'alice' : 'system',
    authEnabled: admin,
    admin,
    canManagePermissions: admin,
    permissions: [
      {
        action: 'NETWORK_SETTINGS',
        label: 'Edit network settings',
        description: 'Per-network settings.',
        level,
        defaultLevel: 'ANALYST',
        allowed: admin || level === 'ANALYST',
        reason: null,
      },
    ],
  };
}

describe('PermissionsPanel (#915)', () => {
  it('shows every item to a non-admin, greyed out, and explains why when clicked', async () => {
    server.use(http.get('*/me', () => HttpResponse.json(me(false))));
    render(<PermissionsPanel />);

    expect(await screen.findByTestId('permissions-locked')).toHaveTextContent(
      'SYSTEM_SETTINGS_EDITABLE'
    );
    expect(screen.getByLabelText('Who may: Edit network settings')).toBeDisabled();

    await userEvent.click(screen.getByRole('button', { name: /Edit network settings/ }));
    expect(screen.getByText(/Why the level is greyed out/)).toBeInTheDocument();
  });

  it('lets an admin change a level, and shows it as changed', async () => {
    let level: 'ANALYST' | 'ADMIN' = 'ANALYST';
    let body: unknown = null;
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true, level))),
      http.put('*/permissions/NETWORK_SETTINGS', async ({ request }) => {
        body = await request.json();
        level = 'ADMIN';
        return HttpResponse.json({});
      })
    );
    render(<PermissionsPanel />);

    const select = await screen.findByLabelText('Who may: Edit network settings');
    expect(select).toBeEnabled();
    await userEvent.selectOptions(select, 'ADMIN');

    await waitFor(() => expect(screen.getByText('changed')).toBeInTheDocument());
    expect(body).toEqual({ level: 'ADMIN' });
  });
});

describe('AuditLogPanel (#915)', () => {
  it('lists entries with before and after, and searches', async () => {
    const searches: (string | null)[] = [];
    server.use(
      http.get('*/audit-log', ({ request }) => {
        const q = new URL(request.url).searchParams.get('search');
        searches.push(q);
        if (q === 'nothing')
          return HttpResponse.json({ data: [], page: 1, pageSize: 25, total: 0, totalPages: 0 });
        return HttpResponse.json({
          data: [
            {
              id: 1,
              at: '2026-11-08T10:00:00',
              actor: 'alice',
              action: 'network.settings.update',
              targetType: 'network',
              targetId: 'n1',
              before: { inactivityThreshold: 1 },
              after: { inactivityThreshold: 7 },
            },
          ],
          page: 1,
          pageSize: 25,
          total: 1,
          totalPages: 1,
        });
      })
    );
    render(<AuditLogPanel />);

    const row = (await screen.findByText('network.settings.update')).closest('tr')!;
    expect(within(row).getByText('alice')).toBeInTheDocument();
    expect(row).toHaveTextContent('inactivityThreshold: 1');
    expect(row).toHaveTextContent('inactivityThreshold: 7');

    await userEvent.type(screen.getByLabelText('Search the audit log'), 'nothing');
    expect(await screen.findByText('No entries match "nothing".')).toBeInTheDocument();
    expect(searches).toContain('nothing');
  });
});

describe('SystemPage (#915)', () => {
  it('is the Settings page: says who you are, opens on Personal, and has every section', async () => {
    server.use(
      http.get('*/me', () => HttpResponse.json(me(false))),
      http.get('*/system/settings', () => HttpResponse.json([]))
    );
    render(
      <MemoryRouter>
        <SystemPage />
      </MemoryRouter>
    );
    expect(await screen.findByText(/login is off/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Settings' })).toBeInTheDocument();
    for (const tab of ['Personal', 'System', 'Detection rules', 'Address defaults', 'Permissions', 'Audit log', 'Users']) {
      expect(screen.getByRole('tab', { name: tab })).toBeInTheDocument();
    }
    expect(screen.getByRole('tab', { name: 'Personal' })).toHaveAttribute('aria-selected', 'true');
  });
});
