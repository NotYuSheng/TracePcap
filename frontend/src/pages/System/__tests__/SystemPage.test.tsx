import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { server } from '@/test/msw';
import { PermissionsPanel } from '../PermissionsPanel';
import { AuditLogPanel } from '../AuditLogPanel';
import { SystemPage } from '../SystemPage';

const PERMS = [
  {
    action: 'SEE_CAPTURES',
    label: 'See captures, networks and findings',
    description: 'Every role has it.',
    group: 'LOOK',
    groupLabel: 'Look',
    suggestedRole: 'viewer',
    fixed: true,
    allowed: true,
    reason: null,
  },
  {
    action: 'ASK_AI',
    label: 'Ask the AI',
    description: 'The story, the chat, insights.',
    group: 'INVESTIGATE',
    groupLabel: 'Investigate',
    suggestedRole: 'analyst',
    fixed: false,
    allowed: true,
    reason: null,
  },
];

function me(admin: boolean) {
  return {
    username: admin ? 'alice' : 'system',
    authEnabled: admin,
    admin,
    canManagePermissions: admin,
    roles: admin ? ['admin'] : ['analyst'],
    permissions: PERMS,
  };
}

function roles(viewerPerms: string[] = ['SEE_CAPTURES'], defaultKey = 'analyst') {
  const role = (key: string, label: string, permissions: string[], editable = true) => ({
    key,
    label,
    builtIn: true,
    defaultRole: key === defaultKey,
    editable,
    permissions,
  });
  return [
    role('viewer', 'Viewer', viewerPerms),
    role('analyst', 'Analyst', ['SEE_CAPTURES', 'ASK_AI']),
    role('admin', 'Admin', ['SEE_CAPTURES', 'ASK_AI'], false),
  ];
}

describe('PermissionsPanel: what each role may do', () => {
  it('shows the grid to a non-admin with every box locked, and says why', async () => {
    server.use(
      http.get('*/me', () => HttpResponse.json(me(false))),
      http.get('*/roles', () => HttpResponse.json(roles()))
    );
    render(<PermissionsPanel />);

    expect(await screen.findByTestId('permissions-locked')).toHaveTextContent('SYSTEM_SETTINGS_EDITABLE');
    expect(screen.getByTestId('my-roles')).toHaveTextContent('Analyst');
    expect(screen.getByLabelText('Viewer: Ask the AI')).toBeDisabled();
    expect(screen.getByLabelText('Analyst: Ask the AI')).toBeChecked();
  });

  it('lets an admin give a role a permission, and choose the default role', async () => {
    let viewerPerms = ['SEE_CAPTURES'];
    let defaultKey = 'analyst';
    const bodies: { key: string; body: unknown }[] = [];
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true))),
      http.get('*/roles', () => HttpResponse.json(roles(viewerPerms, defaultKey))),
      http.patch('*/roles/:key', async ({ request, params }) => {
        const body = (await request.json()) as { permissions?: string[]; defaultRole?: boolean };
        bodies.push({ key: String(params.key), body });
        if (body.permissions) viewerPerms = body.permissions;
        if (body.defaultRole) defaultKey = String(params.key);
        return HttpResponse.json({});
      })
    );
    render(<PermissionsPanel />);

    // The admin role always has everything; seeing captures is every role's.
    expect(await screen.findByLabelText('Admin: Ask the AI')).toBeDisabled();
    expect(screen.getByLabelText('Viewer: See captures, networks and findings')).toBeDisabled();

    await userEvent.click(screen.getByLabelText('Viewer: Ask the AI'));
    await waitFor(() => expect(screen.getByLabelText('Viewer: Ask the AI')).toBeChecked());
    expect(bodies[0]).toEqual({ key: 'viewer', body: { permissions: ['SEE_CAPTURES', 'ASK_AI'] } });

    await userEvent.selectOptions(screen.getByLabelText(/carries none of these roles/), 'viewer');
    await waitFor(() => expect(bodies[1]).toEqual({ key: 'viewer', body: { defaultRole: true } }));
  });
});

describe('AuditLogPanel (#915)', () => {
  it('lists entries with what changed, readably, and searches', async () => {
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

    // One line per change: the kind, the verb, what it was about, the fields that changed.
    const summary = await screen.findByRole('button', { name: /Changed n1: Inactivity threshold/ });
    expect(within(summary.closest('tr')!).getByText('alice')).toBeInTheDocument();
    // Selecting it shows the details: the field, before and after.
    await userEvent.click(summary);
    const details = screen.getByRole('complementary', { name: /Changed n1/ });
    expect(within(details).getByText('Inactivity threshold')).toBeInTheDocument();
    expect(within(details).getByText('1')).toHaveClass('audit-old-text');
    expect(within(details).getByText('7')).toHaveClass('audit-new-text');
    await userEvent.click(within(details).getByRole('button', { name: 'Close the details' }));
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();

    await userEvent.type(screen.getByLabelText('Search the audit log'), 'nothing');
    expect(await screen.findByText('No entries match.')).toBeInTheDocument();
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
    // The sections are down the left, like a capture's analysis.
    const rail = screen.getByRole('navigation', { name: 'Settings sections' });
    for (const section of ['Personal', 'System', 'Detection rules', 'Address defaults', 'Permissions', 'Audit log', 'Users']) {
      expect(within(rail).getByRole('button', { name: section })).toBeInTheDocument();
    }
    expect(within(rail).getByRole('button', { name: 'Personal' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByRole('heading', { name: 'Personal' })).toBeInTheDocument();
  });
});
