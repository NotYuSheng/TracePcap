import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { server } from '@/test/msw';
import { PermissionsPanel } from '../PermissionsPanel';
import { AuditLogPanel } from '../AuditLogPanel';
import { UsersPanel } from '../UsersPanel';
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
  it('lists the roles, opens on your own, and locks every box for a non-admin with the reason', async () => {
    server.use(
      http.get('*/me', () => HttpResponse.json(me(false))),
      http.get('*/roles', () => HttpResponse.json(roles()))
    );
    render(<PermissionsPanel />);

    expect(await screen.findByTestId('permissions-locked')).toHaveTextContent(
      'SYSTEM_SETTINGS_EDITABLE'
    );
    expect(screen.getByTestId('my-roles')).toHaveTextContent('Analyst');
    // Opens on the caller's own role.
    expect(
      within(screen.getByRole('listbox', { name: 'Roles' })).getByRole('option', {
        name: /Analyst/,
      })
    ).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByLabelText('Analyst: Ask the AI')).toBeChecked();
    expect(screen.getByLabelText('Analyst: Ask the AI')).toBeDisabled();

    await userEvent.click(
      within(screen.getByRole('listbox', { name: 'Roles' })).getByRole('option', { name: /Viewer/ })
    );
    expect(screen.getByLabelText('Viewer: Ask the AI')).not.toBeChecked();
    expect(screen.getByLabelText('Viewer: Ask the AI')).toBeDisabled();
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

    // Opens on the caller's role. The admin role always has everything.
    expect(await screen.findByLabelText('Admin: Ask the AI')).toBeDisabled();
    expect(screen.getByText(/Given by the Keycloak client role/)).toBeInTheDocument();

    // Seeing captures is every role's.
    await userEvent.click(
      within(screen.getByRole('listbox', { name: 'Roles' })).getByRole('option', { name: /Viewer/ })
    );
    expect(screen.getByLabelText('Viewer: See captures, networks and findings')).toBeDisabled();

    await userEvent.click(screen.getByLabelText('Viewer: Ask the AI'));
    await waitFor(() => expect(screen.getByLabelText('Viewer: Ask the AI')).toBeChecked());
    expect(bodies[0]).toEqual({ key: 'viewer', body: { permissions: ['SEE_CAPTURES', 'ASK_AI'] } });

    await userEvent.selectOptions(screen.getByLabelText(/carries none of these roles/), 'viewer');
    await waitFor(() => expect(bodies[1]).toEqual({ key: 'viewer', body: { defaultRole: true } }));
  });
});

describe('PermissionsPanel: custom roles', () => {
  it('creates a role named after its Keycloak client role, starting from another', async () => {
    let list = roles();
    let created: unknown = null;
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true))),
      http.get('*/roles', () => HttpResponse.json(list)),
      http.post('*/roles', async ({ request }) => {
        created = await request.json();
        list = [
          ...list,
          {
            key: 'incident-responder',
            label: 'Incident responder',
            builtIn: false,
            defaultRole: false,
            editable: true,
            permissions: ['SEE_CAPTURES', 'ASK_AI'],
          },
        ];
        return HttpResponse.json(list[list.length - 1], { status: 201 });
      })
    );
    render(<PermissionsPanel />);

    await userEvent.click(await screen.findByRole('button', { name: /New role/ }));
    await userEvent.type(screen.getByLabelText('Name'), 'Incident responder');
    // The Keycloak name follows the name until it's edited.
    expect(screen.getByLabelText('Keycloak client role')).toHaveValue('incident-responder');
    await userEvent.selectOptions(screen.getByLabelText('Start from'), 'analyst');
    await userEvent.click(screen.getByRole('button', { name: 'Create role' }));

    await waitFor(() =>
      expect(created).toEqual({
        key: 'incident-responder',
        label: 'Incident responder',
        copyFrom: 'analyst',
      })
    );
    // The new role opens, with what it needs from Keycloak.
    expect(await screen.findByRole('heading', { name: 'Incident responder' })).toBeInTheDocument();
    expect(screen.getByText(/Create role/, { selector: 'strong' })).toBeInTheDocument();
    expect(screen.getByLabelText('Incident responder: Ask the AI')).toBeChecked();
  });

  it("won't take a Keycloak name another role has", async () => {
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true))),
      http.get('*/roles', () => HttpResponse.json(roles()))
    );
    render(<PermissionsPanel />);
    await userEvent.click(await screen.findByRole('button', { name: /New role/ }));
    await userEvent.type(screen.getByLabelText('Name'), 'Viewer');
    expect(screen.getByText('There is already a role with this name.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create role' })).toBeDisabled();
  });

  it('deletes a custom role after asking; built-in roles have no delete', async () => {
    let list = [
      ...roles(),
      {
        key: 'responder',
        label: 'Responder',
        builtIn: false,
        defaultRole: false,
        editable: true,
        permissions: ['SEE_CAPTURES'],
      },
    ];
    let deleted: string | null = null;
    server.use(
      http.get('*/me', () => HttpResponse.json({ ...me(true), roles: ['responder'] })),
      http.get('*/roles', () => HttpResponse.json(list)),
      http.delete('*/roles/:key', ({ params }) => {
        deleted = String(params.key);
        list = list.filter(r => r.key !== deleted);
        return new HttpResponse(null, { status: 204 });
      })
    );
    render(<PermissionsPanel />);

    await userEvent.click(await screen.findByRole('button', { name: /Delete role/ }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: /Delete role/ }));
    await waitFor(() => expect(deleted).toBe('responder'));
    await waitFor(() =>
      expect(screen.queryByRole('option', { name: /Responder/ })).not.toBeInTheDocument()
    );
    expect(screen.queryByRole('button', { name: /Delete role/ })).not.toBeInTheDocument();
  });
});

describe('UsersPanel: who has signed in', () => {
  it('lists people with their roles, flags roles TracePcap has no role for, and searches', async () => {
    const searches: (string | null)[] = [];
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true))),
      http.get('*/roles', () => HttpResponse.json(roles())),
      http.get('*/users', ({ request }) => {
        searches.push(new URL(request.url).searchParams.get('search'));
        return HttpResponse.json({
          data: [
            {
              username: 'ana',
              displayName: 'Ana Analyst',
              roles: ['analyst'],
              defaultRole: false,
              unknownRoles: ['typo-role'],
              permissionCount: 19,
              firstSeen: '2026-11-01T09:00:00',
              lastSeen: '2026-11-20T09:00:00',
            },
            {
              username: 'bob',
              displayName: null,
              roles: ['analyst'],
              defaultRole: true,
              unknownRoles: [],
              permissionCount: 19,
              firstSeen: '2026-11-01T09:00:00',
              lastSeen: '2026-11-19T09:00:00',
            },
          ],
          page: 1,
          pageSize: 25,
          total: 2,
          totalPages: 1,
        });
      })
    );
    render(<UsersPanel />);

    expect(await screen.findByText('Ana Analyst')).toBeInTheDocument();
    expect(screen.getByTestId('unknown-roles')).toHaveTextContent('typo-role');
    expect(screen.getByText(/the default: no role in Keycloak/)).toBeInTheDocument();
    expect(screen.getAllByText(/19 of 2 permissions/)).toHaveLength(2);

    await userEvent.type(screen.getByLabelText('Search users'), 'ana');
    await waitFor(() => expect(searches).toContain('ana'));
  });

  it('says why when the caller may not see who has signed in', async () => {
    server.use(
      http.get('*/me', () => HttpResponse.json(me(false))),
      http.get('*/roles', () => HttpResponse.json(roles())),
      http.get('*/users', () =>
        HttpResponse.json(
          {
            message:
              "Read the audit log and who has signed in: your role (Viewer) doesn't include this.",
          },
          { status: 403 }
        )
      )
    );
    render(<UsersPanel />);
    expect(await screen.findByText(/your role \(Viewer\)/)).toBeInTheDocument();
  });
});

describe('PermissionsPanel: whether a role has been seen', () => {
  it('says when a sign-in last carried the role, or that none has', async () => {
    const list = roles().map(r =>
      r.key === 'admin' ? { ...r, lastSignInAt: '2026-11-20T09:00:00' } : r
    );
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true))),
      http.get('*/roles', () => HttpResponse.json(list))
    );
    render(<PermissionsPanel />);
    expect(await screen.findByTestId('role-signin')).toHaveTextContent('Last carried by a sign-in');
    await userEvent.click(
      within(screen.getByRole('listbox', { name: 'Roles' })).getByRole('option', { name: /Viewer/ })
    );
    expect(screen.getByTestId('role-signin')).toHaveTextContent(
      'No sign-in has carried this role yet.'
    );
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
    for (const section of [
      'Personal',
      'System',
      'Detection rules',
      'Address defaults',
      'Roles',
      'Audit log',
      'Users',
    ]) {
      expect(within(rail).getByRole('button', { name: section })).toBeInTheDocument();
    }
    expect(within(rail).getByRole('button', { name: 'Personal' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(screen.getByRole('heading', { name: 'Personal' })).toBeInTheDocument();
  });
});
