import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { server } from '@/test/msw';
import { PermissionLock } from '../PermissionLock';
import { StartPanel } from '@/pages/Home/StartPanel';
import { NotesTab } from '@components/common/EntityDetailModal/sections/NotesTab';

const REASON = "your role (Viewer) doesn't include this. Ask an admin to add it to your role.";

function meWith(allowed: Record<string, boolean>) {
  return {
    username: 'vic',
    authEnabled: true,
    admin: false,
    canManagePermissions: false,
    roles: ['viewer'],
    permissions: Object.entries(allowed).map(([action, ok]) => ({
      action,
      label: action === 'UPLOAD_CAPTURES' ? 'Upload and analyse captures' : action,
      description: '',
      group: 'INVESTIGATE',
      groupLabel: 'Investigate',
      suggestedRole: 'analyst',
      fixed: false,
      allowed: ok,
      reason: ok ? null : REASON,
    })),
  };
}

describe('PermissionLock (roles step 4)', () => {
  it('shows nothing when the caller may', async () => {
    server.use(http.get('*/me', () => HttpResponse.json(meWith({ ASK_AI: true }))));
    render(<PermissionLock action="ASK_AI" />);
    await new Promise(r => setTimeout(r, 50));
    expect(screen.queryByTestId('permission-lock-ASK_AI')).not.toBeInTheDocument();
  });

  it('opens the permission and the reason when the caller may not', async () => {
    server.use(http.get('*/me', () => HttpResponse.json(meWith({ UPLOAD_CAPTURES: false }))));
    render(<PermissionLock action="UPLOAD_CAPTURES" />);
    await userEvent.click(await screen.findByTestId('permission-lock-UPLOAD_CAPTURES'));
    expect(await screen.findByText('Upload and analyse captures')).toBeInTheDocument();
    expect(screen.getByText(REASON.charAt(0).toUpperCase() + REASON.slice(1))).toBeInTheDocument();
  });

  it('greys out the upload panel for someone who may not upload, and says why', async () => {
    server.use(http.get('*/me', () => HttpResponse.json(meWith({ UPLOAD_CAPTURES: false }))));
    render(
      <MemoryRouter>
        <StartPanel
          onFiles={() => undefined}
          options={{ enableNdpi: true, enableSuricata: true, enableFileExtraction: true, generateStory: false } as never}
          onOptionsChange={() => undefined}
          maxBytes={1024 * 1024}
          maxPackets={0}
          retentionHours={0}
          acceptedTypes={['.pcap']}
          uploads={[]}
          onClearUploads={() => undefined}
        />
      </MemoryRouter>
    );
    expect(await screen.findByTestId('upload-locked')).toHaveTextContent('Viewer');
    expect(screen.getByRole('button', { name: /roles don't allow uploading/ })).toBeDisabled();
  });

  it('disables saving a note without Label hosts and add notes', async () => {
    server.use(http.get('*/me', () => HttpResponse.json(meWith({ LABEL_HOSTS: false }))));
    render(
      <NotesTab
        entityLabel="host"
        displayName="10.0.0.5"
        noteText="x"
        setNoteText={() => undefined}
        savedNote={null}
        noteSaving={false}
        noteDeleting={false}
        noteChanged
        onSave={() => undefined}
        onDelete={() => undefined}
      />
    );
    expect(await screen.findByTestId('permission-lock-LABEL_HOSTS')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Save Note/ })).toBeDisabled();
  });
});
