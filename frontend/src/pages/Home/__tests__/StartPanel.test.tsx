import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { StartPanel } from '../StartPanel';

const options = { enableNdpi: true, enableSuricata: false, enableFileExtraction: true, generateStory: false, expires: true };

function renderPanel(extra: Partial<Parameters<typeof StartPanel>[0]> = {}) {
  const onOptionsChange = vi.fn();
  render(
    <MemoryRouter>
      <StartPanel
        onFiles={vi.fn()}
        options={options}
        onOptionsChange={onOptionsChange}
        maxBytes={500 * 1024 * 1024}
        maxPackets={0}
        retentionHours={12}
        acceptedTypes={['.pcap']}
        uploads={[]}
        onClearUploads={vi.fn()}
        {...extra}
      />
    </MemoryRouter>
  );
  return { onOptionsChange };
}

describe('StartPanel upload options', () => {
  it('offers to write the story only when an LLM is set up', async () => {
    renderPanel();
    expect(screen.queryByLabelText(/Write the story when analysis finishes/)).not.toBeInTheDocument();
  });

  it('turns the story option on', async () => {
    const { onOptionsChange } = renderPanel({ llmConfigured: true });
    await userEvent.click(screen.getByLabelText(/Write the story when analysis finishes/));
    expect(onOptionsChange).toHaveBeenCalledWith({ ...options, generateStory: true });
  });

  it('expires by default, and can be told to keep the capture', async () => {
    const { onOptionsChange } = renderPanel();
    const box = screen.getByLabelText(/Delete after 12 hours/);
    expect(box).toBeChecked();
    await userEvent.click(box);
    expect(onOptionsChange).toHaveBeenCalledWith({ ...options, expires: false });
  });

  it('has nothing to untick when captures are never deleted', () => {
    renderPanel({ retentionHours: 0 });
    expect(screen.queryByLabelText(/Delete after/)).not.toBeInTheDocument();
    expect(screen.getByText('Captures are kept until you delete them.')).toBeInTheDocument();
  });
});
