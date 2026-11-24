import { render, screen } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { server } from '@/test/msw';
import { CaptureQualityNote } from '../CaptureQualityNote';

const base = { tcpConversations: 100, tcpWithoutHandshake: 0 };

describe('CaptureQualityNote (#1268)', () => {
  it('lists the notes, warnings marked', async () => {
    server.use(
      http.get('*/files/f1/capture-quality', () =>
        HttpResponse.json({
          ...base,
          verdict: 'notes',
          notes: [
            { kind: 'gaps', level: 'warning', text: '2 gaps in TCP streams: packets are missing.' },
            { kind: 'depth', level: 'info', text: '5 TCP sessions ran past the first 1 MiB.' },
          ],
        })
      )
    );
    render(<CaptureQualityNote fileId="f1" />);
    expect(await screen.findByTestId('capture-quality-gaps')).toHaveTextContent('2 gaps');
    expect(screen.getByTestId('capture-quality-gaps')).toHaveClass('text-warning-emphasis');
    expect(screen.getByTestId('capture-quality-depth')).toHaveClass('text-muted');
  });

  it('says nothing about a complete capture', async () => {
    let asked = false;
    server.use(
      http.get('*/files/f2/capture-quality', () => {
        asked = true;
        return HttpResponse.json({ ...base, verdict: 'complete', notes: [] });
      })
    );
    const { container } = render(<CaptureQualityNote fileId="f2" />);
    await new Promise((r) => setTimeout(r, 50));
    expect(asked).toBe(true);
    expect(container).toBeEmptyDOMElement();
  });
});
