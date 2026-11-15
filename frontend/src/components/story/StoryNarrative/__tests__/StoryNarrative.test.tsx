import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { StoryNarrative } from '../StoryNarrative';

describe('StoryNarrative', () => {
  it('puts the summary first, then events in time order, then the other sections', () => {
    const { container } = render(
      <StoryNarrative
        sections={[
          { title: 'Conclusion', content: 'Look at the DNS server next.', type: 'conclusion', relatedData: {} },
          { title: 'Summary', content: 'A quiet office capture.', type: 'summary', relatedData: {} },
        ]}
        events={[
          { timestamp: Date.UTC(2009, 4, 4, 15, 41, 2), title: 'Second', description: '', type: 'suspicious', relatedData: {} },
          { timestamp: Date.UTC(2009, 4, 4, 15, 34, 16), title: 'First', description: 'It began.', type: 'normal', relatedData: {} },
        ]}
      />
    );
    const text = container.textContent ?? '';
    expect(text.indexOf('A quiet office capture.')).toBeLessThan(text.indexOf('First'));
    expect(text.indexOf('First')).toBeLessThan(text.indexOf('Second'));
    expect(text.indexOf('Second')).toBeLessThan(text.indexOf('Look at the DNS server next.'));
    expect(screen.getByText('Suspicious')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Conclusion' })).toBeInTheDocument();
  });
});
