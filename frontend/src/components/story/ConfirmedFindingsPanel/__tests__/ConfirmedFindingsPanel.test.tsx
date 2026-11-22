import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
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
