import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { IconTooltip } from '../IconTooltip';

describe('IconTooltip', () => {
  it('shows its text on hover and leaves the button working', async () => {
    const onClick = vi.fn();
    render(
      <IconTooltip text="Mark as reviewed">
        <button type="button" aria-label="Mark as reviewed" onClick={onClick}>
          ✓
        </button>
      </IconTooltip>
    );
    const button = screen.getByRole('button', { name: 'Mark as reviewed' });
    await userEvent.hover(button);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Mark as reviewed');
    await userEvent.click(button);
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});
