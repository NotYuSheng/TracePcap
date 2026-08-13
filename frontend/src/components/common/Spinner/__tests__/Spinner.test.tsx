/**
 * The loading indicator used across the app. Small, but it carries an accessibility
 * contradiction worth recording: it sets role="status" and aria-hidden="true" at the same time,
 * so the role it advertises is unreachable to assistive technology — and to any test that looks
 * for it by role.
 */
import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Spinner } from '../Spinner'

/**
 * The spinner graphic, now nested inside a `role="status"` wrapper so the status is announced
 * while the graphic itself stays `aria-hidden` (#723).
 */
function graphic(container: HTMLElement): HTMLElement {
  return container.querySelector('[aria-hidden="true"]') as HTMLElement
}

describe('Spinner', () => {
  it('renders a border spinner by default', () => {
    const { container } = render(<Spinner />)

    expect(graphic(container)).toHaveClass('spinner-border')
  })

  it('renders a grow spinner when asked', () => {
    const { container } = render(<Spinner animation="grow" />)

    expect(graphic(container)).toHaveClass('spinner-grow')
    expect(graphic(container)).not.toHaveClass('spinner-border')
  })

  it('applies the small modifier alongside the animation class', () => {
    const { container } = render(<Spinner animation="grow" size="sm" />)

    // The modifier is derived from the animation, so `spinner-border-sm` on a grow spinner
    // would size nothing.
    expect(graphic(container)).toHaveClass('spinner-grow', 'spinner-grow-sm')
  })

  it('keeps a caller-supplied className rather than replacing it', () => {
    const { container } = render(<Spinner className="text-primary me-2" />)

    // Callers position the spinner with utility classes; dropping them collapses layouts.
    expect(graphic(container)).toHaveClass('spinner-border', 'text-primary', 'me-2')
  })

  it('omits the size modifier entirely at default size', () => {
    const { container } = render(<Spinner />)

    // Not an empty class token: `.filter(Boolean)` exists to stop "spinner-border  " reaching
    // the DOM with a stray gap.
    expect((graphic(container) as HTMLElement).className).toBe('spinner-border')
  })

  describe('accessibility', () => {
    it('announces a loading status while keeping the graphic decorative', () => {
      render(<Spinner />)

      // Previously role="status" and aria-hidden="true" sat on the same element, so the role was
      // unreachable and a screen reader got no indication anything was loading (#723). The status
      // now wraps a visually-hidden label; the spinner graphic stays hidden because it conveys
      // nothing on its own.
      const status = screen.getByRole('status')
      expect(status).toBeInTheDocument()
      expect(within(status).getByText('Loading…')).toBeInTheDocument()
    })

    it('lets a caller name what is loading', () => {
      render(<Spinner label="Loading conversations" />)

      // With several spinners on a page, "Loading…" three times says less than nothing.
      expect(screen.getByText('Loading conversations')).toBeInTheDocument()
    })

    it('keeps the graphic itself hidden from assistive technology', () => {
      const { container } = render(<Spinner />)

      expect(graphic(container)).toHaveAttribute('aria-hidden', 'true')
    })

    it('lets a caller override the role', () => {
      render(<Spinner role="presentation" />)

      expect(screen.queryByRole('status')).not.toBeInTheDocument()
    })
  })
})
