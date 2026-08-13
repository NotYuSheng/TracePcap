/**
 * The loading indicator used across the app. Small, but it carries an accessibility
 * contradiction worth recording: it sets role="status" and aria-hidden="true" at the same time,
 * so the role it advertises is unreachable to assistive technology — and to any test that looks
 * for it by role.
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Spinner } from '../Spinner'

describe('Spinner', () => {
  it('renders a border spinner by default', () => {
    const { container } = render(<Spinner />)

    expect(container.firstChild).toHaveClass('spinner-border')
  })

  it('renders a grow spinner when asked', () => {
    const { container } = render(<Spinner animation="grow" />)

    expect(container.firstChild).toHaveClass('spinner-grow')
    expect(container.firstChild).not.toHaveClass('spinner-border')
  })

  it('applies the small modifier alongside the animation class', () => {
    const { container } = render(<Spinner animation="grow" size="sm" />)

    // The modifier is derived from the animation, so `spinner-border-sm` on a grow spinner
    // would size nothing.
    expect(container.firstChild).toHaveClass('spinner-grow', 'spinner-grow-sm')
  })

  it('keeps a caller-supplied className rather than replacing it', () => {
    const { container } = render(<Spinner className="text-primary me-2" />)

    // Callers position the spinner with utility classes; dropping them collapses layouts.
    expect(container.firstChild).toHaveClass('spinner-border', 'text-primary', 'me-2')
  })

  it('omits the size modifier entirely at default size', () => {
    const { container } = render(<Spinner />)

    // Not an empty class token: `.filter(Boolean)` exists to stop "spinner-border  " reaching
    // the DOM with a stray gap.
    expect((container.firstChild as HTMLElement).className).toBe('spinner-border')
  })

  describe('accessibility — pinned, not endorsed', () => {
    it('defaults to role="status" but hides itself from assistive technology', () => {
      const { container } = render(<Spinner />)
      const el = container.firstChild as HTMLElement

      // Both are set together. aria-hidden removes the node from the accessibility tree, so
      // the status role announces nothing — a screen reader gets no indication that anything
      // is loading, and getByRole('status') cannot find it either.
      //
      // Pinned rather than fixed: dropping aria-hidden would start announcing every spinner in
      // the app, which is a UX decision rather than a test fix.
      expect(el).toHaveAttribute('role', 'status')
      expect(el).toHaveAttribute('aria-hidden', 'true')
      expect(screen.queryByRole('status')).not.toBeInTheDocument()
    })

    it('lets a caller override the role', () => {
      const { container } = render(<Spinner role="presentation" />)

      expect(container.firstChild).toHaveAttribute('role', 'presentation')
    })
  })
})
