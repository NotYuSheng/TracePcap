/**
 * The payload viewer. Analysts read raw bytes here to confirm what a conversation actually
 * carried, so the rendering has to be faithful in both columns: the hex must be the bytes, and
 * the ASCII column must not let a control byte pretend to be text.
 */
import { render, screen } from '@testing-library/react'
import { beforeAll, describe, expect, it, vi } from 'vitest'

import { HexViewer } from '../HexViewer'

beforeAll(() => {
  // jsdom has no ResizeObserver. The component observes its container to pick a byte width;
  // with a no-op observer it keeps the initial 16 bytes per row, which is what these assert.
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  )
})

/** The rendered <pre>, which holds every row. */
function dump(): string {
  return document.querySelector('pre')?.textContent ?? ''
}

describe('HexViewer', () => {
  it('says so when there is no payload', () => {
    render(<HexViewer hex="" truncated={false} />)

    // An empty hex pane looks like a rendering bug; saying "no payload" distinguishes an
    // empty conversation from a broken viewer.
    expect(screen.getByText(/No payload data available/)).toBeInTheDocument()
    expect(document.querySelector('pre')).toBeNull()
  })

  it('splits the hex string into byte pairs', () => {
    render(<HexViewer hex="48656c6c6f" truncated={false} />)

    expect(dump()).toContain('48 65 6c 6c 6f')
  })

  it('renders printable bytes in the ASCII column', () => {
    render(<HexViewer hex="48656c6c6f" truncated={false} />)

    expect(dump()).toContain('Hello')
  })

  it.each([
    ['00', 'null'],
    ['0a', 'newline'],
    ['1f', 'unit separator'],
    ['7f', 'delete'],
    ['ff', 'high byte'],
  ])('substitutes a dot for %s (%s) in the ASCII column', hex => {
    render(<HexViewer hex={hex} truncated={false} />)

    // Standard hexdump convention, and load-bearing: emitting a raw control byte would let
    // payload content move the cursor or inject escape sequences into the rendered view.
    const ascii = dump().trimEnd().slice(-1)
    expect(ascii).toBe('.')
  })

  it('keeps the printable boundary bytes as characters', () => {
    render(<HexViewer hex="207e" truncated={false} />)

    // 0x20 is space and 0x7e is '~' — both printable. An off-by-one on either bound would
    // blank a legitimate character or print a control one.
    expect(dump()).toContain(' ~')
  })

  it('numbers each row by its byte offset in hex', () => {
    // 20 bytes: two rows at the default 16 wide, so offsets 0000 and 0010.
    render(<HexViewer hex={'ab'.repeat(20)} truncated={false} />)

    expect(dump()).toContain('0000')
    expect(dump()).toContain('0010')
  })

  it('pads the offset to four hex digits', () => {
    render(<HexViewer hex="ab" truncated={false} />)

    // "0" instead of "0000" would misalign every row against the ones below it.
    expect(dump()).toMatch(/^0000/)
  })

  it('splits each row into two groups for readability', () => {
    render(<HexViewer hex={'ab'.repeat(16)} truncated={false} />)

    // A double space at the midpoint is what lets the eye count bytes without a ruler.
    expect(dump()).toContain('ab ab ab ab ab ab ab ab  ab')
  })

  it('announces truncation so a short dump is not mistaken for a short payload', () => {
    render(<HexViewer hex="4142" truncated />)

    expect(screen.getByText(/truncated to first 1024 bytes/)).toBeInTheDocument()
  })

  it('says nothing about truncation when the payload is complete', () => {
    render(<HexViewer hex="4142" truncated={false} />)

    expect(screen.queryByText(/truncated/)).not.toBeInTheDocument()
  })
})
