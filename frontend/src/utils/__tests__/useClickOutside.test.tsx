/**
 * Every popup, filter panel and menu in the app closes through this hook. The interesting part
 * is not that it fires — it is that it stops firing on unmount. A leaked document listener
 * keeps a closed panel's `onClose` alive, so a later click elsewhere calls into a component
 * that is gone.
 */
import { renderHook } from '@testing-library/react'
import { useRef } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { useClickOutside } from '../useClickOutside'

/** Renders the hook against a real element attached to the document. */
function renderWithElement(onClose: () => void) {
  const el = document.createElement('div')
  const child = document.createElement('button')
  el.appendChild(child)
  document.body.appendChild(el)

  const view = renderHook(() => {
    const ref = useRef<HTMLElement | null>(el)
    useClickOutside(ref, onClose)
  })

  return { el, child, ...view }
}

function mousedownOn(target: Node) {
  target.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
}

describe('useClickOutside', () => {
  it('closes when the click lands outside the element', () => {
    const onClose = vi.fn()
    renderWithElement(onClose)

    mousedownOn(document.body)

    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('does not close when the click lands inside', () => {
    const onClose = vi.fn()
    const { el } = renderWithElement(onClose)

    mousedownOn(el)

    expect(onClose).not.toHaveBeenCalled()
  })

  it('does not close when the click lands on a descendant', () => {
    const onClose = vi.fn()
    const { child } = renderWithElement(onClose)

    // `contains` covers the subtree, which is what makes a panel with buttons inside usable —
    // a strict identity check would close the panel on its own controls.
    mousedownOn(child)

    expect(onClose).not.toHaveBeenCalled()
  })

  it('stops listening once unmounted', () => {
    const onClose = vi.fn()
    const { unmount } = renderWithElement(onClose)

    unmount()
    mousedownOn(document.body)

    // The cleanup is the whole reason this is a hook rather than an inline effect. Without it
    // every opened panel leaves a listener behind for the life of the page.
    expect(onClose).not.toHaveBeenCalled()
  })

  it('uses mousedown, not click', () => {
    const onClose = vi.fn()
    renderWithElement(onClose)

    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }))

    // mousedown fires before a button's own click handler, so a panel closes before the click
    // reaches whatever is underneath. Switching to `click` reverses that ordering.
    expect(onClose).not.toHaveBeenCalled()
  })
})
