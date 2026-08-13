/**
 * Anything that picks theme-aware colours in JS rather than CSS reads this hook — notably the
 * network graph, which paints nodes and edges on a canvas the stylesheet cannot reach. Resolve
 * it wrong and the graph is drawn in light colours on a dark page.
 */
import { renderHook, act } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useStore } from '@/store'
import { useResolvedDark } from '../useResolvedDark'

/** jsdom has no matchMedia, so stand one up whose value and listeners we control. */
function stubMatchMedia(initialDark: boolean) {
  const listeners = new Set<(e: MediaQueryListEvent) => void>()
  let matches = initialDark

  vi.stubGlobal(
    'matchMedia',
    vi.fn().mockImplementation((query: string) => ({
      matches,
      media: query,
      addEventListener: (_: string, cb: (e: MediaQueryListEvent) => void) => listeners.add(cb),
      removeEventListener: (_: string, cb: (e: MediaQueryListEvent) => void) => listeners.delete(cb),
    }))
  )

  return {
    listenerCount: () => listeners.size,
    /** Simulates the OS theme flipping while the app is open. */
    emit(nowDark: boolean) {
      matches = nowDark
      listeners.forEach(cb => cb({ matches: nowDark } as MediaQueryListEvent))
    },
  }
}

function setThemeMode(mode: 'light' | 'dark' | 'system') {
  act(() => {
    useStore.setState({ themeMode: mode } as Partial<ReturnType<typeof useStore.getState>>)
  })
}

describe('useResolvedDark', () => {
  beforeEach(() => setThemeMode('system'))
  afterEach(() => vi.unstubAllGlobals())

  it('returns false when the user has chosen light, whatever the OS says', () => {
    stubMatchMedia(true)
    setThemeMode('light')

    const { result } = renderHook(() => useResolvedDark())

    // An explicit choice must win: following the OS here would override the user.
    expect(result.current).toBe(false)
  })

  it('returns true when the user has chosen dark, whatever the OS says', () => {
    stubMatchMedia(false)
    setThemeMode('dark')

    const { result } = renderHook(() => useResolvedDark())

    expect(result.current).toBe(true)
  })

  it.each([true, false])('follows the OS in system mode (dark=%s)', osDark => {
    stubMatchMedia(osDark)
    setThemeMode('system')

    const { result } = renderHook(() => useResolvedDark())

    expect(result.current).toBe(osDark)
  })

  it('re-renders when the OS theme flips while in system mode', () => {
    const mq = stubMatchMedia(false)
    setThemeMode('system')

    const { result } = renderHook(() => useResolvedDark())
    expect(result.current).toBe(false)

    act(() => mq.emit(true))

    // The point of subscribing at all: a static read would leave the graph in the old palette
    // until the next navigation.
    expect(result.current).toBe(true)
  })

  it('does not subscribe when the theme is pinned', () => {
    const mq = stubMatchMedia(false)
    setThemeMode('dark')

    renderHook(() => useResolvedDark())

    // No listener is needed when the answer cannot change, and adding one would re-render
    // every consumer on an OS flip that must not affect them.
    expect(mq.listenerCount()).toBe(0)
  })

  it('unsubscribes on unmount', () => {
    const mq = stubMatchMedia(false)
    setThemeMode('system')

    const { unmount } = renderHook(() => useResolvedDark())
    expect(mq.listenerCount()).toBe(1)

    unmount()

    expect(mq.listenerCount()).toBe(0)
  })
})
