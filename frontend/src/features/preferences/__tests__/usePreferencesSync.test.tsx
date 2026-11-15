/**
 * Personal preferences sync (#915 phase 2): server values win on load, an empty server receives
 * this browser's existing setup once, and later changes are saved.
 */
import { renderHook, waitFor, act } from '@testing-library/react'
import { HttpResponse, http } from 'msw'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { useStore } from '@/store'
import { COLUMN_STORAGE_KEY } from '@/features/conversation/constants'
import { usePreferencesSync } from '../usePreferencesSync'

let puts: Record<string, unknown>[] = []

function serve(initial: Record<string, unknown>) {
  puts = []
  server.use(
    http.get('*/preferences', () => HttpResponse.json(initial)),
    http.put('*/preferences', async ({ request }) => {
      const body = (await request.json()) as Record<string, unknown>
      puts.push(body)
      return HttpResponse.json({ ...body, shared: true })
    })
  )
}

beforeEach(() => {
  localStorage.clear()
  useStore.getState().setThemeMode('system')
})
afterEach(() => localStorage.clear())

describe('usePreferencesSync', () => {
  it('applies server values on load, without echoing them back', async () => {
    serve({ themeMode: 'dark', conversationColumns: ['source', 'users'], shared: true })
    renderHook(() => usePreferencesSync())

    await waitFor(() => expect(useStore.getState().themeMode).toBe('dark'))
    expect(JSON.parse(localStorage.getItem(COLUMN_STORAGE_KEY)!)).toEqual(['source', 'users'])
    await new Promise(r => setTimeout(r, 800))
    expect(puts).toHaveLength(0)
  })

  it("uploads this browser's preferences once when the server has none yet", async () => {
    localStorage.setItem(COLUMN_STORAGE_KEY, JSON.stringify(['source']))
    useStore.getState().setThemeMode('light')
    serve({ shared: true })
    renderHook(() => usePreferencesSync())

    await waitFor(() => expect(puts).toHaveLength(1))
    expect(puts[0]).toMatchObject({ themeMode: 'light', conversationColumns: ['source'] })
  })

  it('saves a later change', async () => {
    serve({ themeMode: 'light', shared: true })
    renderHook(() => usePreferencesSync())
    await waitFor(() => expect(useStore.getState().themeMode).toBe('light'))

    act(() => useStore.getState().setThemeMode('dark'))

    await waitFor(() => expect(puts.at(-1)).toMatchObject({ themeMode: 'dark' }), { timeout: 2000 })
  })
})
