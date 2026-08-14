/**
 * The note hook backs the one control that writes an operator's own words into the tool.
 *
 * Two behaviours matter more than the CRUD: the modal is reused across entities, so a previous
 * entity's note must not leak into the next one; and every failure path here is swallowed to a
 * console.error, which is pinned below rather than endorsed.
 */
import { act, renderHook, waitFor } from '@testing-library/react'
import { HttpResponse, http } from 'msw'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { server } from '@/test/msw'
import { useEntityNote } from '../useEntityNote'

function note(entityKey: string, text: string) {
  return {
    entityType: 'IP',
    entityKey,
    note: text,
    createdAt: '2026-08-12T00:00:00Z',
    updatedAt: '2026-08-12T00:00:00Z',
  }
}

beforeEach(() => {
  // The hook reports every failure this way, so silence it and assert on behaviour instead.
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('useEntityNote', () => {
  it('loads the existing note into the draft', async () => {
    server.use(
      http.get('*/api/v1/entity-notes', () => HttpResponse.json(note('10.0.0.1', 'Jump box')))
    )

    const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))

    await waitFor(() => expect(result.current.noteText).toBe('Jump box'))
    expect(result.current.savedNote?.note).toBe('Jump box')
    // Draft equals saved, so the Save button has nothing to do yet.
    expect(result.current.noteChanged).toBe(false)
  })

  it('clears the previous entity note when the key changes', async () => {
    server.use(
      http.get('*/api/v1/entity-notes', ({ request }) => {
        const key = new URL(request.url).searchParams.get('entityKey')
        return key === '10.0.0.1'
          ? HttpResponse.json(note('10.0.0.1', 'Jump box'))
          : HttpResponse.json(null)
      })
    )

    const { result, rerender } = renderHook(({ key }) => useEntityNote('IP', key), {
      initialProps: { key: '10.0.0.1' },
    })
    await waitFor(() => expect(result.current.noteText).toBe('Jump box'))

    rerender({ key: '10.0.0.2' })

    // The modal is reused across entities. Without the reset, the second host would display —
    // and could be saved — with the first host's note.
    await waitFor(() => expect(result.current.noteText).toBe(''))
    expect(result.current.savedNote).toBeNull()
  })

  it('marks the draft changed once it diverges from the saved note', async () => {
    server.use(http.get('*/api/v1/entity-notes', () => HttpResponse.json(null)))

    const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))
    await waitFor(() => expect(result.current.noteChanged).toBe(false))

    act(() => result.current.setNoteText('new finding'))

    expect(result.current.noteChanged).toBe(true)
  })

  it('stores the saved note returned by the server', async () => {
    server.use(
      http.get('*/api/v1/entity-notes', () => HttpResponse.json(null)),
      http.put('*/api/v1/entity-notes', () => HttpResponse.json(note('10.0.0.1', 'persisted')))
    )

    const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))
    act(() => result.current.setNoteText('persisted'))

    await act(async () => {
      await result.current.save()
    })

    expect(result.current.savedNote?.note).toBe('persisted')
    expect(result.current.noteSaving).toBe(false)
  })

  describe('swallowed failures — pinned, not endorsed', () => {
    it('keeps the draft and reports nothing when a save fails', async () => {
      server.use(
        http.get('*/api/v1/entity-notes', () => HttpResponse.json(null)),
        http.put('*/api/v1/entity-notes', () =>
          HttpResponse.json({ message: 'boom' }, { status: 500 })
        )
      )

      const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))
      act(() => result.current.setNoteText('unsaved finding'))

      await act(async () => {
        await result.current.save()
      })

      // The catch only console.errors, so the hook exposes no error state. The draft still
      // reads as unsaved (noteChanged stays true), which is the single thing standing between
      // an operator and losing what they typed — but nothing tells them the save failed.
      expect(result.current.savedNote).toBeNull()
      expect(result.current.noteChanged).toBe(true)
      expect(result.current.noteSaving).toBe(false)
    })
  })
})
