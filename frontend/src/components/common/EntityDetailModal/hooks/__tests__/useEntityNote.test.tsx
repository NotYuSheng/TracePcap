/**
 * The entity detail modal is reused across hosts: clicking one node then another mounts the
 * same component with new props. That makes the reset and the stale-response guard the two
 * properties worth testing — both are invisible until an analyst sees one host's note attached
 * to another.
 */
import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { entityNotesService, type EntityNote } from '@/features/notes/services/entityNotesService'
import { useEntityNote } from '../useEntityNote'

vi.mock('@/features/notes/services/entityNotesService', () => ({
  entityNotesService: {
    getNote: vi.fn(),
    upsertNote: vi.fn(),
    deleteNote: vi.fn(),
  },
}))

const mocked = vi.mocked(entityNotesService)

function note(text: string, key = '10.0.0.1'): EntityNote {
  return {
    entityType: 'IP',
    entityKey: key,
    note: text,
    createdAt: '2026-08-12T00:00:00Z',
    updatedAt: '2026-08-12T00:00:00Z',
  }
}

afterEach(() => vi.resetAllMocks())

describe('useEntityNote', () => {
  it('loads the existing note into the draft', async () => {
    mocked.getNote.mockResolvedValue(note('DNS server'))

    const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))

    await waitFor(() => expect(result.current.noteText).toBe('DNS server'))
    expect(result.current.noteChanged).toBe(false)
  })

  it('clears the previous note immediately when the entity changes', async () => {
    mocked.getNote.mockResolvedValue(note('first host'))
    const { result, rerender } = renderHook(({ key }) => useEntityNote('IP', key), {
      initialProps: { key: '10.0.0.1' },
    })
    await waitFor(() => expect(result.current.noteText).toBe('first host'))

    mocked.getNote.mockReturnValue(new Promise(() => {}))
    rerender({ key: '10.0.0.2' })

    // Synchronously blank, not "blank once the fetch returns". The modal is reused, so leaving
    // the old text visible would attribute one host's note to another.
    expect(result.current.noteText).toBe('')
    expect(result.current.savedNote).toBeNull()
  })

  it('ignores a slow response for an entity the user has already left', async () => {
    let resolveFirst: (n: EntityNote) => void = () => {}
    mocked.getNote.mockImplementationOnce(
      () => new Promise<EntityNote>(res => { resolveFirst = res })
    )

    const { result, rerender } = renderHook(({ key }) => useEntityNote('IP', key), {
      initialProps: { key: '10.0.0.1' },
    })

    mocked.getNote.mockResolvedValue(note('second host', '10.0.0.2'))
    rerender({ key: '10.0.0.2' })
    await waitFor(() => expect(result.current.noteText).toBe('second host'))

    // The first request now lands. Without the `active` flag it would overwrite the note the
    // user is actually looking at — the classic out-of-order response bug.
    await act(async () => {
      resolveFirst(note('first host'))
    })

    expect(result.current.noteText).toBe('second host')
  })

  it('tracks whether the draft differs from what is saved', async () => {
    mocked.getNote.mockResolvedValue(note('original'))
    const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))
    await waitFor(() => expect(result.current.noteText).toBe('original'))

    act(() => result.current.setNoteText('edited'))

    // Drives the Save button's enabled state.
    expect(result.current.noteChanged).toBe(true)
  })

  it('treats an empty draft against no saved note as unchanged', async () => {
    mocked.getNote.mockResolvedValue(null)

    const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))

    // `savedNote?.note ?? ''` — otherwise an untouched empty field would look edited and offer
    // to save nothing.
    await waitFor(() => expect(result.current.noteChanged).toBe(false))
  })

  it('adopts the saved note returned by the backend after a save', async () => {
    mocked.getNote.mockResolvedValue(null)
    mocked.upsertNote.mockResolvedValue(note('saved text'))

    const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))
    act(() => result.current.setNoteText('saved text'))
    await act(async () => { await result.current.save() })

    // Takes the server's copy, so createdAt/updatedAt come from the backend rather than being
    // guessed locally.
    expect(result.current.savedNote?.note).toBe('saved text')
    expect(result.current.noteChanged).toBe(false)
  })

  it('clears the draft after a successful delete', async () => {
    mocked.getNote.mockResolvedValue(note('to be removed'))
    mocked.deleteNote.mockResolvedValue(undefined)

    const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))
    await waitFor(() => expect(result.current.noteText).toBe('to be removed'))

    await act(async () => { await result.current.remove() })

    expect(result.current.savedNote).toBeNull()
    expect(result.current.noteText).toBe('')
  })

  describe('known looseness — pinned, not endorsed', () => {
    it('swallows a failed save, leaving no signal beyond a console error', async () => {
      mocked.getNote.mockResolvedValue(null)
      mocked.upsertNote.mockRejectedValue(new Error('backend down'))
      const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})

      const { result } = renderHook(() => useEntityNote('IP', '10.0.0.1'))
      act(() => result.current.setNoteText('important finding'))
      await act(async () => { await result.current.save() })

      // save() resolves either way and exposes no error state. The draft is preserved and
      // noteChanged stays true, which is the only hint anything went wrong — an analyst who
      // closes the modal loses the note believing it was stored. Notes already swallow read
      // errors too (#719), so both directions fail quietly.
      expect(result.current.savedNote).toBeNull()
      expect(result.current.noteChanged).toBe(true)
      expect(result.current.noteSaving).toBe(false)
      expect(consoleError).toHaveBeenCalled()
      consoleError.mockRestore()
    })
  })
})
