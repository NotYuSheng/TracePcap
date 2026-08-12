/**
 * Upload is the app's front door, and this hook drives its only progress UI. The two properties
 * that matter are not visible in a single upload: that files go one at a time, and that a
 * duplicate is reported as a duplicate rather than a failure.
 */
import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { uploadService } from '../../services/uploadService'
import { useFileUpload } from '../useFileUpload'

vi.mock('../../services/uploadService', () => ({
  uploadService: { uploadPcap: vi.fn() },
}))

const mocked = vi.mocked(uploadService)

const pcap = (name: string) => new File([new Uint8Array([1, 2, 3])], name)

/** An axios-shaped rejection, which is what the hook branches on. */
function httpError(status: number, data: unknown) {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    response: { status, data },
  })
}

afterEach(() => vi.resetAllMocks())

describe('useFileUpload', () => {
  it('records a fileId for each successful upload', async () => {
    mocked.uploadPcap.mockResolvedValue({ fileId: 'f1' } as never)

    const { result } = renderHook(() => useFileUpload())
    await act(async () => { await result.current.uploadFiles([pcap('a.pcap')]) })

    expect(result.current.uploads[0]).toMatchObject({
      fileName: 'a.pcap',
      fileId: 'f1',
      progress: 100,
      isUploading: false,
    })
  })

  it('uploads one file at a time rather than all at once', async () => {
    let inFlight = 0
    let maxConcurrent = 0
    mocked.uploadPcap.mockImplementation(async () => {
      inFlight += 1
      maxConcurrent = Math.max(maxConcurrent, inFlight)
      await new Promise(r => setTimeout(r, 5))
      inFlight -= 1
      return { fileId: 'f' } as never
    })

    const { result } = renderHook(() => useFileUpload())
    await act(async () => {
      await result.current.uploadFiles([pcap('a.pcap'), pcap('b.pcap'), pcap('c.pcap')])
    })

    // Sequential by design: captures are large, and a Promise.all here would flood the backend
    // and the network with concurrent multipart bodies.
    expect(maxConcurrent).toBe(1)
    expect(mocked.uploadPcap).toHaveBeenCalledTimes(3)
  })

  it('marks a 409 as a duplicate, not a failure', async () => {
    mocked.uploadPcap.mockRejectedValue(httpError(409, { existingFileId: 'existing-1' }))

    const { result } = renderHook(() => useFileUpload())
    await act(async () => { await result.current.uploadFiles([pcap('dup.pcap')]) })

    // Re-uploading a capture is a normal thing to do. Showing it as an error would send the
    // analyst looking for a problem instead of to the file they already have.
    expect(result.current.uploads[0]).toMatchObject({
      isDuplicate: true,
      duplicateOfFileId: 'existing-1',
    })
    // No error key at all — the duplicate branch never sets one, which is what keeps the entry
    // out of the failure styling.
    expect(result.current.uploads[0].error).toBeUndefined()
  })

  it('treats a 409 without an existing id as a plain error', async () => {
    mocked.uploadPcap.mockRejectedValue(httpError(409, { message: 'conflict' }))

    const { result } = renderHook(() => useFileUpload())
    await act(async () => { await result.current.uploadFiles([pcap('x.pcap')]) })

    // The duplicate affordance needs the id to link to; without one there is nothing to offer.
    expect(result.current.uploads[0].isDuplicate).toBeUndefined()
    expect(result.current.uploads[0].error).toBe('conflict')
  })

  it('prefers the backend message when an upload fails', async () => {
    mocked.uploadPcap.mockRejectedValue(httpError(422, { message: 'Not a valid pcap' }))

    const { result } = renderHook(() => useFileUpload())
    await act(async () => { await result.current.uploadFiles([pcap('bad.pcap')]) })

    // The backend knows why it rejected the file; "Upload failed" would discard that.
    expect(result.current.uploads[0].error).toBe('Not a valid pcap')
  })

  it('falls back to a readable message when the failure carries none', async () => {
    mocked.uploadPcap.mockRejectedValue({})

    const { result } = renderHook(() => useFileUpload())
    await act(async () => { await result.current.uploadFiles([pcap('bad.pcap')]) })

    expect(result.current.uploads[0].error).toBe('Upload failed')
  })

  it('keeps going after one file fails', async () => {
    mocked.uploadPcap
      .mockRejectedValueOnce(httpError(422, { message: 'bad' }))
      .mockResolvedValueOnce({ fileId: 'f2' } as never)

    const { result } = renderHook(() => useFileUpload())
    await act(async () => {
      await result.current.uploadFiles([pcap('bad.pcap'), pcap('good.pcap')])
    })

    // One malformed capture in a drag-and-drop of twenty must not abandon the other nineteen.
    expect(result.current.uploads[0].error).toBe('bad')
    expect(result.current.uploads[1].fileId).toBe('f2')
  })

  it('reports progress from the service onto the matching entry', async () => {
    mocked.uploadPcap.mockImplementation(async (_f, onProgress) => {
      onProgress?.(42)
      return { fileId: 'f1' } as never
    })

    const { result } = renderHook(() => useFileUpload())
    const done = act(async () => { await result.current.uploadFiles([pcap('a.pcap')]) })
    await done

    await waitFor(() => expect(result.current.uploads[0].progress).toBe(100))
  })

  it('exposes isUploading only while work is outstanding', async () => {
    mocked.uploadPcap.mockResolvedValue({ fileId: 'f1' } as never)

    const { result } = renderHook(() => useFileUpload())
    expect(result.current.isUploading).toBe(false)

    await act(async () => { await result.current.uploadFiles([pcap('a.pcap')]) })

    expect(result.current.isUploading).toBe(false)
  })

  it('clears the list on request', async () => {
    mocked.uploadPcap.mockResolvedValue({ fileId: 'f1' } as never)

    const { result } = renderHook(() => useFileUpload())
    await act(async () => { await result.current.uploadFiles([pcap('a.pcap')]) })
    expect(result.current.uploads).toHaveLength(1)

    act(() => result.current.clearUploads())

    expect(result.current.uploads).toEqual([])
  })
})
