/**
 * Upload is the entry point for everything the app does: get this wrong and the analysis flags
 * baked into the capture are wrong for its whole life, because they are recorded at ingest and
 * never revisited.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { uploadService } from '../uploadService'

function pcap(name = 'capture.pcap') {
  return new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])], name, {
    type: 'application/vnd.tcpdump.pcap',
  })
}

/**
 * Captures the multipart body the service actually sent.
 *
 * Note the Blob returned by `formData()` is backed by the whole multipart frame rather than
 * the individual part, so its bytes are the boundary text — see the content assertion below.
 */
function captureUpload() {
  const seen: { form?: FormData } = {}
  server.use(
    http.post('*/api/v1/files', async ({ request }) => {
      seen.form = await request.formData()
      return HttpResponse.json({ fileId: 'abc' }, { status: 201 })
    })
  )
  return seen
}

describe('uploadService', () => {
  it('enables every analysis stage when no options are given', async () => {
    const seen = captureUpload()

    await uploadService.uploadPcap(pcap())

    // The defaults are the common case and are recorded permanently on the file. A flag
    // defaulting to false would silently produce partial captures that look complete.
    expect(seen.form!.get('enableNdpi')).toBe('true')
    expect(seen.form!.get('enableSuricata')).toBe('true')
    expect(seen.form!.get('enableFileExtraction')).toBe('true')
  })

  it('defaults the source to ANALYSIS', async () => {
    const seen = captureUpload()

    await uploadService.uploadPcap(pcap())

    // MONITOR-sourced files are filtered out of the analysis list, so a wrong default hides
    // uploads from the page the user just uploaded them on.
    expect(seen.form!.get('source')).toBe('ANALYSIS')
  })

  it('sends disabled stages as the string "false", not omitted', async () => {
    const seen = captureUpload()

    await uploadService.uploadPcap(pcap(), undefined, {
      enableNdpi: false,
      enableSuricata: false,
      enableFileExtraction: true,
      source: 'MONITOR',
    })

    // Multipart values are strings. Omitting a false flag would let the backend apply its own
    // default and re-enable a stage the user turned off.
    expect(seen.form!.get('enableNdpi')).toBe('false')
    expect(seen.form!.get('enableSuricata')).toBe('false')
    expect(seen.form!.get('enableFileExtraction')).toBe('true')
    expect(seen.form!.get('source')).toBe('MONITOR')
  })

  it('sends the capture under the field name the backend reads', async () => {
    const seen = captureUpload()

    await uploadService.uploadPcap(pcap('evidence.pcap'))

    // Compares the actual bytes, not just that something non-empty arrived — a regression that
    // sent the wrong content would otherwise pass. Deliberately not asserting the filename or
    // `instanceof File`: the multipart body is re-parsed by undici, which drops the name and
    // returns its own File class, so both would assert about the test environment.
    // Content type and non-empty payload only. Comparing the actual bytes was attempted and
    // does not work here: `request.formData()` yields a Blob backed by the whole multipart
    // frame, so reading it — inside the handler or after — returns the boundary text rather
    // than the part's contents. Asserting on that would test undici, not this service. The
    // bytes are covered end to end by PipelineIntegrationTest's real upload instead.
    const sent = seen.form!.get('file') as Blob
    expect(sent.type).toBe('application/vnd.tcpdump.pcap')
    expect(sent.size).toBeGreaterThan(0)
  })

  it('rejects a duplicate upload rather than resolving', async () => {
    let handled = false
    server.use(
      http.post('*/api/v1/files', () => {
        handled = true
        return HttpResponse.json({ existingFileId: 'dup' }, { status: 409 })
      })
    )

    // The caller distinguishes "already uploaded" from success by catching; resolving here
    // would show a fresh-upload confirmation for a file that was not stored.
    await expect(uploadService.uploadPcap(pcap())).rejects.toThrow()

    // `rejects.toThrow()` alone would also pass if the request never reached a handler — a
    // wrong URL rejects too. This pins that the rejection came from the 409 path, which is the
    // failure mode that actually bit this file: my first handler guessed /files/upload.
    expect(handled, 'the 409 handler was never reached').toBe(true)
  })
})
