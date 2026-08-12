/**
 * Service-layer tests for extracted files, run against the real `apiClient` with MSW
 * intercepting at the network layer.
 *
 * This module is where #630 lived: `getDownloadUrl()` built `/api/files/...` while every
 * route is served under `/api/v1`, and nothing here was tested, so the broken URL shipped.
 * The URL builders are asserted explicitly for that reason.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import {
  getDownloadUrl,
  getExtractedFiles,
  getExtractionWarnings,
  getExtractionsByConversation,
  getPreviewUrl,
} from '../extractedFilesService'

const FILE_ID = '11111111-1111-1111-1111-111111111111'
const EXTRACTION_ID = '22222222-2222-2222-2222-222222222222'

const extractedFile = {
  id: EXTRACTION_ID,
  conversationId: null,
  filename: 'evidence.bin',
  mimeType: 'application/octet-stream',
  fileSize: 94,
  sha256: 'abc',
  extractionMethod: 'tshark',
  skippedReason: null,
  createdAt: '2026-08-12T00:00:00Z',
}

describe('extractedFilesService', () => {
  it('unwraps the response body for the extracted-file list', async () => {
    server.use(
      http.get('*/api/v1/files/:fileId/extractions', () => HttpResponse.json([extractedFile]))
    )

    await expect(getExtractedFiles(FILE_ID)).resolves.toEqual([extractedFile])
  })

  it('passes the conversation filter as a query parameter', async () => {
    let seen: string | null = null
    server.use(
      http.get('*/api/v1/files/:fileId/extractions', ({ request }) => {
        seen = new URL(request.url).searchParams.get('conversationId')
        return HttpResponse.json([])
      })
    )

    await getExtractionsByConversation(FILE_ID, 'conv-7')

    // Asserted through the request MSW actually received, not by string-matching the builder,
    // so an encoding change that breaks the real request still fails.
    expect(seen).toBe('conv-7')
  })

  it('surfaces a server error rather than resolving with undefined', async () => {
    server.use(
      http.get('*/api/v1/files/:fileId/extractions', () =>
        HttpResponse.json({ message: 'boom' }, { status: 500 })
      )
    )

    // The component layer distinguishes "no extracted files" from "the request failed" only
    // because this rejects; resolving to undefined would render an empty list on an outage.
    await expect(getExtractedFiles(FILE_ID)).rejects.toThrow()
  })

  it('reads the extraction-warning envelope', async () => {
    const warnings = {
      matchLimitConversationIds: ['c1'],
      conversationLimitSkippedCount: 2,
      conversationLimitSkippedIds: ['c2', 'c3'],
      sizeLimitFiles: [],
      maxMatchesPerStream: 10,
      maxStreamConversations: 100,
      maxFileSizeMb: 5,
    }
    server.use(
      http.get('*/api/v1/files/:fileId/extractions/warnings', () => HttpResponse.json(warnings))
    )

    await expect(getExtractionWarnings(FILE_ID)).resolves.toEqual(warnings)
  })

  describe('direct-navigation URLs', () => {
    // These are browser-navigated (anchor href), so they bypass apiClient's baseURL and must
    // carry the version segment themselves. Getting this wrong is exactly #630.
    it('builds a download URL under the versioned prefix', () => {
      expect(getDownloadUrl(FILE_ID, EXTRACTION_ID)).toBe(
        `/api/v1/files/${FILE_ID}/extractions/${EXTRACTION_ID}/download`
      )
    })

    it('builds a preview URL under the versioned prefix', () => {
      expect(getPreviewUrl(FILE_ID, EXTRACTION_ID)).toBe(
        `/api/v1/files/${FILE_ID}/extractions/${EXTRACTION_ID}/preview`
      )
    })
  })
})
