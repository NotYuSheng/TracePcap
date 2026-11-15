/**
 * Upload A: the files on their way, as rows in the start panel. Each row says where its file is
 * and what to do next, in words.
 */
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { apiClient } from '@/services/api/client'
import type { UploadEntry } from '@features/upload/hooks/useFileUpload'
import { UploadQueue } from '../UploadQueue'
import { stagesText } from '../StartPanel'

vi.mock('@/services/api/client', () => ({ apiClient: { get: vi.fn() } }))
const get = vi.mocked(apiClient.get)

const entry = (extra: Partial<UploadEntry>): UploadEntry => ({
  id: '1',
  fileName: 'site_to_site_vpn.pcap',
  progress: 0,
  isUploading: false,
  ...extra,
})

function show(uploads: UploadEntry[], rejected: { name: string; reason: string }[] = []) {
  render(
    <MemoryRouter>
      <UploadQueue uploads={uploads} rejected={rejected} onClear={() => {}} />
    </MemoryRouter>,
  )
}

afterEach(() => vi.resetAllMocks())

describe('UploadQueue', () => {
  it('shows nothing when there is nothing on its way', () => {
    const { container } = render(
      <MemoryRouter>
        <UploadQueue uploads={[]} rejected={[]} onClear={() => {}} />
      </MemoryRouter>,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('shows upload progress in bytes', () => {
    show([entry({ isUploading: true, progress: 50, size: 2048 })])
    expect(screen.getByText('50%')).toBeInTheDocument()
    expect(screen.getByText(/^Uploading · 1(\.0+)? KB of 2(\.0+)? KB$/)).toBeInTheDocument()
    expect(screen.queryByText('Clear these')).not.toBeInTheDocument()
  })

  it('follows the analysis and offers Open when ready', async () => {
    get.mockResolvedValue({ status: 200, data: { status: 'completed', packetCount: 700 } } as never)
    show([entry({ progress: 100, fileId: 'f1' })])
    await waitFor(() => expect(screen.getByRole('link', { name: 'Open' })).toHaveAttribute('href', '/analysis/f1'))
    expect(screen.getByText('Ready · 700 packets')).toBeInTheDocument()
  })

  it('shows the analysis stage while it runs', async () => {
    get.mockImplementation(((url: string) =>
      Promise.resolve(
        url.includes('/progress')
          ? { status: 200, data: { stageIndex: 2, totalStages: 5, stage: 'Detecting applications & threats', percent: 40 } }
          : { status: 200, data: { status: 'processing' } },
      )) as never)
    show([entry({ progress: 100, fileId: 'f1' })])
    await waitFor(() => expect(screen.getByText('Stage 2 of 5: Detecting applications & threats')).toBeInTheDocument())
  })

  it('says a duplicate was not uploaded again, and links the analysis it has', () => {
    show([entry({ progress: 100, isDuplicate: true, duplicateOfFileId: 'old' })])
    expect(screen.getByText('Already analysed. Nothing was uploaded again.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open that analysis' })).toHaveAttribute('href', '/analysis/old')
  })

  it('lists rejected files with the reason', () => {
    show([], [{ name: 'capture.zip', reason: 'Not a capture.' }])
    expect(screen.getByText('capture.zip')).toBeInTheDocument()
    expect(screen.getByText('Not a capture.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Clear these' })).toBeInTheDocument()
  })
})

describe('stagesText', () => {
  it('names the stages that will run', () => {
    expect(stagesText({ enableNdpi: true, enableSuricata: false, enableFileExtraction: true })).toBe(
      'nDPI and file extraction',
    )
    expect(stagesText({ enableNdpi: true, enableSuricata: true, enableFileExtraction: true })).toBe(
      'nDPI, Suricata and file extraction',
    )
    expect(stagesText({ enableNdpi: false, enableSuricata: false, enableFileExtraction: false })).toBe(
      'the basic analysis only',
    )
  })
})
