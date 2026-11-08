import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { FileTabPage } from '../FileTabPage'

const orig = {
  fileId: 'f1', fileName: 'a.pcap', status: 'completed', packetCount: 1200, uploadedAt: [2026, 11, 8, 10, 0, 0, 0],
  enableNdpi: false, enableSuricata: false, enableFileExtraction: true, derivedFrom: null, version: false,
}
const v1 = { ...orig, fileId: 'f2', enableNdpi: true, derivedFrom: 'f1', version: true, uploadedAt: '2026-11-08T11:00:00' }

function Where() {
  return <div data-testid="where">{useLocation().pathname}</div>
}

function renderAt(fileId: string) {
  return render(
    <MemoryRouter initialEntries={[`/analysis/${fileId}/file`]}>
      <Routes>
        <Route path="/analysis/:fileId/file" element={<FileTabPage />} />
        <Route path="*" element={<Where />} />
      </Routes>
    </MemoryRouter>
  )
}

describe('FileTabPage (#915 phase 3)', () => {
  it("shows how the capture was analysed and re-analyses it as a new version", async () => {
    let sent: unknown = null
    server.use(
      http.get('*/files/f1/versions', () => HttpResponse.json([orig])),
      http.post('*/files/f1/reanalyses', async ({ request }) => {
        sent = await request.json()
        return HttpResponse.json({ fileId: 'f9' }, { status: 201 })
      })
    )
    renderAt('f1')
    expect(await screen.findByText(/Application detection \(nDPI\):/)).toHaveTextContent('off')
    expect(screen.getByText(/File extraction:/)).toHaveTextContent('on')
    expect(screen.getByTestId('file-tab')).not.toHaveTextContent('Invalid Date') // the API's array dates

    await userEvent.click(screen.getByRole('button', { name: /Re-analyse with other options/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('button', { name: 'Re-analyse with the same options' })).toBeInTheDocument()
    await userEvent.click(within(dialog).getByLabelText(/Application detection/))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Re-analyse' }))
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/analysis/f9'))
    expect(sent).toEqual({ enableNdpi: true, enableSuricata: false, enableFileExtraction: true })
  })

  it('on a version, links back to the original and lists every version', async () => {
    server.use(http.get('*/files/f2/versions', () => HttpResponse.json([orig, v1])))
    renderAt('f2')
    expect(await screen.findByText(/This is a re-analysis/)).toBeInTheDocument()
    const rows = screen.getAllByRole('row')
    expect(rows).toHaveLength(3) // header + 2 versions
    expect(rows[2]).toHaveTextContent('viewing')
    await userEvent.click(within(rows[1]).getByRole('button', { name: 'Open' }))
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/analysis/f1'))
  })

  it("shows the server's reason when re-analysis isn't possible", async () => {
    server.use(
      http.get('*/files/f1/versions', () => HttpResponse.json([orig])),
      http.post('*/files/f1/reanalyses', () =>
        HttpResponse.json({ message: "Retention already deleted this capture's packets, so it can't be re-analysed." }, { status: 400 })
      )
    )
    renderAt('f1')
    await userEvent.click(await screen.findByRole('button', { name: /Re-analyse with other options/ }))
    const dialog = await screen.findByRole('dialog')
    await userEvent.click(within(dialog).getByRole('button', { name: /Re-analyse/ }))
    expect(await within(dialog).findByText(/Retention already deleted/)).toBeInTheDocument()
  })
})
