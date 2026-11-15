import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { RulePreviewPanel } from '../RulePreviewPanel'

const draft = {
  name: 'odd', severity: 'low' as const, enabled: true, match: { dstPort: 5999 },
  payloadContains: [], payloadRegex: [], matchAll: false,
}

function serveFiles() {
  server.use(
    http.get('*/files', () =>
      HttpResponse.json({
        data: [
          { fileId: 'f1', fileName: 'a.pcap', status: 'completed' },
          { fileId: 'f2', fileName: 'busy.pcap', status: 'processing' },
        ],
      })
    )
  )
}

describe('RulePreviewPanel (#925 phase 4)', () => {
  it('tests the rule as it stands against a capture and shows the matches', async () => {
    let sent: unknown = null
    serveFiles()
    server.use(
      http.post('*/detection-rules/previews', async ({ request }) => {
        sent = await request.json()
        return HttpResponse.json({
          fileId: 'f1', fileName: 'a.pcap', matches: 12, conversations: 40, packetsDeleted: false,
          sample: [{ conversationId: 'c1', srcIp: '10.0.0.1', srcPort: 4000, dstIp: '10.0.0.2', dstPort: 5999, protocol: 'UDP' }],
        })
      })
    )
    render(<RulePreviewPanel draft={draft} canTest />)
    const select = await screen.findByLabelText('Test against a capture')
    await waitFor(() => expect(select).toHaveValue('f1'))
    expect(screen.queryByText('busy.pcap')).not.toBeInTheDocument() // only analysed captures
    await userEvent.click(screen.getByRole('button', { name: 'Test' }))

    expect(await screen.findByTestId('rule-preview-result')).toHaveTextContent('Would match 12 of 40 conversations')
    expect(screen.getByText(/10\.0\.0\.1:4000 → 10\.0\.0\.2:5999/)).toBeInTheDocument()
    expect(screen.getByText('…and 11 more')).toBeInTheDocument()
    expect(sent).toMatchObject({ fileId: 'f1', rule: { name: 'odd', match: { dstPort: 5999 } } })
  })

  it("says when it can't test because the packets were deleted", async () => {
    serveFiles()
    server.use(
      http.post('*/detection-rules/previews', () =>
        HttpResponse.json({ fileId: 'f1', fileName: 'a.pcap', matches: null, conversations: 40, packetsDeleted: true, sample: [] })
      )
    )
    render(<RulePreviewPanel draft={draft} canTest />)
    await waitFor(() => expect(screen.getByLabelText('Test against a capture')).toHaveValue('f1'))
    await userEvent.click(screen.getByRole('button', { name: 'Test' }))
    expect(await screen.findByTestId('rule-preview-result')).toHaveTextContent("Can't test this rule here")
  })

  it("can't test an invalid form", async () => {
    serveFiles()
    render(<RulePreviewPanel draft={draft} canTest={false} />)
    await waitFor(() => expect(screen.getByLabelText('Test against a capture')).toHaveValue('f1'))
    expect(screen.getByRole('button', { name: 'Test' })).toBeDisabled()
  })
})
