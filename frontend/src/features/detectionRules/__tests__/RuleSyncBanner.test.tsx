import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { RuleSyncBanner } from '../RuleSyncBanner'

const status = (over: Partial<Record<string, unknown>> = {}) => ({
  captures: 1,
  staleCaptures: 0,
  uncheckableCaptures: 0,
  staleRules: [],
  uncheckableRules: [],
  ...over,
})

describe('RuleSyncBanner (#925 phase 2)', () => {
  it('shows nothing when the capture is up to date', async () => {
    let asked = false
    server.use(
      http.get('*/files/f1/rule-status', () => {
        asked = true
        return HttpResponse.json(status())
      }),
      http.get('*/rule-reapply-jobs', () => HttpResponse.json([]))
    )
    render(<RuleSyncBanner fileId="f1" canReapply />)
    await waitFor(() => expect(asked).toBe(true))
    expect(screen.queryByTestId('rule-sync-banner')).not.toBeInTheDocument()
  })

  it("names the rules a capture is out of date for, re-applies, and follows the job", async () => {
    let started: unknown = null
    let polls = 0
    server.use(
      http.get('*/files/f1/rule-status', () =>
        HttpResponse.json(status({ staleCaptures: 1, staleRules: ['c2_beacon', 'tor_use'] }))
      ),
      http.get('*/rule-reapply-jobs', () => HttpResponse.json([])),
      http.post('*/rule-reapply-jobs', async ({ request }) => {
        started = await request.json()
        return HttpResponse.json({ id: 'j1', status: 'RUNNING', total: 1, done: 0, failed: 0, requestedBy: 'system', createdAt: '' }, { status: 201 })
      }),
      http.get('*/rule-reapply-jobs/j1', () => {
        polls++
        return HttpResponse.json({ id: 'j1', status: 'DONE', total: 1, done: 1, failed: 0, requestedBy: 'system', createdAt: '' })
      })
    )
    render(<RuleSyncBanner fileId="f1" canReapply />)

    expect(await screen.findByText(/c2_beacon, tor_use/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Re-apply to this capture' }))
    expect(started).toEqual({ fileId: 'f1' })
    expect(await screen.findByText(/Re-applying rules: 0 of 1/)).toBeInTheDocument()
    expect(await screen.findByText('Re-applied to 1 capture.', {}, { timeout: 4000 })).toBeInTheDocument()
    expect(polls).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'Show updated matches' })).toBeInTheDocument()
  })

  it("lists the device types re-scoring changed, and the labels it flagged (#925)", async () => {
    server.use(
      http.get('*/files/f1/rule-status', () => HttpResponse.json(status({ staleCaptures: 1, staleRules: ['rtsp'] }))),
      http.get('*/rule-reapply-jobs', () => HttpResponse.json([])),
      http.post('*/rule-reapply-jobs', () =>
        HttpResponse.json({ id: 'j2', status: 'RUNNING', total: 1, done: 0, failed: 0, requestedBy: 'alice', createdAt: '' }, { status: 201 })),
      http.get('*/rule-reapply-jobs/j2', () =>
        HttpResponse.json({
          id: 'j2', status: 'DONE', total: 1, done: 1, failed: 0, requestedBy: 'alice', createdAt: '',
          reclassifiedCount: 1, staleLabelsCount: 1,
          reclassified: [{ fileId: 'f1', ip: '10.0.0.9', from: 'IOT', to: 'CCTV Camera', rules: ['rtsp'] }],
        }))
    )
    render(<RuleSyncBanner fileId="f1" canReapply />)
    await userEvent.click(await screen.findByRole('button', { name: 'Re-apply to this capture' }))
    const list = await screen.findByTestId('reapply-reclassified', {}, { timeout: 4000 })
    expect(list).toHaveTextContent('1 host changed device type')
    expect(list).toHaveTextContent('10.0.0.9: IOT → CCTV Camera (rule rtsp)')
    expect(list).toHaveTextContent('1 analyst label now disagrees with the evidence and is marked stale')
  })

  it("can't re-apply without permission, and says why", async () => {
    server.use(
      http.get('*/detection-rules/status', () => HttpResponse.json(status({ captures: 5, staleCaptures: 3 }))),
      http.get('*/rule-reapply-jobs', () => HttpResponse.json([]))
    )
    render(<RuleSyncBanner canReapply={false} reason="only admins can change this." />)
    expect(await screen.findByText(/3 of 5 captures haven't been checked/)).toBeInTheDocument()
    expect(screen.getByText(/only admins can change this/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Re-apply to 3 captures' })).toBeDisabled()
  })

  it('says when payload rules could not be re-checked because packets were deleted', async () => {
    server.use(
      http.get('*/files/f1/rule-status', () =>
        HttpResponse.json(status({ uncheckableCaptures: 1, uncheckableRules: ['cleartext_credentials'] }))
      ),
      http.get('*/rule-reapply-jobs', () => HttpResponse.json([]))
    )
    render(<RuleSyncBanner fileId="f1" canReapply />)
    expect(await screen.findByText(/Couldn't re-check/)).toHaveTextContent('cleartext_credentials')
  })

  it('picks up a job that is already running', async () => {
    server.use(
      http.get('*/detection-rules/status', () => HttpResponse.json(status({ captures: 9, staleCaptures: 4 }))),
      http.get('*/rule-reapply-jobs', () =>
        HttpResponse.json([{ id: 'j9', status: 'RUNNING', total: 4, done: 2, failed: 0, requestedBy: 'alice', createdAt: '' }])
      ),
      http.get('*/rule-reapply-jobs/j9', () =>
        HttpResponse.json({ id: 'j9', status: 'RUNNING', total: 4, done: 3, failed: 0, requestedBy: 'alice', createdAt: '' })
      )
    )
    render(<RuleSyncBanner canReapply />)
    expect(await screen.findByText(/Re-applying rules: 2 of 4/)).toBeInTheDocument()
  })
})
