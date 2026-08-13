/**
 * The tracer walks an analyst through a single conversation packet by packet. Its explain
 * endpoint is LLM-backed, and that path fails *softly*: a 200 carrying an `error` field rather
 * than an HTTP error. A caller that only checks the status shows an empty explanation panel
 * with no indication anything went wrong.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { tracerService } from '../tracerService'

const CONV = 'conv-1'

describe('tracerService', () => {
  it('returns the step list with its conversation metadata', async () => {
    const payload = {
      conversationId: CONV,
      srcIp: '10.0.0.1',
      srcPort: 1234,
      dstIp: '8.8.8.8',
      dstPort: 53,
      protocol: 'UDP',
      appName: 'DNS',
      steps: [
        {
          stepIndex: 0,
          packetNumber: 1,
          timestamp: null,
          direction: 'CLIENT' as const,
          protocol: 'UDP',
          size: 74,
          info: null,
          payloadHex: null,
        },
      ],
    }
    server.use(http.get('*/api/v1/tracer/:id/steps', () => HttpResponse.json(payload)))

    await expect(tracerService.getSteps(CONV)).resolves.toEqual(payload)
  })

  it('returns peers for a conversation', async () => {
    const payload = {
      conversationId: CONV,
      hostIp: '10.0.0.1',
      peers: [
        { ip: '8.8.8.8', conversationId: CONV, protocol: 'UDP', packetCount: 2, responded: true },
      ],
    }
    server.use(http.get('*/api/v1/tracer/:id/peers', () => HttpResponse.json(payload)))

    await expect(tracerService.getPeers(CONV)).resolves.toEqual(payload)
  })

  it('requests an explanation with POST, since it triggers generation', async () => {
    let method: string | null = null
    server.use(
      http.post('*/api/v1/tracer/:id/explanations', ({ request }) => {
        method = request.method
        return HttpResponse.json({ conversationId: CONV, explanations: [] })
      })
    )

    await tracerService.explain(CONV)

    // Not a GET: the call runs an LLM and creates a result, so it is not safe to retry or cache.
    expect(method).toBe('POST')
  })

  it('surfaces a soft LLM failure as a 200 carrying an error field', async () => {
    server.use(
      http.post('*/api/v1/tracer/:id/explanations', () =>
        HttpResponse.json({
          conversationId: CONV,
          explanations: [],
          error: 'LLM server is not responding',
        })
      )
    )

    const result = await tracerService.explain(CONV)

    // The promise resolves — the failure is in the body, not the status. Pinned because a
    // caller that only checks for a rejection renders an empty panel and says nothing.
    expect(result.error).toBe('LLM server is not responding')
    expect(result.explanations).toEqual([])
  })

  it('still rejects on a hard failure from the explain endpoint', async () => {
    let handled = false
    server.use(
      http.post('*/api/v1/tracer/:id/explanations', () => {
        handled = true
        return HttpResponse.json({ message: 'gateway' }, { status: 502 })
      })
    )

    // Both failure modes exist, so the UI has to handle each. e2e/llm-error.spec.ts covers the
    // 502 path end to end; this pins that the service does not swallow it.
    await expect(tracerService.explain(CONV)).rejects.toThrow()
    expect(handled).toBe(true)
  })
})
