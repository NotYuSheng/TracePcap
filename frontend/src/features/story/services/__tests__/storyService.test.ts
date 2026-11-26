/**
 * Story generation is the most expensive call the app makes: it runs an LLM over a whole
 * capture. Everything here is about not wasting that — sending the right body, and waiting
 * long enough for an answer the backend is about to produce.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { investigationToSummary, storyService } from '../storyService'

const FILE_ID = '11111111-1111-1111-1111-111111111111'

/** Captures the JSON body sent to the story endpoint. */
function captureStoryRequest() {
  const seen: { body?: Record<string, unknown>; handled?: boolean } = {}
  server.use(
    http.post('*/api/v1/stories', async ({ request }) => {
      seen.handled = true
      seen.body = (await request.json()) as Record<string, unknown>
      return HttpResponse.json({ id: 's1', content: 'narrative' })
    })
  )
  return seen
}

describe('storyService', () => {
  it('sends only the file id when nothing else is supplied', async () => {
    const seen = captureStoryRequest()

    await storyService.generateStory(FILE_ID)

    // Absent keys rather than nulls: the backend applies its own defaults for anything the
    // caller did not set, and an explicit null would override them.
    expect(seen.body).toEqual({ fileId: FILE_ID })
  })

  it('trims context and prompt before sending', async () => {
    const seen = captureStoryRequest()

    await storyService.generateStory(FILE_ID, '  focus on DNS  ', undefined, '  be terse  ')

    expect(seen.body).toMatchObject({
      additionalContext: 'focus on DNS',
      customPrompt: 'be terse',
    })
  })

  it('omits whitespace-only context rather than sending a blank prompt', async () => {
    const seen = captureStoryRequest()

    await storyService.generateStory(FILE_ID, '   ', undefined, '\n\t')

    // A blank string would still be interpolated into the LLM prompt, spending tokens on
    // nothing and potentially confusing the model.
    expect(seen.body).toEqual({ fileId: FILE_ID })
  })

  it('keeps a zero limit, which truthiness would have dropped', async () => {
    const seen = captureStoryRequest()

    await storyService.generateStory(FILE_ID, undefined, undefined, undefined, 0, 0)

    // The guard is `!== undefined`, not truthiness. 0 means "no findings", which is a real
    // instruction and must not silently become the backend's default.
    expect(seen.body).toMatchObject({ maxFindings: 0, maxRiskMatrix: 0 })
  })

  it('passes through non-zero limits', async () => {
    const seen = captureStoryRequest()

    await storyService.generateStory(FILE_ID, undefined, undefined, undefined, 5, 3)

    expect(seen.body).toMatchObject({ maxFindings: 5, maxRiskMatrix: 3 })
  })

  it('surfaces an LLM failure from the generation endpoint', async () => {
    let handled = false
    server.use(
      http.post('*/api/v1/stories', () => {
        handled = true
        return HttpResponse.json({ message: 'LLM unavailable' }, { status: 502 })
      })
    )

    await expect(storyService.generateStory(FILE_ID)).rejects.toThrow()
    // Pins that the rejection came from the endpoint, not from a missed URL — any rejection
    // would satisfy rejects.toThrow() on its own.
    expect(handled, 'the story endpoint was never reached').toBe(true)
  })

  it('fetches an existing story by id', async () => {
    let path: string | null = null
    server.use(
      http.get('*/api/v1/stories/:storyId', ({ request }) => {
        path = new URL(request.url).pathname
        return HttpResponse.json({ id: 's1', content: 'narrative' })
      })
    )

    await expect(storyService.getStory('s1')).resolves.toMatchObject({ id: 's1' })
    expect(path).toBe('/api/v1/stories/s1')
  })
})

describe('investigationToSummary', () => {
  it('keeps a goal answer\'s attributes, so its chip and conversations link render (#1264)', () => {
    const { answers } = investigationToSummary({
      goals: [
        {
          goal: 'C2',
          answered: true,
          headline: '93.152.209.36 — C2 for NetSupport RAT',
          grade: 'INFERRED',
          confidence: 55,
          basis: [],
          subjects: [],
          attributes: { address: '93.152.209.36', conclusion: 'install-chain' },
        },
      ],
      additional: [],
      unknowns: [],
      coverage: [],
    })
    expect(answers[0].attributes).toEqual({ address: '93.152.209.36', conclusion: 'install-chain' })
  })
})
