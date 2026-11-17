/**
 * Node roles are operator-owned labels: an analyst decides a host is "branch printer" and that
 * sticks across captures. The safety property is that an AI suggestion never silently replaces
 * a label a human confirmed — it goes into the editor for review instead.
 */
import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { insightsService } from '@/features/insights/services/insightsService'
import { aiJobsService } from '@/features/aiJobs/aiJobsService'
import type { AiJob } from '@/features/aiJobs/aiJobs.types'
import type { NodeRole } from '@/features/insights/types/insights.types'
import { useEntityRole } from '../useEntityRole'

vi.mock('@/features/insights/services/insightsService', () => ({
  insightsService: {
    getNodeRole: vi.fn(),
    suggestNodeRole: vi.fn(),
    suggestNodeRolePreview: vi.fn(),
    upsertNodeRole: vi.fn(),
    deleteNodeRole: vi.fn(),
  },
}))

// Suggestions run as background AI jobs; here they come back already finished.
vi.mock('@/features/aiJobs/aiJobsService', () => ({
  AI_JOBS_CHANGED: 'tracepcap:ai-jobs-changed',
  aiJobsService: { list: vi.fn().mockResolvedValue([]), get: vi.fn(), cancel: vi.fn(), startRoleSuggestion: vi.fn() },
}))

const mocked = vi.mocked(insightsService)
const jobs = vi.mocked(aiJobsService)
const finished = (preview: boolean, over: Partial<AiJob>): AiJob => ({
  id: 'j1', kind: preview ? 'ROLE_PREVIEW' : 'ROLE_SUGGESTION', subjectId: '11111111-1111-1111-1111-111111111111',
  subjectKey: 'IP:10.0.0.1', trigger: 'USER', status: 'DONE', createdAt: '2026-11-17T10:00:00Z', ...over,
})
const FILE = '11111111-1111-1111-1111-111111111111'

const role = (overrides: Partial<NodeRole> = {}): NodeRole =>
  ({
    roleLabel: 'branch printer',
    roleDescription: 'prints things',
    confirmedByHuman: false,
    ...overrides,
  }) as NodeRole

afterEach(() => {
  vi.resetAllMocks()
  jobs.list.mockResolvedValue([])
})

function render(showRole = true) {
  return renderHook(() => useEntityRole('IP', '10.0.0.1', FILE, showRole))
}

describe('useEntityRole', () => {
  it('loads the existing role', async () => {
    mocked.getNodeRole.mockResolvedValue(role())

    const { result } = render()

    await waitFor(() => expect(result.current.role?.roleLabel).toBe('branch printer'))
  })

  it('does not fetch when the role section is hidden', async () => {
    const { result } = render(false)

    await waitFor(() => expect(result.current.roleLoading).toBe(false))
    expect(mocked.getNodeRole).not.toHaveBeenCalled()
  })

  describe('suggest', () => {
    it('replaces an unconfirmed role outright', async () => {
      mocked.getNodeRole.mockResolvedValue(role({ confirmedByHuman: false }))
      jobs.startRoleSuggestion.mockResolvedValue(finished(false, { result: role({ roleLabel: 'ai guess' }) }))

      const { result } = render()
      await waitFor(() => expect(result.current.role).not.toBeNull())
      await act(async () => { await result.current.suggest() })

      // Nothing human-authored is at stake, so the suggestion is applied directly.
      expect(result.current.role?.roleLabel).toBe('ai guess')
      expect(result.current.roleEditing).toBe(false)
    })

    it('never overwrites a human-confirmed label, offering the suggestion for review', async () => {
      mocked.getNodeRole.mockResolvedValue(
        role({ roleLabel: 'analyst label', confirmedByHuman: true })
      )
      jobs.startRoleSuggestion.mockResolvedValue(
        finished(true, { result: { roleLabel: 'ai guess', roleDescription: 'ai description' } })
      )

      const { result } = render()
      await waitFor(() => expect(result.current.role?.confirmedByHuman).toBe(true))
      await act(async () => { await result.current.suggest() })

      // The whole point of a confirmed label: it survives until the analyst says otherwise.
      // The suggestion lands in the draft and the editor opens for a decision.
      expect(result.current.role?.roleLabel).toBe('analyst label')
      expect(result.current.roleLabelDraft).toBe('ai guess')
      expect(result.current.roleEditing).toBe(true)
      expect(jobs.startRoleSuggestion).toHaveBeenCalledWith(FILE, 'IP', '10.0.0.1', true)
    })

    it('surfaces the suggestion error message', async () => {
      mocked.getNodeRole.mockResolvedValue(null)
      jobs.startRoleSuggestion.mockResolvedValue(
        finished(false, { status: 'FAILED', error: { message: 'Only 2 conversations seen' } })
      )

      const { result } = render()
      await waitFor(() => expect(result.current.roleLoading).toBe(false))
      await act(async () => { await result.current.suggest() })

      // The model's "not enough evidence" comes back as the job's error; the hook must show it
      // rather than discarding the reason no role could be suggested.
      expect(result.current.roleSuggestError).toBe('Only 2 conversations seen')
      expect(result.current.roleSuggesting).toBe(false)
    })
  })

  it('marks a role confirmed when accepted', async () => {
    mocked.getNodeRole.mockResolvedValue(role())
    mocked.upsertNodeRole.mockResolvedValue(role({ confirmedByHuman: true }))

    const { result } = render()
    await waitFor(() => expect(result.current.role).not.toBeNull())
    await act(async () => { await result.current.accept() })

    // The `true` argument is the confirmation flag — accepting an AI guess is what promotes it
    // to a human-owned label that later suggestions must not overwrite.
    expect(mocked.upsertNodeRole).toHaveBeenCalledWith(
      'IP', '10.0.0.1', 'branch printer', 'prints things', true, FILE
    )
    expect(result.current.role?.confirmedByHuman).toBe(true)
  })

  it('clears the role on discard', async () => {
    mocked.getNodeRole.mockResolvedValue(role())
    mocked.deleteNodeRole.mockResolvedValue(undefined)

    const { result } = render()
    await waitFor(() => expect(result.current.role).not.toBeNull())
    await act(async () => { await result.current.discard() })

    expect(result.current.role).toBeNull()
    expect(result.current.roleEditing).toBe(false)
  })

  it('seeds the editor from the current role', async () => {
    mocked.getNodeRole.mockResolvedValue(role())

    const { result } = render()
    await waitFor(() => expect(result.current.role).not.toBeNull())
    act(() => result.current.openEdit())

    // Editing starts from what is there, so a small correction does not require retyping.
    expect(result.current.roleLabelDraft).toBe('branch printer')
    expect(result.current.roleDescDraft).toBe('prints things')
    expect(result.current.roleEditing).toBe(true)
  })

  it('saves the draft as a confirmed role', async () => {
    mocked.getNodeRole.mockResolvedValue(null)
    mocked.upsertNodeRole.mockResolvedValue(role({ roleLabel: 'edited', confirmedByHuman: true }))

    const { result } = render()
    await waitFor(() => expect(result.current.roleLoading).toBe(false))
    act(() => result.current.setRoleLabelDraft('edited'))
    await act(async () => { await result.current.save() })

    expect(mocked.upsertNodeRole).toHaveBeenCalledWith(
      'IP', '10.0.0.1', 'edited', '', true, FILE
    )
    expect(result.current.role?.roleLabel).toBe('edited')
  })
})
