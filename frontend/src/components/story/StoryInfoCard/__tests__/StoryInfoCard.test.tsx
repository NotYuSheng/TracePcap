/**
 * Caps on how many findings and risk-matrix rows go into a generated story. These are LLM
 * prompt-size controls: too low and the narrative omits evidence the analyst has already seen,
 * too high and the prompt exceeds the context window and the generation fails outright.
 */
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { StoryInfoCard } from '../StoryInfoCard'

function renderCard(props: Parameters<typeof StoryInfoCard>[0] = {}) {
  const onMaxFindingsChange = vi.fn()
  const onMaxRiskMatrixChange = vi.fn()
  render(
    <StoryInfoCard
      onMaxFindingsChange={onMaxFindingsChange}
      onMaxRiskMatrixChange={onMaxRiskMatrixChange}
      {...props}
    />
  )
  return { onMaxFindingsChange, onMaxRiskMatrixChange }
}

/**
 * The row of controls belonging to one cap, located by its exact label. A regex like /findings/i
 * also matches the explanatory prose above the controls, so the exact string is what isolates
 * the row.
 */
function capRow(label: 'Max findings:' | 'Max risk matrix rows:'): HTMLElement {
  return screen.getByText(label).parentElement as HTMLElement
}

async function expand() {
  await userEvent.click(screen.getByText(/How Stories Are Generated/i))
}

describe('StoryInfoCard cap controls', () => {
  it('starts collapsed so the controls do not crowd the story', async () => {
    renderCard()

    expect(screen.queryByPlaceholderText(/Custom/)).not.toBeInTheDocument()
  })

  it('reports a preset selection', async () => {
    const { onMaxFindingsChange } = renderCard({ maxFindings: 20, totalFindings: 100 })
    await expand()

    const row = capRow('Max findings:')
    await userEvent.click(within(row).getByRole('button', { name: '50' }))

    expect(onMaxFindingsChange).toHaveBeenCalledWith(50)
  })

  it('sends the real total when "All" is chosen and the total is known', async () => {
    const { onMaxFindingsChange } = renderCard({ totalFindings: 137 })
    await expand()

    await userEvent.click(within(capRow('Max findings:')).getByRole('button', { name: /All 137/ }))

    // Not a sentinel: the caller gets the actual count, so the prompt is built from a real
    // number rather than one that happens to exceed it.
    expect(onMaxFindingsChange).toHaveBeenCalledWith(137)
  })

  it('falls back to a large sentinel when the total is unknown', async () => {
    const { onMaxRiskMatrixChange } = renderCard()
    await expand()

    await userEvent.click(within(capRow('Max risk matrix rows:')).getByRole('button', { name: 'All' }))

    // The total is not always loaded. A sentinel keeps "All" meaning "no cap" rather than
    // silently capping at zero.
    expect(onMaxRiskMatrixChange).toHaveBeenCalledWith(999999)
  })

  it('applies a custom value on Enter', async () => {
    const { onMaxFindingsChange } = renderCard()
    await expand()

    const input = within(capRow('Max findings:')).getByPlaceholderText(/Custom/)
    await userEvent.type(input, '37{Enter}')

    expect(onMaxFindingsChange).toHaveBeenCalledWith(37)
  })

  it('applies a custom value on blur, so a typed number is not silently lost', async () => {
    const { onMaxFindingsChange } = renderCard()
    await expand()

    const input = within(capRow('Max findings:')).getByPlaceholderText(/Custom/)
    await userEvent.type(input, '42')
    await userEvent.tab()

    expect(onMaxFindingsChange).toHaveBeenCalledWith(42)
  })

  it.each(['0', '-5', 'abc'])('ignores an invalid custom value (%s)', async bad => {
    const { onMaxFindingsChange } = renderCard()
    await expand()

    const input = within(capRow('Max findings:')).getByPlaceholderText(/Custom/)
    await userEvent.type(input, `${bad}{Enter}`)

    // A cap of zero or a NaN would produce a story with no evidence in it at all.
    expect(onMaxFindingsChange).not.toHaveBeenCalled()
  })

  it('clears the custom box after applying, ready for the next edit', async () => {
    renderCard()
    await expand()

    const input = within(capRow('Max findings:')).getByPlaceholderText(/Custom/) as HTMLInputElement
    await userEvent.type(input, '37{Enter}')

    expect(input.value).toBe('')
  })
})
