import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { useStore } from '@/store'
import { PersonalSettingsTab } from '../PersonalSettingsTab'

function serve(shared: boolean) {
  server.use(http.get('*/preferences', () => HttpResponse.json({ shared })))
}

describe('PersonalSettingsTab', () => {
  it('says plainly when login is off and preferences are shared by everyone', async () => {
    serve(true)
    render(<PersonalSettingsTab />)

    expect(await screen.findByText(/Login is off on this install/, undefined, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.getByText('shared by everyone')).toBeInTheDocument()
  })

  it('says preferences follow the account when login is on', async () => {
    serve(false)
    render(<PersonalSettingsTab />)

    expect(await screen.findByText(/Saved to your account/)).toBeInTheDocument()
    expect(screen.queryByText(/Login is off on this install/)).not.toBeInTheDocument()
  })

  it('changes the theme', async () => {
    serve(true)
    render(<PersonalSettingsTab />)

    await userEvent.selectOptions(screen.getByLabelText('Theme'), 'dark')

    expect(useStore.getState().themeMode).toBe('dark')
  })
})
