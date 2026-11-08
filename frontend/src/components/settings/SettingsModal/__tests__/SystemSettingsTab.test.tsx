/**
 * The System settings tab (#915 phase 1): every deploy-time setting is listed, greyed out, and
 * explains when clicked why it can't be changed here and where it's set. Secrets show only
 * whether they're set.
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { SystemSettingsTab } from '../SystemSettingsTab'

const rows = [
  {
    key: 'FILE_RETENTION_HOURS', label: 'File retention hours', group: 'POLICY', value: '12',
    defaultValue: '12', secret: false, set: true, editable: false,
    lockedReason: 'Analysis policy. Changing it in the app is planned (#915); until then, set FILE_RETENTION_HOURS in the deployment\'s .env file and restart.',
    description: 'Hours after upload before an analysis file is deleted.',
  },
  {
    key: 'LLM_API_KEY', label: 'LLM API key', group: 'INFRASTRUCTURE', value: null, defaultValue: null,
    secret: true, set: true, editable: false, lockedReason: 'A secret, so its value is never shown in the app.',
    description: 'API key for the LLM server.',
  },
  {
    key: 'DB_POOL_MAX_SIZE', label: 'DB pool max size', group: 'MEMORY', value: '20', defaultValue: '20',
    secret: false, set: true, editable: false, lockedReason: 'Tied to how much memory the backend has.',
    description: 'Maximum database connections.',
  },
]

function serve() {
  server.use(http.get('*/system/settings', () => HttpResponse.json(rows)))
}

describe('SystemSettingsTab', () => {
  it('lists every setting, grouped, with its value; secrets show only that they are set', async () => {
    serve()
    render(<SystemSettingsTab />)

    expect(await screen.findByText('File retention hours')).toBeInTheDocument()
    expect(screen.getByText('Analysis policy')).toBeInTheDocument()
    expect(screen.getByText('Memory and capacity')).toBeInTheDocument()
    expect(screen.getByText('Infrastructure')).toBeInTheDocument()
    expect(screen.getByText('Set (hidden)')).toBeInTheDocument()
  })

  it('explains, when a greyed-out setting is clicked, why it cannot be changed here', async () => {
    serve()
    render(<SystemSettingsTab />)
    const row = await screen.findByRole('button', { name: /File retention hours/ })
    expect(row).toHaveAttribute('aria-expanded', 'false')

    await userEvent.click(row)

    expect(row).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText(/Why you can't change it here:/)).toBeInTheDocument()
    expect(screen.getByText(/set FILE_RETENTION_HOURS in the deployment's .env file/)).toBeInTheDocument()
  })

  it('filters by name, variable or description', async () => {
    serve()
    render(<SystemSettingsTab />)
    await screen.findByText('File retention hours')

    await userEvent.type(screen.getByLabelText('Search settings'), 'pool')

    expect(screen.getByText('DB pool max size')).toBeInTheDocument()
    expect(screen.queryByText('File retention hours')).not.toBeInTheDocument()
  })

  describe('editable policy (#915 phase 5)', () => {
    const threshold = {
      key: 'HTTP_MIN_REQUESTS', label: 'HTTP min requests', group: 'POLICY', value: '20', defaultValue: '20',
      secret: false, set: true, editable: true, inAppEditable: true, deployValue: '20', overridden: false,
      takesEffect: 'At once in the network cluster view.', lockedReason: null, description: 'Minimum requests.',
    }
    const retention = {
      key: 'FILE_RETENTION_HOURS', label: 'File retention hours', group: 'POLICY', value: '12', defaultValue: '12',
      secret: false, set: true, editable: false, inAppEditable: true, deployValue: '12', overridden: false,
      lockedReason: 'only admins can change this.', description: 'Hours kept.',
    }

    it('changes a setting in a modal, then shows it as changed in the app', async () => {
      let current = threshold
      let sent: unknown = null
      server.use(
        http.get('*/system/settings', () => HttpResponse.json([current, retention])),
        http.put('*/system/settings/HTTP_MIN_REQUESTS', async ({ request }) => {
          sent = await request.json()
          current = { ...threshold, value: '35', overridden: true }
          return HttpResponse.json(current)
        })
      )
      render(<SystemSettingsTab />)

      await userEvent.click(await screen.findByRole('button', { name: /HTTP min requests/ }))
      await userEvent.click(screen.getByRole('button', { name: 'Change…' }))
      const input = screen.getByLabelText('Value')
      await userEvent.clear(input)
      await userEvent.type(input, '35')
      await userEvent.click(screen.getByRole('button', { name: 'Save' }))

      expect(sent).toEqual({ value: '35' })
      expect(await screen.findByText('changed in the app')).toBeInTheDocument()
    })

    it("shows the server's refusal in the modal", async () => {
      server.use(
        http.get('*/system/settings', () => HttpResponse.json([threshold])),
        http.put('*/system/settings/HTTP_MIN_REQUESTS', () =>
          HttpResponse.json({ message: 'Enter a whole number.' }, { status: 400 })
        )
      )
      render(<SystemSettingsTab />)
      await userEvent.click(await screen.findByRole('button', { name: /HTTP min requests/ }))
      await userEvent.click(screen.getByRole('button', { name: 'Change…' }))
      await userEvent.type(screen.getByLabelText('Value'), '.5')
      await userEvent.click(screen.getByRole('button', { name: 'Save' }))
      expect(await screen.findByText('Enter a whole number.')).toBeInTheDocument()
    })

    it('greys out one you may not change, with the reason and no Change button', async () => {
      server.use(http.get('*/system/settings', () => HttpResponse.json([retention])))
      render(<SystemSettingsTab />)
      await userEvent.click(await screen.findByRole('button', { name: /File retention hours/ }))
      expect(screen.getByText(/only admins can change this/)).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Change…' })).not.toBeInTheDocument()
    })
  })
})
