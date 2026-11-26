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

  describe('the LLM connection, in one form', () => {
    const llm = (key: string, label: string, value: string | null, extra = {}) => ({
      key, label, group: 'LLM', value, defaultValue: null, secret: false, set: value !== null,
      editable: true, inAppEditable: true, deployValue: value, overridden: false, lockedReason: null,
      description: label, ...extra,
    })
    const llmRows = [
      llm('LLM_API_BASE_URL', 'LLM API base URL', 'http://old:1234/v1'),
      llm('LLM_API_KEY', 'LLM API key', null, { secret: true, set: true }),
      llm('LLM_MODEL', 'LLM model', 'qwen'),
    ]

    it('lists the models at the typed URL, picks one, and saves only what changed', async () => {
      const listed: unknown[] = []
      let saved: unknown = null
      server.use(
        http.get('*/system/settings', () => HttpResponse.json(llmRows)),
        http.post('*/system/llm/models', async ({ request }) => {
          const body = (await request.json()) as { baseUrl?: string }
          listed.push(body)
          return HttpResponse.json(
            body.baseUrl === 'http://new/v1'
              ? { ok: true, baseUrl: 'http://new/v1', models: [{ id: 'glm-5', contextLength: 262144 }, { id: 'llama' }] }
              : { ok: true, baseUrl: 'http://old:1234/v1', models: [{ id: 'qwen', contextLength: 32768 }] }
          )
        }),
        http.patch('*/system/settings', async ({ request }) => {
          saved = await request.json()
          return HttpResponse.json([])
        })
      )
      render(<SystemSettingsTab />)
      await userEvent.click(await screen.findByRole('button', { name: /Change connection/ }))

      const url = screen.getByLabelText('Server URL')
      await userEvent.clear(url)
      await userEvent.type(url, 'http://new/v1')
      const select = (await screen.findByRole('option', { name: 'glm-5 · 256k context' }, { timeout: 3000 }))
        .closest('select') as HTMLSelectElement
      // The saved model isn't on the new server, and says so.
      expect(screen.getByRole('option', { name: 'qwen (not on this server)' })).toBeInTheDocument()
      await userEvent.selectOptions(select, 'glm-5')
      await userEvent.click(screen.getByRole('button', { name: 'Save' }))

      expect(listed.at(-1)).toEqual({ baseUrl: 'http://new/v1' })
      // Together, all or none.
      expect(saved).toEqual({ values: { LLM_API_BASE_URL: 'http://new/v1', LLM_MODEL: 'glm-5' } })
    })

    it("lets a model the server doesn't list be typed", async () => {
      server.use(
        http.get('*/system/settings', () => HttpResponse.json(llmRows)),
        http.post('*/system/llm/models', () =>
          HttpResponse.json({ ok: true, baseUrl: 'http://old:1234/v1', models: [{ id: 'glm-5' }] })
        )
      )
      render(<SystemSettingsTab />)
      await userEvent.click(await screen.findByRole('button', { name: /Change connection/ }))
      const option = await screen.findByRole('option', { name: 'qwen (not on this server)' }, { timeout: 3000 })
      await userEvent.selectOptions(option.closest('select') as HTMLSelectElement, 'Type another name…')

      const typed = screen.getByLabelText('Model')
      expect(typed.tagName).toBe('INPUT')
      expect(typed).toHaveValue('qwen')
    })

    it('never saves a blank URL', async () => {
      server.use(
        http.get('*/system/settings', () => HttpResponse.json(llmRows)),
        http.post('*/system/llm/models', () => HttpResponse.json({ ok: true, baseUrl: '', models: [] }))
      )
      render(<SystemSettingsTab />)
      await userEvent.click(await screen.findByRole('button', { name: /Change connection/ }))
      await userEvent.clear(screen.getByLabelText('Server URL'))
      await userEvent.type(screen.getByLabelText('Model'), '-2')

      expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    })

    it("resets what was changed in the app to the deployment's values", async () => {
      const reset: string[] = []
      server.use(
        http.get('*/system/settings', () =>
          HttpResponse.json([
            { ...llmRows[0], overridden: true }, llmRows[1], { ...llmRows[2], overridden: true },
          ])
        ),
        http.post('*/system/llm/models', () => HttpResponse.json({ ok: true, baseUrl: '', models: [] })),
        http.delete('*/system/settings/:key', ({ params }) => {
          reset.push(params.key as string)
          return new HttpResponse(null, { status: 204 })
        })
      )
      render(<SystemSettingsTab />)
      await userEvent.click(await screen.findByRole('button', { name: /Change connection/ }))
      await userEvent.click(screen.getByRole('button', { name: "Reset to the deployment's values" }))

      await screen.findByRole('button', { name: /Change connection/ })
      expect(reset).toEqual(['LLM_API_BASE_URL', 'LLM_MODEL'])
    })

    it("lets the model be typed when the server doesn't list its models", async () => {
      server.use(
        http.get('*/system/settings', () => HttpResponse.json(llmRows)),
        http.post('*/system/llm/models', () =>
          HttpResponse.json({ ok: true, baseUrl: 'http://old:1234/v1', models: [], detail: "The server doesn't list its models: type the model's name." })
        )
      )
      render(<SystemSettingsTab />)
      await userEvent.click(await screen.findByRole('button', { name: /Change connection/ }))

      expect(await screen.findByText(/doesn't list its models/, {}, { timeout: 3000 })).toBeInTheDocument()
      expect(screen.getByLabelText('Model')).toHaveValue('qwen')
      expect(screen.getByLabelText('Model').tagName).toBe('INPUT')
    })

    it("opens from a connection setting's own Change button too", async () => {
      server.use(
        http.get('*/system/settings', () => HttpResponse.json(llmRows)),
        http.post('*/system/llm/models', () => HttpResponse.json({ ok: false, baseUrl: '', models: [], detail: 'The server refused the key (401).' }))
      )
      render(<SystemSettingsTab />)
      await userEvent.click(await screen.findByRole('button', { name: /LLM model/ }))
      await userEvent.click(screen.getByRole('button', { name: 'Change…' }))

      expect(screen.getByText('LLM connection')).toBeInTheDocument()
      expect(await screen.findByText('The server refused the key (401).', {}, { timeout: 3000 })).toBeInTheDocument()
    })
  })
})
