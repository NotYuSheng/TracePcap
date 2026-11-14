import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { NetworkContextPicker } from '../NetworkContextPicker'
import { RuleScopeTag } from '../RuleScopeTag'

function Where() {
  const loc = useLocation()
  return <div data-testid="where">{loc.search}</div>
}

function serve() {
  server.use(
    http.get('*/files/f1/networks', () => HttpResponse.json([{ id: 'hq', name: 'HQ' }])),
    http.get('*/monitor/networks', () =>
      HttpResponse.json([
        { id: 'hq', name: 'HQ' },
        { id: 'br', name: 'Branch' },
      ])
    )
  )
}

describe('NetworkContextPicker (#925 phase 3)', () => {
  it("lists the capture's networks first, hints at them, and sets the context in the URL", async () => {
    serve()
    render(
      <MemoryRouter initialEntries={['/analysis/f1?customSignatures=x&page=3']}>
        <NetworkContextPicker fileId="f1" />
        <Where />
      </MemoryRouter>
    )
    expect(await screen.findByTestId('network-context-hint')).toHaveTextContent('This capture is in HQ')
    const select = screen.getByLabelText('Custom detection rules')
    expect(screen.getByRole('group', { name: 'Networks with this capture' })).toHaveTextContent("HQ's rules too")
    expect(screen.getByRole('group', { name: 'Other networks' })).toHaveTextContent("Branch's rules too")

    await userEvent.selectOptions(select, 'hq')
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('networkId=hq'))
    // Other filters stay; paging restarts.
    expect(screen.getByTestId('where')).toHaveTextContent('customSignatures=x')
    expect(screen.getByTestId('where')).not.toHaveTextContent('page=3')
    expect(screen.queryByTestId('network-context-hint')).not.toBeInTheDocument()

    await userEvent.selectOptions(select, '')
    await waitFor(() => expect(screen.getByTestId('where')).not.toHaveTextContent('networkId'))
  })
})

describe('RuleScopeTag with a network', () => {
  it("labels a network rule's match with the network's name", () => {
    const { container } = render(<RuleScopeTag scope="NETWORK:HQ" />)
    expect(container).toHaveTextContent('· HQ')
  })
})
