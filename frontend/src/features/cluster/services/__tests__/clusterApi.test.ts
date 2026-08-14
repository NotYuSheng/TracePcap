/**
 * The intelligence view clusters hosts by ASN, country, subnet and so on, filtered by the same
 * criteria as the conversation table. If a filter is dropped on the way out, the operator sees
 * clusters built from more traffic than they asked for — and nothing says so.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { clusterApi } from '../clusterApi'

const FILE = '11111111-1111-1111-1111-111111111111'

/** Captures the query string the service actually requested. */
function captureClusters() {
  const seen: { query?: URLSearchParams } = {}
  server.use(
    http.get('*/api/v1/clusters/*/graph', ({ request }) => {
      seen.query = new URL(request.url).searchParams
      return HttpResponse.json({ clusters: [], edges: [] })
    })
  )
  return seen
}

describe('clusterApi.getClusters', () => {
  it('always sends the grouping dimension', async () => {
    const seen = captureClusters()

    await clusterApi.getClusters(FILE, 'asn')

    // groupBy comes from the endpoint itself rather than the filter block, which is why the
    // query is appended with "&" — see the joining test below.
    expect(seen.query!.get('groupBy')).toBe('asn')
  })

  it('appends filters alongside groupBy rather than replacing the query string', async () => {
    const seen = captureClusters()

    await clusterApi.getClusters(FILE, 'country', { ip: '10.0.0.1' })

    // The builder joins with "&" because the endpoint already carries "?groupBy=". Both must
    // survive: losing groupBy silently regroups the view, losing the filter silently widens it.
    expect(seen.query!.get('groupBy')).toBe('country')
    expect(seen.query!.get('ip')).toBe('10.0.0.1')
  })

  it('serialises list filters as comma-joined values', async () => {
    const seen = captureClusters()

    await clusterApi.getClusters(FILE, 'asn', {
      protocols: ['TCP', 'UDP'],
      countries: ['SG'],
      networkLabels: ['Corp', 'Guest'],
    })

    expect(seen.query!.get('protocols')).toBe('TCP,UDP')
    expect(seen.query!.get('countries')).toBe('SG')
    expect(seen.query!.get('networkLabels')).toBe('Corp,Guest')
  })

  it('omits empty lists rather than sending empty parameters', async () => {
    const seen = captureClusters()

    await clusterApi.getClusters(FILE, 'asn', { protocols: [], apps: [] })

    // An empty "protocols=" would be a filter matching nothing, inverting the intent.
    expect(seen.query!.has('protocols')).toBe(false)
    expect(seen.query!.has('apps')).toBe(false)
  })

  it('sends hasRisks only when true', async () => {
    const off = captureClusters()
    await clusterApi.getClusters(FILE, 'asn', { hasRisks: false })
    expect(off.query!.has('hasRisks')).toBe(false)

    const on = captureClusters()
    await clusterApi.getClusters(FILE, 'asn', { hasRisks: true })
    expect(on.query!.get('hasRisks')).toBe('true')
  })

  it('works with no filter argument at all', async () => {
    const seen = captureClusters()

    await clusterApi.getClusters(FILE, 'subnet24')

    expect(seen.query!.get('groupBy')).toBe('subnet24')
    expect([...seen.query!.keys()]).toEqual(['groupBy'])
  })
})
