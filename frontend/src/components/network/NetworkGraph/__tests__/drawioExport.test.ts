import { describe, expect, it } from 'vitest'
import type { GraphEdge, GraphNode } from '@/features/network/types'
import { buildGroupTree, layoutGroups } from '@/features/network/services/networkGroups'
import { toDrawio } from '../drawioExport'

const node = (id: string, deviceType = 'LAPTOP_DESKTOP', hostname?: string): GraphNode =>
  ({ id, label: id, data: { ip: id, deviceType, hostname } }) as unknown as GraphNode
const edge = (id: string, source: string, target: string, protocol = 'TCP'): GraphEdge =>
  ({ id, source, target, label: '', data: { protocol, conversationId: id } }) as unknown as GraphEdge

const nodes = [node('10.0.0.5'), node('10.0.0.53', 'DNS_SERVER'), node('93.184.216.34', 'WEB_SERVER', 'www.example.com')]
const edges = [edge('c1', '10.0.0.5', '10.0.0.53', 'DNS'), edge('c2', '10.0.0.53', '10.0.0.5', 'DNS'), edge('c3', '10.0.0.5', '93.184.216.34')]

const parse = (xml: string) => new DOMParser().parseFromString(xml, 'application/xml')

describe('toDrawio', () => {
  const layout = layoutGroups(buildGroupTree(nodes))
  const doc = parse(toDrawio(layout, nodes, edges, n => [n.data.hostname ?? n.id, n.data.ip, 'A & <B>']))
  const cells = [...doc.querySelectorAll('mxCell')]
  const byValue = (v: string) => cells.find(c => (c.getAttribute('value') ?? '').startsWith(v))!

  it('is a well-formed draw.io file', () => {
    expect(doc.querySelector('parsererror')).toBeNull()
    expect(doc.querySelector('mxfile > diagram > mxGraphModel > root')).not.toBeNull()
  })

  it('nests boxes as containers, with coordinates relative to the parent', () => {
    const local = byValue('Your networks')
    const net = byValue('Local network')
    expect(local.getAttribute('style')).toContain('container=1')
    expect(net.getAttribute('parent')).toBe(local.getAttribute('id'))
    const box = layout.boxes.find(b => b.id === 'network:other')!
    const top = layout.boxes.find(b => b.id === 'local')!
    const g = net.querySelector('mxGeometry')!
    expect(Number(g.getAttribute('x'))).toBe(Math.round(box.x - top.x))
  })

  it('draws devices as network shapes inside their innermost box', () => {
    const dns = cells.find(c => (c.getAttribute('value') ?? '').includes('10.0.0.53'))!
    expect(dns.getAttribute('style')).toContain('shape=mxgraph.networks.server')
    const parent = cells.find(c => c.getAttribute('id') === dns.getAttribute('parent'))!
    expect(parent.getAttribute('value')).toMatch(/^Servers/)
    const laptop = cells.find(c => (c.getAttribute('value') ?? '').startsWith('10.0.0.5&lt;') || c.getAttribute('value') === '10.0.0.5<br>10.0.0.5<br>A &amp; &lt;B&gt;')!
    expect(laptop.getAttribute('style')).toContain('mxgraph.networks.laptop')
  })

  it('one line per device pair; labels keep their own markup escaped', () => {
    expect(cells.filter(c => c.getAttribute('edge') === '1')).toHaveLength(2)
    const web = cells.find(c => (c.getAttribute('value') ?? '').startsWith('www.example.com'))!
    // The attribute decodes to an html label whose text still shows "A & <B>" literally.
    expect(web.getAttribute('value')).toBe('www.example.com<br>93.184.216.34<br>A &amp; &lt;B&gt;')
  })
})
