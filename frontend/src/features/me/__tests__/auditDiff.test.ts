import { describe, expect, it } from 'vitest'
import { describeAction, diffValues, groupIdText, humanize } from '../auditDiff'

describe('auditDiff', () => {
  it('an update lists only what changed, old → new; bookkeeping is left out', () => {
    const before = { name: 'live_check_tcp', match: { protocol: 'TCP' }, version: 2, severity: 'low' }
    const after = { name: 'live_check_tcp', match: { protocol: 'TCP' }, enabled: false, version: 3, severity: 'high' }
    expect(diffValues(before, after)).toEqual([
      { field: 'Severity', kind: 'changed', before: 'low', after: 'high' },
      { field: 'Enabled', kind: 'added', after: 'No' },
    ])
  })

  it('a creation lists its fields, nested ones as paths, empty ones skipped', () => {
    expect(diffValues(null, { name: 'branch_smb', match: { dstPort: 445 }, note: null })).toEqual([
      { field: 'Name', kind: 'added', after: 'branch_smb' },
      { field: 'Match › Dst port', kind: 'added', after: '445' },
    ])
  })

  it('a removal lists what was there', () => {
    expect(diffValues({ macA: 'aa', reason: 'same phone' }, null)).toEqual([
      { field: 'MAC A', kind: 'removed', before: 'aa' },
      { field: 'Reason', kind: 'removed', before: 'same phone' },
    ])
  })

  it('records in a list are named by their name; network map group keys read as words', () => {
    const after = { groups: [{ id: 'user:1', name: 'Payments', parentId: 'network:vlan:30' }], names: { 'network:vlan:10': 'Staff' } }
    expect(diffValues({ groups: [], names: {} }, after)).toEqual([
      { field: 'Groups › Payments › Name', kind: 'added', after: 'Payments' },
      { field: 'Groups › Payments › Parent ID', kind: 'added', after: 'network vlan:30' },
      { field: 'Names › network vlan:10', kind: 'added', after: 'Staff' },
    ])
  })

  it('names and actions read as words', () => {
    expect(humanize('overridesDefault')).toBe('Overrides default')
    expect(humanize('10.0.0.0/8')).toBe('10.0.0.0/8')
    expect(describeAction('detection-rule.update')).toBe('Detection rule · update')
    expect(describeAction('network-device.link.same')).toBe('Network device · link same')
  })

  it('network map group ids read as words', () => {
    expect(groupIdText('type:vlan:20:10.20.20.0/24:Laptops and desktops')).toBe('Laptops and desktops · 10.20.20.0/24')
    expect(groupIdText('network:vlan:30')).toBe('network vlan:30')
    expect(groupIdText('network:other')).toBe('Other local addresses')
    expect(diffValues({ names: {} }, { names: { 'network:vlan:10': 'Staff' } })).toEqual([
      { field: 'Names › network vlan:10', kind: 'added', after: 'Staff' },
    ])
  })
})
