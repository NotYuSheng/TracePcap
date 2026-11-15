/** The captures list's chips, as queries for the files endpoint. */
import { describe, expect, it } from 'vitest'

import { filterParams } from '../FileList'

const NOW = Date.UTC(2026, 10, 14, 12)

describe('filterParams', () => {
  it('lists everything for All', () => {
    expect(filterParams('all', { keptIds: [], retentionHours: 12, now: NOW })).toEqual({})
  })

  it('asks for the captures kept with a network by id, and matches none when there are none', () => {
    expect(filterParams('kept', { keptIds: ['a', 'b'], retentionHours: 12, now: NOW })).toEqual({ fileIds: ['a', 'b'] })
    expect(filterParams('kept', { keptIds: [], retentionHours: 12, now: NOW })?.fileIds).toHaveLength(1)
  })

  it('finds expiring captures: analysis uploads within two hours of deletion, not kept', () => {
    expect(filterParams('expiring', { keptIds: ['k'], retentionHours: 12, now: NOW })).toEqual({
      source: 'ANALYSIS',
      status: ['COMPLETED'],
      excludeFileIds: ['k'],
      uploadedBefore: NOW - 10 * 3600_000,
    })
  })

  it('has nothing expiring when captures are kept forever', () => {
    expect(filterParams('expiring', { keptIds: [], retentionHours: 0, now: NOW })).toBeNull()
  })

  it('filters failed captures by status', () => {
    expect(filterParams('failed', { keptIds: [], retentionHours: 12, now: NOW })).toEqual({ status: ['FAILED'] })
  })
})
