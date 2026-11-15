/**
 * The conversation table remembers which columns a user chose. v7 added the User column (#812);
 * someone who customised their columns before that must keep their choice and see the new column.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { COLUMN_STORAGE_KEY, defaultVisibleColumns, loadVisibleColumns } from '../constants'

afterEach(() => localStorage.clear())

describe('loadVisibleColumns', () => {
  it('shows the User column by default', () => {
    expect(defaultVisibleColumns().has('users')).toBe(true)
    expect(loadVisibleColumns().has('users')).toBe(true)
  })

  it('keeps a pre-v7 custom selection and adds the User column to it', () => {
    localStorage.setItem('conv-visible-columns-v6', JSON.stringify(['source', 'destination', 'bytes']))

    expect([...loadVisibleColumns()].sort()).toEqual(['bytes', 'destination', 'source', 'users'])
  })

  it('respects a v7 selection that hides the User column', () => {
    localStorage.setItem(COLUMN_STORAGE_KEY, JSON.stringify(['source', 'destination']))
    localStorage.setItem('conv-visible-columns-v6', JSON.stringify(['source']))

    expect(loadVisibleColumns().has('users')).toBe(false)
  })
})
